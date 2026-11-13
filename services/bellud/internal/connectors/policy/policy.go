// Package policy decides whether an outbound provider request is allowed. It
// is pure (no I/O) and fails closed: anything not explicitly allowed by the
// manifest's read allowlist and the Connection's egress hosts is denied.
package policy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// Caller values.
const (
	CallerCollector = "collector"
	CallerLifecycle = "lifecycle"
	// CallerAgentPrefix prefixes the caller of an agent live read
	// ("agent:<principal>"). Such a caller is denied unless Request.Agent
	// carries scope inputs that allow the request (Requirement 17).
	CallerAgentPrefix = "agent:"
)

// IsAgentCaller reports whether caller is an agent principal ("agent:<p>").
func IsAgentCaller(caller string) bool { return strings.HasPrefix(caller, CallerAgentPrefix) }

// Principal returns the principal of an agent caller, or "".
func Principal(caller string) string { return strings.TrimPrefix(caller, CallerAgentPrefix) }

// AgentInputs are the per-request facts the Session_Scope layer supplies for
// an agent caller. The zero value denies.
type AgentInputs struct {
	// InScope: the Connection, Connector and operation are in the caller's
	// Session_Scope and the operation is on the connector's read allowlist.
	InScope bool
	// LiveReads: the Connection has "Allow agent live reads" enabled.
	LiveReads bool
	// Why names the specific denial cause for the audit log (never a secret).
	Why string
}

// CheckAgent applies the agent conditions: scope and live reads. It allows a
// non-agent caller. A nil in for an agent caller is a deny (default deny).
func CheckAgent(caller string, in *AgentInputs) Decision {
	if !IsAgentCaller(caller) {
		return Decision{Allow: true, Reason: ReasonOK}
	}
	switch {
	case in == nil || !in.InScope:
		return deny(ReasonScope, "scope")
	case !in.LiveReads:
		return deny(ReasonScope, "live_reads")
	}
	return Decision{Allow: true, Reason: ReasonOK}
}

// Reason explains a Decision.
type Reason string

// Decision reasons.
const (
	ReasonOK          Reason = "ok"
	ReasonNotReadOnly Reason = "not_read_only"
	ReasonHostBlocked Reason = "host_blocked"
	ReasonOpNotListed Reason = "op_not_listed"
	ReasonScope       Reason = "scope"
	ReasonRateLimited Reason = "rate_limited"
)

// Request describes one outbound call.
type Request struct {
	ConnectionID, ConnectorID, Caller string
	Method, Host, Path                string
	// Operation is the provider operation name resolved by the wrapper.
	Operation string
	// Class is "read" or "auth".
	Class string
	// Agent holds the scope inputs for callers "agent:<principal>"; nil
	// denies such a caller.
	Agent *AgentInputs
}

// Decision is the result of Check. Violated names the failed condition
// ("method", "host", "operation", "class", "path") and is empty when allowed.
type Decision struct {
	Allow    bool
	Reason   Reason
	Violated string
}

// Selection is the per-Connection choice that fills host placeholders.
type Selection struct {
	// Regions replaces {region} in host patterns.
	Regions []string
	// Host replaces {host} in host patterns (GitHub Enterprise Server host).
	Host string
}

// Policy is a manifest compiled against a Selection.
type Policy struct {
	connectorID string
	egress      []hostPattern
	ops         map[string]compiledOp
}

type compiledOp struct {
	op    manifest.Operation
	hosts []hostPattern
	path  []string // nil when any path is accepted
}

var (
	regionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	hostRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// Compile builds a Policy. It fails when the manifest is invalid, when a
// placeholder has no selected value, or when the selection is malformed.
func Compile(m manifest.Manifest, sel Selection) (*Policy, error) {
	if errs := manifest.Validate(m); len(errs) > 0 {
		return nil, fmt.Errorf("policy: invalid manifest: %w", errs[0])
	}
	for _, r := range sel.Regions {
		if !regionRe.MatchString(r) {
			return nil, errors.New("policy: invalid region in selection")
		}
	}
	if sel.Host != "" && !hostRe.MatchString(strings.ToLower(sel.Host)) {
		return nil, errors.New("policy: invalid host in selection")
	}
	sel.Host = strings.ToLower(sel.Host)

	p := &Policy{connectorID: m.ID, ops: map[string]compiledOp{}}
	for _, e := range m.Egress {
		hs, err := expand(e, sel)
		if err != nil {
			return nil, err
		}
		p.egress = append(p.egress, hs...)
	}
	for _, op := range m.Operations {
		if manifest.IsWrite(op) {
			return nil, errors.New("policy: manifest lists a write operation")
		}
		hs, err := expand(op.Host, sel)
		if err != nil {
			return nil, err
		}
		c := compiledOp{op: op, hosts: hs}
		if op.Path != "" {
			c.path = strings.Split(op.Path, "/")
		}
		p.ops[op.Name] = c
	}
	return p, nil
}

// Check decides r. It is pure and deterministic.
func (p *Policy) Check(r Request) Decision {
	if p == nil {
		return deny(ReasonOpNotListed, "operation")
	}
	if r.ConnectorID != "" && r.ConnectorID != p.connectorID {
		return deny(ReasonOpNotListed, "operation")
	}

	// Agent callers need an in-scope request on a live-read connection.
	if d := CheckAgent(r.Caller, r.Agent); !d.Allow {
		return d
	}

	// Class: auth operations are for the lifecycle only.
	switch r.Class {
	case manifest.ClassRead:
	case manifest.ClassAuth:
		if r.Caller != CallerLifecycle {
			return deny(ReasonScope, "class")
		}
	default:
		return deny(ReasonNotReadOnly, "class")
	}

	// Operation must be listed with the same class; unknown is a deny.
	c, ok := p.ops[r.Operation]
	if r.Operation == "" || !ok || c.op.Class != r.Class || manifest.IsWrite(c.op) {
		return deny(ReasonOpNotListed, "operation")
	}

	// Method: reads, or a POST that the manifest marks as a read query.
	if !methodAllowed(r.Method, c.op) {
		return deny(ReasonNotReadOnly, "method")
	}

	// Host: must be in the egress allowlist and match the operation's host.
	h := normalizeHost(r.Host)
	if h == "" || !matchAny(p.egress, h) || !matchAny(c.hosts, h) {
		return deny(ReasonHostBlocked, "host")
	}

	if c.path != nil && !pathMatches(c.path, r.Path) {
		return deny(ReasonOpNotListed, "path")
	}
	return Decision{Allow: true, Reason: ReasonOK}
}

func deny(r Reason, violated string) Decision {
	return Decision{Reason: r, Violated: violated}
}

func methodAllowed(method string, op manifest.Operation) bool {
	if op.Method == "" {
		// AWS-style: a single signed POST/GET carries the action; the
		// operation name already proved read-only. Only read-capable
		// transports are accepted.
		return method == "GET" || method == "POST"
	}
	if method != op.Method {
		return false
	}
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	case "POST":
		return op.Query
	}
	return false
}

// hostPattern is a literal host or a "*." wildcard suffix (one or more labels).
type hostPattern struct {
	suffix   string // set for wildcard, includes leading dot
	literal  string
	wildcard bool
}

func (h hostPattern) match(host string) bool {
	if h.wildcard {
		return len(host) > len(h.suffix) && strings.HasSuffix(host, h.suffix)
	}
	return host == h.literal
}

func matchAny(ps []hostPattern, host string) bool {
	for _, p := range ps {
		if p.match(host) {
			return true
		}
	}
	return false
}

// expand substitutes placeholders, yielding one pattern per selected region.
func expand(pattern string, sel Selection) ([]hostPattern, error) {
	pattern = strings.ToLower(pattern)
	vals := []string{pattern}
	if strings.Contains(pattern, "{region}") {
		if len(sel.Regions) == 0 {
			return nil, errors.New("policy: pattern requires a region but none selected")
		}
		vals = vals[:0]
		for _, r := range sel.Regions {
			vals = append(vals, strings.ReplaceAll(pattern, "{region}", r))
		}
	}
	out := make([]hostPattern, 0, len(vals))
	for _, v := range vals {
		if strings.Contains(v, "{host}") {
			if sel.Host == "" {
				return nil, errors.New("policy: pattern requires a host but none selected")
			}
			v = strings.ReplaceAll(v, "{host}", sel.Host)
		}
		if strings.ContainsAny(v, "{}") {
			return nil, errors.New("policy: unknown placeholder in host pattern")
		}
		if rest, ok := strings.CutPrefix(v, "*."); ok {
			out = append(out, hostPattern{wildcard: true, suffix: "." + rest})
			continue
		}
		out = append(out, hostPattern{literal: v})
	}
	return out, nil
}

// normalizeHost lowercases, drops a port and a trailing dot. IP literals are
// never allowed.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	if net.ParseIP(strings.Trim(h, "[]")) != nil || !hostRe.MatchString(h) {
		return ""
	}
	return h
}

// pathMatches matches segment by segment; "{x}" matches exactly one non-empty
// segment. A query string is ignored.
func pathMatches(pat []string, path string) bool {
	path, _, _ = strings.Cut(path, "?")
	segs := strings.Split(path, "/")
	if len(segs) != len(pat) {
		return false
	}
	for i, s := range pat {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			if segs[i] == "" || segs[i] == "." || segs[i] == ".." {
				return false
			}
			continue
		}
		if s != segs[i] {
			return false
		}
	}
	return true
}
