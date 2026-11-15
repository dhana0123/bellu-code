package broker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker/opname"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
)

// memBody is a fully buffered, already redacted response body.
type memBody struct {
	io.Reader
	data []byte
}

func (*memBody) Close() error { return nil }

func newMemBody(b []byte) *memBody { return &memBody{Reader: bytes.NewReader(b), data: b} }

// policyTransport is the single choke point for outbound traffic.
type policyTransport struct {
	b      *Broker
	ref    ConnectionRef
	caller string
	ops    map[string]manifest.Operation
	names  []string // REST operation names, sorted
}

func newPolicyTransport(b *Broker, ref ConnectionRef, caller string) *policyTransport {
	t := &policyTransport{b: b, ref: ref, caller: caller, ops: map[string]manifest.Operation{}}
	for _, op := range ref.Manifest.Operations {
		t.ops[op.Name] = op
		if op.Method != "" {
			t.names = append(t.names, op.Name)
		}
	}
	sort.Strings(t.names)
	return t
}

func (t *policyTransport) isAWS() bool {
	return t.ref.Auth == AuthAWSVault || t.ref.Auth == AuthAWSAmbient
}

// RoundTrip implements http.RoundTripper. Order: policy, rate limit,
// credential, dial, response projection.
func (t *policyTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	defer func() {
		if recover() != nil {
			resp, err = nil, ErrInternal
		}
	}()
	parent := req.Context()
	if err := parent.Err(); err != nil {
		return nil, &NetworkError{cause: err}
	}
	ctx, cancel := context.WithTimeout(parent, CallTimeout)
	defer cancel()

	// 1. Policy.
	op, derr := t.authorize(ctx, req)
	if derr != nil {
		return nil, derr
	}

	// 1b. Query operations: the body must be a read-only query.
	if op.Query && !t.isAWS() {
		check := t.checkQueryBody
		if op.Class == manifest.ClassAuth {
			check = t.checkAuthBody
		}
		if err := check(ctx, req, op); err != nil {
			return nil, err
		}
	}
	// 2. Rate limit.
	st := t.b.state(t.ref.ID)
	pause, err := t.wait(ctx, st)
	if err != nil {
		return nil, err
	}
	if obs, ok := parent.Value(keyWaitObserver).(func(RateWait)); ok && pause.Waited > 0 {
		obs(pause)
	}
	// 2b. The wait may have been long: agent scope is re-read before dialing.
	if err := t.recheckAgent(ctx, req, op); err != nil {
		return nil, err
	}

	// 3. Credential injection. Nothing is sent when the vault fails.
	out := req.Clone(ctx)
	release := func() {}
	if t.injects() {
		if t.ref.Auth == AuthK8sBearer && t.ref.APIHost != "" && req.URL.Host != t.ref.APIHost {
			return nil, t.block(ctx, op.Name, req.Method, req.URL.Host, policy.ReasonHostBlocked, "host")
		}
		out.Header.Del("Authorization")
		r, err := t.inject(ctx, out)
		if err != nil {
			return nil, err
		}
		release = r
	}
	defer release()

	// 4. Dial (guarded in the inner transport).
	inner := t.b.inner
	if t.ref.Auth == AuthK8sBearer && t.b.cfg.Inner == nil {
		inner, err = t.b.k8sTransport(ctx, t.ref)
		if err != nil {
			return nil, err
		}
	}
	raw, err := inner.RoundTrip(out)
	if err != nil {
		return nil, t.networkError(parent, ctx, err)
	}
	defer raw.Body.Close()

	// 5. Projection: cap, decode, redact, strip.
	limit := ClientMaxBytes
	if v, ok := parent.Value(keyMaxBytes).(int); ok {
		limit = v
	}
	if op.MaxBytes > 0 && op.MaxBytes < limit {
		limit = op.MaxBytes
	}
	body, err := t.readCapped(raw, limit)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, err
		}
		return nil, t.networkError(parent, ctx, err)
	}
	t.notePause(st, raw, body)
	if op.IssuesCredential {
		// The body carries a credential for the lifecycle caller: token
		// patterns stay, registered values are still replaced. Never audited.
		body = t.b.cfg.Redactor.Registered(body)
	} else {
		body = t.b.cfg.Redactor.JSON(body)
	}
	body = stripKeys(body, op.StripKeys)

	raw.Body = newMemBody(body)
	raw.ContentLength = int64(len(body))
	raw.Header = t.cleanHeader(raw.Header)
	raw.Header.Set("Content-Length", strconv.Itoa(len(body)))
	raw.Uncompressed = true
	return raw, nil
}

// authorize resolves the operation and asks the policy. A denial is audited
// before it is returned.
func (t *policyTransport) authorize(ctx context.Context, req *http.Request) (manifest.Operation, error) {
	if req.URL.Scheme != "https" {
		return manifest.Operation{}, t.block(ctx, "", req.Method, req.URL.Host, policy.ReasonHostBlocked, "scheme")
	}
	path := strings.TrimPrefix(req.URL.Path, t.ref.BasePath)
	if t.isAWS() {
		return t.authorizeAWS(ctx, req)
	}
	pr := policy.Request{
		ConnectionID: t.ref.ID, ConnectorID: t.ref.ConnectorID, Caller: t.caller,
		Method: req.Method, Host: req.URL.Host, Path: path, Class: manifest.ClassRead,
	}
	if forced, ok := req.Context().Value(keyOperation).(string); ok {
		return t.check(ctx, req, pr, forced)
	}
	// SDK-less REST client: find the allowlisted operation that matches.
	var last policy.Decision
	why := ""
	for _, name := range t.names {
		op := t.ops[name]
		pr.Operation, pr.Class = name, op.Class
		pr.Agent = t.agentInputs(name)
		d := t.ref.Policy.Check(pr)
		if d.Allow {
			return op, nil
		}
		last = d
		if pr.Agent != nil && !pr.Agent.InScope {
			why = pr.Agent.Why
		}
	}
	if last.Reason == "" {
		last = policy.Decision{Reason: policy.ReasonOpNotListed, Violated: "operation"}
	}
	return manifest.Operation{}, t.blockWhy(ctx, "", req.Method, req.URL.Host, last.Reason, last.Violated, why)
}

// checkQueryBody reads a bounded copy of the body, restores it for sending and
// blocks (audited, nothing sent) unless the connector's validator accepts it.
func (t *policyTransport) checkQueryBody(ctx context.Context, req *http.Request, op manifest.Operation) error {
	deny := func() error {
		return t.block(ctx, op.Name, req.Method, req.URL.Host, policy.ReasonNotReadOnly, "query")
	}
	validate := t.b.cfg.QueryValidators[t.ref.ConnectorID]
	if validate == nil || req.Body == nil || req.Body == http.NoBody {
		return deny()
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, MaxQueryBody+1))
	_ = req.Body.Close()
	if err != nil || len(data) > MaxQueryBody || !validate(data) {
		return deny()
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	req.ContentLength = int64(len(data))
	return nil
}

// MaxAuthBody bounds the request body of an auth-class operation.
const MaxAuthBody = 4 << 10

var authBodyKeys = map[string]bool{"assertion": true, "client_id": true, "device_code": true, "grant_type": true, "scope": true, "refresh_token": true}

// checkAuthBody allows only a small form or JSON body whose keys are all in
// authBodyKeys. A client_secret key, an unparseable or oversized body, or a
// missing body is blocked (audited, nothing sent).
func (t *policyTransport) checkAuthBody(ctx context.Context, req *http.Request, op manifest.Operation) error {
	deny := func() error {
		return t.block(ctx, op.Name, req.Method, req.URL.Host, policy.ReasonNotReadOnly, "auth_body")
	}
	if req.Body == nil || req.Body == http.NoBody {
		return deny()
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, MaxAuthBody+1))
	_ = req.Body.Close()
	if err != nil || len(data) > MaxAuthBody || !authBodyAllowed(data, req.Header.Get("Content-Type")) {
		return deny()
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	req.ContentLength = int64(len(data))
	return nil
}

func authBodyAllowed(data []byte, contentType string) bool {
	keys := []string{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var m map[string]json.RawMessage
		if json.Unmarshal(trimmed, &m) != nil {
			return false
		}
		for k := range m {
			keys = append(keys, k)
		}
	} else {
		if strings.Contains(strings.ToLower(contentType), "json") {
			return false
		}
		vals, err := url.ParseQuery(string(data))
		if err != nil {
			return false
		}
		for k := range vals {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		if !authBodyKeys[strings.ToLower(k)] { // also rejects client_secret
			return false
		}
	}
	return true
}

func (t *policyTransport) check(ctx context.Context, req *http.Request, pr policy.Request, name string) (manifest.Operation, error) {
	op, ok := t.ops[name]
	if !ok {
		return manifest.Operation{}, t.block(ctx, name, req.Method, req.URL.Host, policy.ReasonOpNotListed, "operation")
	}
	pr.Operation, pr.Class = name, op.Class
	pr.Agent = t.agentInputs(name)
	if d := t.ref.Policy.Check(pr); !d.Allow {
		why := ""
		if pr.Agent != nil {
			why = pr.Agent.Why
		}
		return manifest.Operation{}, t.blockWhy(ctx, name, req.Method, req.URL.Host, d.Reason, d.Violated, why)
	}
	return op, nil
}

// agentInputs returns the scope inputs for an agent caller, or nil for any
// other caller. A missing gate yields the zero value, which denies.
func (t *policyTransport) agentInputs(op string) *policy.AgentInputs {
	if !policy.IsAgentCaller(t.caller) {
		return nil
	}
	in := policy.AgentInputs{Why: "no_gate"}
	if g := t.b.cfg.AgentGate; g != nil {
		in = g.AgentInputs(policy.Principal(t.caller), t.ref.ID, t.ref.ConnectorID, op)
	}
	return &in
}

// recheckAgent re-evaluates the agent conditions right before dialing.
func (t *policyTransport) recheckAgent(ctx context.Context, req *http.Request, op manifest.Operation) error {
	in := t.agentInputs(op.Name)
	if in == nil {
		return nil
	}
	if d := policy.CheckAgent(t.caller, in); !d.Allow {
		return t.blockWhy(ctx, op.Name, req.Method, req.URL.Host, d.Reason, d.Violated, in.Why)
	}
	return nil
}

func (t *policyTransport) authorizeAWS(ctx context.Context, req *http.Request) (manifest.Operation, error) {
	short, ok := opname.Resolve(req)
	if !ok {
		return manifest.Operation{}, t.block(ctx, "", req.Method, req.URL.Host, policy.ReasonOpNotListed, "operation")
	}
	service, _, _ := strings.Cut(req.URL.Hostname(), ".")
	name := service + ":" + short
	if t.ref.Auth == AuthAWSAmbient && service != "sts" {
		// Ambient credentials are used only to assume a role.
		return manifest.Operation{}, t.block(ctx, name, req.Method, req.URL.Host, policy.ReasonScope, "class")
	}
	pr := policy.Request{
		ConnectionID: t.ref.ID, ConnectorID: t.ref.ConnectorID, Caller: t.caller,
		Method: req.Method, Host: req.URL.Host, Path: req.URL.Path,
	}
	return t.check(ctx, req, pr, name)
}

// block audits the denial and returns the typed error. The audit entry is
// appended before this function returns; a failed append cannot unblock.
func (t *policyTransport) block(ctx context.Context, op, method, host string, reason policy.Reason, violated string) error {
	return t.blockWhy(ctx, op, method, host, reason, violated, "")
}

// blockWhy is block with the finer denial cause of an agent scope check. A
// scope or live-read denial is recorded as scope_denied.
func (t *policyTransport) blockWhy(ctx context.Context, op, method, host string, reason policy.Reason, violated, why string) error {
	event := audit.EventBlockedOperation
	detail := map[string]string{
		"caller": t.caller, "operation": op, "violated": violated,
		"reason": string(reason), "method": method, "host": host,
	}
	if reason == policy.ReasonScope && (violated == "scope" || violated == "live_reads") {
		event = audit.EventScopeDenied
		if why != "" {
			detail["why"] = why
		}
	}
	_ = t.b.appendAudit(ctx, audit.Entry{
		ConnectionID: t.ref.ID, ConnectorID: t.ref.ConnectorID,
		Event: event, Outcome: audit.OutcomeBlocked, Actor: orSystem(t.caller),
		Detail: detail,
	})
	return &BlockedError{Reason: reason, Violated: violated}
}

func orSystem(s string) string {
	if s == "" {
		return audit.ActorSystem
	}
	return s
}

func (b *Broker) appendAudit(ctx context.Context, e audit.Entry) error {
	if b.cfg.Audit == nil {
		return nil
	}
	// The call context may already be done; the audit must still be written.
	return b.cfg.Audit.Append(context.WithoutCancel(ctx), e)
}

func (t *policyTransport) networkError(parent, ctx context.Context, err error) error {
	if errors.Is(err, errBlockedAddr) || strings.Contains(err.Error(), errBlockedAddr.Error()) {
		return &BlockedError{Reason: policy.ReasonHostBlocked, Violated: "host"}
	}
	var be *BlockedError
	if errors.As(err, &be) {
		return be
	}
	if cerr := parent.Err(); cerr != nil {
		return &NetworkError{Timeout: errors.Is(cerr, context.DeadlineExceeded), cause: cerr}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &NetworkError{Timeout: true, cause: context.DeadlineExceeded}
	}
	return &NetworkError{}
}

// wait applies the per-connection pause (Retry-After and friends) and the
// 10 req/s limiter. It never waits past the call deadline.
// It returns the provider-requested pause it waited out; the limiter's own
// smoothing delay is not reported.
func (t *policyTransport) wait(ctx context.Context, st *connState) (RateWait, error) {
	var rw RateWait
	st.mu.Lock()
	until := st.until
	st.mu.Unlock()
	if d := until.Sub(t.b.now()); d > 0 {
		if dl, ok := ctx.Deadline(); ok && t.b.now().Add(d).After(dl) {
			return rw, &RateLimitedError{RetryAfter: d}
		}
		if err := t.b.sleep(ctx, d); err != nil {
			return rw, &NetworkError{Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded), cause: ctx.Err()}
		}
		rw = RateWait{Until: until, Waited: d}
	}
	// Strict sliding window on the broker clock: at most max(1, rps) sends in
	// any 1 s span; bursts are allowed.
	now := t.b.now()
	maxDelay := time.Duration(1<<63 - 1)
	if dl, ok := ctx.Deadline(); ok {
		maxDelay = dl.Sub(now)
	}
	at, ok := st.reserve(now, max(1, int(t.b.rps)), maxDelay)
	if !ok {
		return rw, &RateLimitedError{RetryAfter: at.Sub(now)}
	}
	if delay := at.Sub(now); delay > 0 {
		if err := t.b.sleep(ctx, delay); err != nil {
			st.release(at)
			return rw, &NetworkError{Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded), cause: ctx.Err()}
		}
	}
	return rw, nil
}

// notePause records a provider-requested pause from Retry-After,
// X-RateLimit-Reset and AWS throttling responses.
func (t *policyTransport) notePause(st *connState, resp *http.Response, body []byte) {
	d := t.pauseFor(resp, body)
	if d <= 0 {
		return
	}
	if d > maxPause {
		d = maxPause
	}
	until := t.b.now().Add(d)
	st.mu.Lock()
	if until.After(st.until) {
		st.until = until
	}
	st.mu.Unlock()
}

func (t *policyTransport) pauseFor(resp *http.Response, body []byte) time.Duration {
	h := resp.Header
	if v := h.Get("Retry-After"); v != "" && (resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 403) {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
		if at, err := http.ParseTime(v); err == nil {
			return at.Sub(t.b.now())
		}
	}
	if (resp.StatusCode == 403 || resp.StatusCode == 429) && strings.TrimSpace(h.Get("X-RateLimit-Remaining")) == "0" {
		if reset, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil {
			return time.Unix(reset, 0).Sub(t.b.now())
		}
	}
	if t.isAWS() && awsThrottled(resp, body) {
		return time.Second
	}
	return 0
}

func awsThrottled(resp *http.Response, body []byte) bool {
	if resp.StatusCode == 429 {
		return true
	}
	if et := resp.Header.Get("X-Amzn-ErrorType"); strings.Contains(et, "Throttl") || strings.Contains(et, "RequestLimitExceeded") {
		return true
	}
	if resp.StatusCode == 400 || resp.StatusCode == 503 {
		s := string(body)
		return strings.Contains(s, "Throttling") || strings.Contains(s, "RequestLimitExceeded") || strings.Contains(s, "SlowDown")
	}
	return false
}

// readCapped reads the body (gunzipping if the transport did not) and fails
// with ErrTooLarge above limit bytes.
func (t *policyTransport) readCapped(resp *http.Response, limit int) ([]byte, error) {
	var r io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(io.LimitReader(resp.Body, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
		resp.Header.Del("Content-Encoding")
	default:
		return nil, errors.New("unsupported content encoding")
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

func (t *policyTransport) cleanHeader(h http.Header) http.Header {
	out := http.Header{}
	for k, vs := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Set-Cookie", "Set-Cookie2", "Authorization", "Proxy-Authenticate", "Www-Authenticate", "Content-Encoding":
			continue
		}
		for _, v := range vs {
			out.Add(k, t.b.cfg.Redactor.String(v))
		}
	}
	return out
}

// stripKeys removes the named keys at any depth. Non-JSON bodies are returned unchanged.
func stripKeys(body []byte, keys []string) []byte {
	if len(keys) == 0 || len(body) == 0 {
		return body
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return body
	}
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	strip(v, set)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return body
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func strip(v any, keys map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if keys[k] {
				delete(x, k)
				continue
			}
			strip(child, keys)
		}
	case []any:
		for _, child := range x {
			strip(child, keys)
		}
	}
}

func jsonBody(params map[string]any) (io.Reader, error) {
	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
