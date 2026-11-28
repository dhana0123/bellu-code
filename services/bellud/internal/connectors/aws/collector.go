package aws

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// This file maps Client projections to graph entities. It depends on the
// Client interface only: no SDK and no net/http. Only metadata is collected
// (no object contents, environment variable values or secrets).

const (
	kindAccount  = awsschema.KindAccount
	kindResource = awsschema.KindResource
	kindSGRule   = awsschema.KindSGRule
	kindCIDR     = awsschema.KindCIDR

	defaultInterval = 5 * time.Minute

	// Caps on security group rule nodes. They are fields of the collector so
	// tests can lower them.
	defaultMaxRulesPerSG       = 200
	defaultMaxRuleNodesPerConn = 20000
)

type collector struct {
	client   Client
	connID   string
	alias    string
	interval time.Duration
	regions  []string // selected, deduplicated, sorted
	status   collectors.StatusRecorder

	maxRulesPerSG       int
	maxRuleNodesPerConn int
}

var _ collectors.StatusReporter = (*collector)(nil)

// RunStatus implements collectors.StatusReporter. It describes the last
// Collect call: rate-limit waits, the authorization error that ended it, and
// the scopes AWS denied.
func (c *collector) RunStatus() collectors.RunStatus { return c.status.Status() }

// NewCollector returns the collector of one AWS Connection. Only the regions
// in sel are queried.
func NewCollector(c Client, conn store.Connection, sel store.Selection) collectors.Collector {
	seen := map[string]bool{}
	var rs []string
	for _, r := range sel.Regions {
		if r = strings.TrimSpace(r); r != "" && !seen[r] {
			seen[r] = true
			rs = append(rs, r)
		}
	}
	sort.Strings(rs)
	iv := defaultInterval
	if conn.IntervalSec > 0 {
		iv = time.Duration(conn.IntervalSec) * time.Second
	}
	return &collector{client: c, connID: conn.ID, alias: conn.Alias, interval: iv, regions: rs,
		maxRulesPerSG: defaultMaxRulesPerSG, maxRuleNodesPerConn: defaultMaxRuleNodesPerConn}
}

func (c *collector) Name() string            { return "connector:aws:" + c.connID }
func (c *collector) Interval() time.Duration { return c.interval }

// Timeout implements collectors.Timeouter.
func (c *collector) Timeout() time.Duration { return collectors.ConnectorTimeout }

func partition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	}
	return "aws"
}

type builder struct {
	c       *collector
	source  string
	account string
	acctID  string
	b       batch.Batch
	seen    map[string]string // arn (or a pseudo key for rule and cidr nodes) -> entity id
	attrs   map[string]map[string]any
	pending []pendingRel
}

// pendingRel is a relation whose endpoints are resolved after every step ran,
// so a relation never names an entity that was not collected.
type pendingRel struct {
	typ, from, to string // from and to are keys of builder.seen
	attrs         map[string]any
}

// rel queues a relation between two collected entities.
func (b *builder) rel(typ, from, to string, attrs map[string]any) {
	b.pending = append(b.pending, pendingRel{typ, from, to, attrs})
}

// resolve appends every queued relation whose two endpoints were collected.
func (b *builder) resolve() {
	for _, p := range b.pending {
		f, ok1 := b.seen[p.from]
		t, ok2 := b.seen[p.to]
		if ok1 && ok2 {
			b.b.Relations = append(b.b.Relations, batch.Relation{Type: p.typ, From: f, To: t, Attributes: p.attrs})
		}
	}
}

func (b *builder) add(arn, service, rtype, region string, attrs map[string]any) (string, bool) {
	if arn == "" {
		return "", false
	}
	if id, ok := b.seen[arn]; ok {
		return id, true
	}
	idn := map[string]string{"connection": b.c.connID, "arn": arn}
	id, err := identity.Hash(kindResource, idn)
	if err != nil {
		return "", false
	}
	a := map[string]any{
		"connection": b.c.connID, "arn": arn, "source": b.source,
		"service": service, "resource_type": rtype, "region": region,
	}
	for k, v := range attrs {
		a[k] = v
	}
	if key, ok := canonical.Key(canonical.KindARN, arn); ok {
		a[canonical.AttrCanonicalKey] = key
	}
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kindResource, Identity: idn, Attributes: a})
	b.b.Relations = append(b.b.Relations, batch.Relation{Type: "owned_by", From: string(id), To: b.account})
	b.seen[arn] = string(id)
	b.attrs[arn] = a
	return string(id), true
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (c *collector) waitObserver(scope string) func(broker.RateWait) {
	return func(w broker.RateWait) { c.status.Wait(scope, w.Until, w.Waited) }
}

func isRejected(err error) bool {
	return errors.Is(err, ErrExpired) || errors.Is(err, ErrInvalidCredential)
}

// rejected records the authorization error and tags err so the supervisor
// sets the connection EXPIRED.
func (c *collector) rejected(err error) error {
	c.status.Auth("provider rejected the credentials")
	return fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: lifecycle.StatusUnauthorized}, err)
}
