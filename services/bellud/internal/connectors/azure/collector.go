package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/retry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/azure/azureschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// This file reads Azure Resource Manager with GET requests only and maps the
// answers to graph entities. Only metadata is collected. Entity_ID comes from
// the Azure resource ID (lower-cased, since ARM ids are case-insensitive), so
// a rename or a tag change keeps the id.

const (
	defaultInterval = 5 * time.Minute

	// ResourcesAPIVersion serves /resources and /resourcegroups.
	ResourcesAPIVersion = "2021-04-01"

	// maxPages bounds the pages read for one resource type and subscription.
	maxPages = 200
)

// Resource types a run reads in every subscription. Each fails on its own.
const (
	typeResourceGroups  = "resource-groups"
	typeResources       = "resources"
	typeRoleAssignments = "role-assignments"
)

type collector struct {
	hc       *http.Client
	connID   string
	interval time.Duration
	subs     []string // selected subscription ids; empty means all visible
	status   collectors.StatusRecorder
	now      func() time.Time
	probeOpt []collectors.ProbeOption
	retryOpt []retry.Option
}

var _ collectors.StatusReporter = (*collector)(nil)

// RunStatus implements collectors.StatusReporter.
func (c *collector) RunStatus() collectors.RunStatus { return c.status.Status() }

// NewCollector returns the collector of one Azure Connection. hc must send
// requests through the broker; only subscriptions in conn.Selection.Items are
// read (all visible ones when empty).
func NewCollector(hc *http.Client, conn store.Connection) collectors.Collector {
	return newCollector(hc, conn)
}

func newCollector(hc *http.Client, conn store.Connection) *collector {
	iv := defaultInterval
	if conn.IntervalSec > 0 {
		iv = time.Duration(conn.IntervalSec) * time.Second
	}
	seen := map[string]bool{}
	var subs []string
	for _, s := range conn.Selection.Items {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" && !seen[s] {
			seen[s] = true
			subs = append(subs, s)
		}
	}
	sort.Strings(subs)
	return &collector{hc: hc, connID: conn.ID, interval: iv, subs: subs, now: time.Now}
}

func (c *collector) Name() string            { return "connector:azure:" + c.connID }
func (c *collector) Interval() time.Duration { return c.interval }

// Timeout implements collectors.Timeouter.
func (c *collector) Timeout() time.Duration { return collectors.ConnectorTimeout }

// httpError is a non-2xx response. It carries no body.
type httpError struct{ Status int }

func (e *httpError) Error() string   { return fmt.Sprintf("azure: unexpected status %d", e.Status) }
func (e *httpError) HTTPStatus() int { return e.Status }

// get reads one ARM page, retrying rate limits, and decodes it into out.
func (c *collector) get(ctx context.Context, scope, rawURL string, out any) error {
	opts := append([]retry.Option{retry.WithOnWait(func(d time.Duration) {
		c.status.Wait(scope, c.now().Add(d), d)
	})}, c.retryOpt...)
	return retry.Do(ctx, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := retry.FromResponse(resp, c.now()); err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &httpError{Status: resp.StatusCode}
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return err
		}
		return json.Unmarshal(body, out)
	}, opts...)
}

// page is the envelope of every ARM list response.
type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

// list reads every page of a list URL. It follows nextLink only on the ARM host.
func list[T any](ctx context.Context, c *collector, scope, first string) ([]T, error) {
	var all []T
	next := first
	for i := 0; next != ""; i++ {
		if i >= maxPages {
			return all, errors.New("azure: page limit reached")
		}
		var p page[T]
		if err := c.get(ctx, scope, next, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Value...)
		next = ""
		if p.NextLink != "" {
			u, err := url.Parse(p.NextLink)
			if err != nil || u.Scheme != "https" || u.Host != ARMHost {
				return nil, errors.New("azure: refusing nextLink outside Azure Resource Manager")
			}
			next = p.NextLink
		}
	}
	return all, nil
}

func armURL(path, apiVersion string) string {
	return "https://" + ARMHost + path + "?api-version=" + apiVersion
}

type armResource struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

type armRoleAssignment struct {
	ID         string `json:"id"`
	Properties struct {
		PrincipalID      string `json:"principalId"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		Scope            string `json:"scope"`
	} `json:"properties"`
}

// resourceTypes maps lower-cased ARM types to azure_type values. Types not
// listed are not collected.
var resourceTypes = map[string]string{
	"microsoft.network/virtualnetworks":                azureschema.TypeVNet,
	"microsoft.network/networksecuritygroups":          azureschema.TypeNSG,
	"microsoft.network/loadbalancers":                  azureschema.TypeLoadBalancer,
	"microsoft.compute/virtualmachines":                azureschema.TypeVM,
	"microsoft.containerservice/managedclusters":       azureschema.TypeAKS,
	"microsoft.web/sites":                              azureschema.TypeFunction,
	"microsoft.storage/storageaccounts":                azureschema.TypeStorageAccount,
	"microsoft.sql/servers/databases":                  azureschema.TypeSQLDatabase,
	"microsoft.keyvault/vaults":                        azureschema.TypeKeyVault,
	"microsoft.managedidentity/userassignedidentities": azureschema.TypeManagedIdentity,
	"microsoft.cognitiveservices/accounts/deployments": azureschema.TypeOpenAIDeploy,
}

type pendingRel struct{ typ, from, to string }

type builder struct {
	c       *collector
	source  string
	b       batch.Batch
	seen    map[string]string // lower-cased azure id -> entity id
	pending []pendingRel
}

func (b *builder) add(kind, idKey, azID string, attrs map[string]any) (string, bool) {
	key := strings.ToLower(azID)
	if key == "" {
		return "", false
	}
	if id, ok := b.seen[key]; ok {
		return id, true
	}
	idn := map[string]string{"connection": b.c.connID, idKey: key}
	id, err := identity.Hash(kind, idn)
	if err != nil {
		return "", false
	}
	a := map[string]any{"connection": b.c.connID, idKey: key, "source": b.source}
	for k, v := range attrs {
		a[k] = v
	}
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kind, Identity: idn, Attributes: a})
	b.seen[key] = string(id)
	return string(id), true
}

func (b *builder) rel(typ, from, to string) {
	b.pending = append(b.pending, pendingRel{typ, strings.ToLower(from), strings.ToLower(to)})
}

// retain keeps what an earlier run observed for a type that failed now, so a
// failed read does not retire its entities.
func (b *builder) retain(rtype, sub string) {
	switch rtype {
	case typeResourceGroups:
		b.b.Retain = append(b.b.Retain, batch.Retain{Kind: azureschema.KindResource,
			Attrs: map[string]string{"azure_type": azureschema.TypeResourceGroup, "subscription_id": sub}})
	case typeResources:
		for _, t := range resourceTypes {
			b.b.Retain = append(b.b.Retain, batch.Retain{Kind: azureschema.KindResource,
				Attrs: map[string]string{"azure_type": t, "subscription_id": sub}})
		}
	case typeRoleAssignments:
		b.b.Retain = append(b.b.Retain, batch.Retain{Kind: azureschema.KindRoleAssignment})
	case typeAI:
		b.retainAI(sub)
	}
}

func (b *builder) resolve() {
	for _, p := range b.pending {
		f, ok1 := b.seen[p.from]
		t, ok2 := b.seen[p.to]
		if ok1 && ok2 {
			b.b.Relations = append(b.b.Relations, batch.Relation{Type: p.typ, From: f, To: t})
		}
	}
}

// resourceGroupOf returns the group name of an ARM id, or "".
func resourceGroupOf(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourcegroups") {
			return parts[i+1]
		}
	}
	return ""
}

// Collect probes the credentials, then reads each resource type of each
// selected subscription independently. A failed type becomes a gap and the run
// returns the rest with a PartialError. A failed probe returns a
// *collectors.ProbeError and no batch, so the graph stays unchanged.
func (c *collector) Collect(ctx context.Context) (graph.Batch, error) {
	c.status.Reset()
	var visible []subscription
	err := collectors.Probe(ctx, func(ctx context.Context) error {
		subs, err := list[subscription](ctx, c, "global", armURL("/subscriptions", SubscriptionsAPIVersion))
		visible = subs
		return err
	}, c.probeOpt...)
	if err != nil {
		var pe *collectors.ProbeError
		if errors.As(err, &pe) && pe.Kind == collectors.ProbeCredentialsRejected {
			c.status.Auth("provider rejected the credentials")
		}
		return graph.Batch{}, err
	}
	subs := c.subs
	if len(subs) == 0 {
		for _, s := range visible {
			if s.ID != "" {
				subs = append(subs, strings.ToLower(s.ID))
			}
		}
		sort.Strings(subs)
	}

	source := c.Name()
	b := &builder{c: c, source: source, seen: map[string]string{}}
	b.b.Collector = source
	failed := map[string]bool{}
	attempts, failures := 0, 0
	try := func(rtype, sub string, fn func() error) {
		attempts++
		if err := fn(); err != nil {
			failures++
			failed[rtype] = true
			b.retain(rtype, sub)
			c.status.FailType(rtype, sub, err)
		}
	}

	for _, sub := range subs {
		if ctx.Err() != nil {
			return graph.Batch{}, ctx.Err()
		}
		if strings.ContainsAny(sub, "/?#") {
			continue
		}
		subPath := "/subscriptions/" + sub
		if _, ok := b.add(azureschema.KindSubscription, "subscription_id", sub, nil); !ok {
			continue
		}

		try(typeResourceGroups, sub, func() error {
			groups, err := list[armResource](ctx, c, sub, armURL(subPath+"/resourcegroups", ResourcesAPIVersion))
			if err != nil {
				return err
			}
			for _, g := range groups {
				a := map[string]any{"azure_type": azureschema.TypeResourceGroup, "location": g.Location,
					"subscription_id": sub, "resource_group": resourceGroupOf(g.ID)}
				if _, ok := b.add(azureschema.KindResource, "resource_id", g.ID, a); ok {
					b.rel("azure_in_subscription", g.ID, sub)
				}
			}
			return nil
		})

		try(typeResources, sub, func() error {
			res, err := list[armResource](ctx, c, sub, armURL(subPath+"/resources", ResourcesAPIVersion))
			if err != nil {
				return err
			}
			var accts map[string]armStorageAccount
			storage := func() map[string]armStorageAccount {
				if accts == nil {
					accts = c.storageAccounts(ctx, sub)
				}
				return accts
			}
			for _, r := range res {
				t, known := resourceTypes[strings.ToLower(r.Type)]
				if !known {
					continue
				}
				if t == azureschema.TypeFunction && !strings.Contains(strings.ToLower(r.Kind), "functionapp") {
					continue
				}
				a := map[string]any{"azure_type": t, "location": r.Location,
					"subscription_id": sub, "resource_group": resourceGroupOf(r.ID)}
				for k, v := range c.dataAttrsFor(t, r.ID, storage) {
					a[k] = v
				}
				if _, ok := b.add(azureschema.KindResource, "resource_id", r.ID, a); !ok {
					continue
				}
				b.rel("azure_in_subscription", r.ID, sub)
				if g := resourceGroupOf(r.ID); g != "" {
					b.rel("azure_in_resource_group", r.ID, subPath+"/resourceGroups/"+g)
				}
			}
			return nil
		})

		try(typeAI, sub, func() error { return b.collectAI(ctx, sub) })

		try(typeRoleAssignments, sub, func() error {
			ras, err := list[armRoleAssignment](ctx, c, sub,
				armURL(subPath+"/providers/Microsoft.Authorization/roleAssignments", AuthorizationAPIVersion))
			if err != nil {
				return err
			}
			for _, ra := range ras {
				a := map[string]any{"principal_id": ra.Properties.PrincipalID,
					"role_definition_id": ra.Properties.RoleDefinitionID, "scope": ra.Properties.Scope}
				if _, ok := b.add(azureschema.KindRoleAssignment, "assignment_id", ra.ID, a); ok {
					b.rel("azure_assignment_scope", ra.ID, ra.Properties.Scope)
				}
			}
			return nil
		})
	}

	if attempts > 0 && failures == attempts {
		// Nothing usable: an empty full observation would delete every entity.
		return graph.Batch{}, errors.New("azure: every resource type failed")
	}
	b.resolve()
	b.b.ObservedAt = c.now().UTC()
	if len(failed) > 0 {
		types := make([]string, 0, len(failed))
		for t := range failed {
			types = append(types, t)
		}
		sort.Strings(types)
		return b.b, collectors.PartialError{Types: types}
	}
	return b.b, nil
}
