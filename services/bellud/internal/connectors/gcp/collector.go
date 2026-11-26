package gcp

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
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gcp/gcpschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// The collector reads metadata only, through GET list calls that the manifest
// allows. It takes an *http.Client so the broker's policy transport (or a
// loopback test transport) decides where requests go and how they are signed.

const (
	defaultInterval = 5 * time.Minute
	maxPages        = 100
	maxListBody     = 16 << 20
)

type collector struct {
	client   *http.Client
	connID   string
	interval time.Duration
	projects []string // selected project ids; empty means every visible project
	status   collectors.StatusRecorder

	// probeOpts and retryOpts let tests skip real waits.
	probeOpts []collectors.ProbeOption
	retryOpts []retry.Option
	now       func() time.Time
}

var (
	_ collectors.StatusReporter = (*collector)(nil)
	_ collectors.Timeouter      = (*collector)(nil)
)

// NewCollector returns the collector of one Google Cloud Connection. The
// projects in sel.Items are read; with none selected, every active project
// the account can see is read.
func NewCollector(client *http.Client, conn store.Connection, sel store.Selection) collectors.Collector {
	iv := defaultInterval
	if conn.IntervalSec > 0 {
		iv = time.Duration(conn.IntervalSec) * time.Second
	}
	seen := map[string]bool{}
	var ps []string
	for _, p := range sel.Items {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			ps = append(ps, p)
		}
	}
	sort.Strings(ps)
	return &collector{client: client, connID: conn.ID, interval: iv, projects: ps, now: time.Now}
}

func (c *collector) Name() string                    { return "connector:gcp:" + c.connID }
func (c *collector) Interval() time.Duration         { return c.interval }
func (c *collector) Timeout() time.Duration          { return collectors.ConnectorTimeout }
func (c *collector) RunStatus() collectors.RunStatus { return c.status.Status() }

// httpError is a non-2xx response. HTTPStatus lets collectors.ClassifyGap map
// 401 and 403 to missing_permission.
type httpError struct {
	status int
	host   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("gcp: %s returned status %d", e.host, e.status)
}
func (e *httpError) HTTPStatus() int { return e.status }

// resourceType is one row of the table-driven loop. Each type is read per
// project and fails on its own.
type resourceType struct {
	typ  string // gcp_type value
	host string
	path string   // with {p} for the project id
	args []string // extra query parameters, "k={p}" allowed
	// items returns the resource objects of one page.
	items func(page map[string]any) []map[string]any
	// name returns the full resource name of one object, or "".
	name func(project string, o map[string]any) string
	// attrs returns extra scalar attributes of one object.
	attrs func(o map[string]any) map[string]any
}

func str(o map[string]any, k string) string {
	s, _ := o[k].(string)
	return s
}

func list(key string) func(map[string]any) []map[string]any {
	return func(page map[string]any) []map[string]any {
		var out []map[string]any
		arr, _ := page[key].([]any)
		for _, x := range arr {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
}

// aggregated flattens a compute aggregatedList page: items is an object keyed
// by scope, each value holding the list under key.
func aggregated(key string) func(map[string]any) []map[string]any {
	return func(page map[string]any) []map[string]any {
		var out []map[string]any
		scopes, _ := page["items"].(map[string]any)
		keys := make([]string, 0, len(scopes))
		for k := range scopes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sc, _ := scopes[k].(map[string]any)
			arr, _ := sc[key].([]any)
			for _, x := range arr {
				if m, ok := x.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
		return out
	}
}

// computeName trims a compute selfLink to "projects/...".
func computeName(_ string, o map[string]any) string {
	l := str(o, "selfLink")
	if i := strings.Index(l, "/projects/"); i >= 0 {
		return l[i+1:]
	}
	return ""
}

func location(o map[string]any) map[string]any {
	loc := str(o, "zone")
	if loc == "" {
		loc = str(o, "region")
	}
	if i := strings.LastIndex(loc, "/"); i >= 0 {
		loc = loc[i+1:]
	}
	return map[string]any{"location": loc}
}

// TODO(task 41.1 follow-up): the cis_gcp pack reads direction, internet_open,
// from_port, to_port, public_access, uniform_bucket_level_access, ssl_required
// and role, which this collector does not emit yet, and Analysis (exposure.go)
// is not called. Needs firewall, bucket, SQL and instance parsing; azure and
// kubernetes have the same gap against cis_azure and cis_k8s.
var resourceTypes = []resourceType{
	{typ: gcpschema.TypeNetwork, host: ComputeHost, path: "/compute/v1/projects/{p}/global/networks",
		items: list("items"), name: computeName},
	{typ: gcpschema.TypeSubnetwork, host: ComputeHost, path: "/compute/v1/projects/{p}/aggregated/subnetworks",
		items: aggregated("subnetworks"), name: computeName, attrs: location},
	{typ: gcpschema.TypeFirewall, host: ComputeHost, path: "/compute/v1/projects/{p}/global/firewalls",
		items: list("items"), name: computeName},
	{typ: gcpschema.TypeInstance, host: ComputeHost, path: "/compute/v1/projects/{p}/aggregated/instances",
		items: aggregated("instances"), name: computeName, attrs: location},
	{typ: gcpschema.TypeGKECluster, host: ContainerHost, path: "/v1/projects/{p}/locations/-/clusters",
		items: list("clusters"),
		name: func(p string, o map[string]any) string {
			if n, l := str(o, "name"), str(o, "location"); n != "" && l != "" {
				return "projects/" + p + "/locations/" + l + "/clusters/" + n
			}
			return ""
		},
		attrs: func(o map[string]any) map[string]any { return map[string]any{"location": str(o, "location")} }},
	{typ: gcpschema.TypeBucket, host: StorageHost, path: "/storage/v1/b", args: []string{"project={p}"},
		items: list("items"),
		name: func(_ string, o map[string]any) string {
			if n := str(o, "name"); n != "" {
				return "projects/_/buckets/" + n
			}
			return ""
		},
		attrs: bucketAttrs},
	{typ: gcpschema.TypeSQLInstance, host: SQLAdminHost, path: "/v1/projects/{p}/instances",
		items: list("items"),
		name: func(p string, o map[string]any) string {
			if n := str(o, "name"); n != "" {
				return "projects/" + p + "/instances/" + n
			}
			return ""
		},
		attrs: sqlAttrs},
	{typ: gcpschema.TypeServiceAccount, host: IAMHost, path: "/v1/projects/{p}/serviceAccounts",
		items: list("accounts"),
		name:  func(_ string, o map[string]any) string { return str(o, "name") }},
}

// get fetches one JSON page, retrying rate-limited responses.
func (c *collector) get(ctx context.Context, scope, rawURL string) (map[string]any, error) {
	var page map[string]any
	opts := append([]retry.Option{retry.WithOnWait(func(d time.Duration) {
		c.status.Wait(scope, c.now().Add(d), d)
	})}, c.retryOpts...)
	err := retry.Do(ctx, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if rl := retry.FromResponse(resp, c.now()); rl != nil {
			return rl
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &httpError{status: resp.StatusCode, host: req.URL.Host}
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
		if err != nil {
			return err
		}
		var out map[string]any
		if json.Unmarshal(body, &out) != nil {
			return fmt.Errorf("gcp: invalid response from %s", req.URL.Host)
		}
		page = out
		return nil
	}, opts...)
	return page, err
}

// pages reads every page of a list call.
func (c *collector) pages(ctx context.Context, scope string, rt resourceType, project string) ([]map[string]any, error) {
	var out []map[string]any
	token := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{}
		for _, a := range rt.args {
			k, v, _ := strings.Cut(a, "=")
			q.Set(k, strings.ReplaceAll(v, "{p}", project))
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		u := "https://" + rt.host + strings.ReplaceAll(rt.path, "{p}", url.PathEscape(project))
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		page, err := c.get(ctx, scope, u)
		if err != nil {
			return nil, err
		}
		out = append(out, rt.items(page)...)
		if token = str(page, "nextPageToken"); token == "" {
			return out, nil
		}
	}
	return out, nil
}

// discover lists the active projects the account can see.
func (c *collector) discover(ctx context.Context) ([]string, error) {
	var ids []string
	token := ""
	for i := 0; i < maxPages; i++ {
		u := "https://" + ResourceManagerHost + "/v3/projects:search?pageSize=50"
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		page, err := c.get(ctx, "projects", u)
		if err != nil {
			return nil, err
		}
		arr, _ := page["projects"].([]any)
		for _, x := range arr {
			m, _ := x.(map[string]any)
			if id := str(m, "projectId"); id != "" && (str(m, "state") == "" || str(m, "state") == "ACTIVE") {
				ids = append(ids, id)
			}
		}
		if token = str(page, "nextPageToken"); token == "" {
			break
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Collect gathers the full current observation. A resource type that fails is
// skipped, recorded as a gap, kept through Batch.Retain, and reported through
// collectors.PartialError.
func (c *collector) Collect(ctx context.Context) (graph.Batch, error) {
	c.status.Reset()
	probe := func(ctx context.Context) error {
		_, err := c.get(ctx, "probe", "https://"+ResourceManagerHost+"/v3/projects:search?pageSize=1")
		return err
	}
	if err := collectors.Probe(ctx, probe, c.probeOpts...); err != nil {
		var pe *collectors.ProbeError
		if errors.As(err, &pe) && pe.Kind == collectors.ProbeCredentialsRejected {
			c.status.Auth("provider rejected the credentials")
			return graph.Batch{}, fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: lifecycle.StatusUnauthorized}, err)
		}
		return graph.Batch{}, err
	}

	projects := c.projects
	if len(projects) == 0 {
		var err error
		if projects, err = c.discover(ctx); err != nil {
			return graph.Batch{}, err
		}
	}

	source := c.Name()
	var b batch.Batch
	b.Collector = source
	failed := map[string]bool{}
	attempted := 0
	for _, p := range projects {
		pidn := map[string]string{"connection": c.connID, "project_id": p}
		pid, err := identity.Hash(gcpschema.KindProject, pidn)
		if err != nil {
			return graph.Batch{}, err
		}
		b.Entities = append(b.Entities, batch.Entity{Type: gcpschema.KindProject, Identity: pidn,
			Attributes: map[string]any{"connection": c.connID, "project_id": p, "source": source}})
		seen := map[string]bool{}
		for _, rt := range resourceTypes {
			attempted++
			objs, err := c.pages(ctx, p, rt, p)
			if err != nil {
				if ctx.Err() != nil {
					return graph.Batch{}, ctx.Err()
				}
				c.status.FailType(rt.typ, p, err)
				failed[rt.typ] = true
				b.Retain = append(b.Retain, batch.Retain{Kind: gcpschema.KindResource,
					Attrs: map[string]string{"connection": c.connID, "project_id": p, gcpschema.DiscriminatorType: rt.typ}})
				continue
			}
			for _, o := range objs {
				name := rt.name(p, o)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				idn := map[string]string{"connection": c.connID, "resource_name": name}
				id, err := identity.Hash(gcpschema.KindResource, idn)
				if err != nil {
					continue
				}
				a := map[string]any{
					"connection": c.connID, "resource_name": name, "project_id": p, "source": source,
					gcpschema.DiscriminatorType: rt.typ,
				}
				if rt.attrs != nil {
					for k, v := range rt.attrs(o) {
						a[k] = v
					}
				}
				b.Entities = append(b.Entities, batch.Entity{Type: gcpschema.KindResource, Identity: idn, Attributes: a})
				b.Relations = append(b.Relations, batch.Relation{Type: "gcp_in_project", From: string(id), To: string(pid)})
			}
		}
		attempted++
		if !c.collectAI(ctx, p, source, &b) {
			if ctx.Err() != nil {
				return graph.Batch{}, ctx.Err()
			}
			failed[TypeAIEndpoint] = true
		}
	}
	if attempted > 0 && len(c.status.Status().Gaps) == attempted {
		// Nothing usable: an empty full observation would delete every entity.
		return graph.Batch{}, errors.New("gcp: every resource type failed")
	}
	if len(failed) > 0 {
		types := make([]string, 0, len(failed))
		for t := range failed {
			types = append(types, t)
		}
		sort.Strings(types)
		return b, collectors.PartialError{Types: types}
	}
	return b, nil
}
