package github

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// DefaultInterval is used when NewCollector gets a non-positive interval.
const DefaultInterval = 15 * time.Minute

// Collection type names reported in a PartialError.
const (
	typeOrg            = "org"
	typeRepo           = "repo"
	typeWorkflow       = "workflow"
	typePullRequest    = "pull_request"
	typeCodeScanning   = "code_scanning"
	typeDependabot     = "dependabot"
	typeSecretScanning = "secret_scanning"
)

// API is the subset of *Client the collector uses. The collector reaches
// GitHub only through these typed methods, never through net/http.
type API interface {
	Org(ctx context.Context, org string) (Org, error)
	Repo(ctx context.Context, owner, repo string) (Repo, error)
	Workflows(ctx context.Context, owner, repo string) ([]Workflow, error)
	OpenPullRequests(ctx context.Context, owner, repo string) ([]PullRequest, error)
	CodeScanningAlerts(ctx context.Context, owner, repo string) ([]CodeScanningAlert, error)
	DependabotAlerts(ctx context.Context, owner, repo string) ([]DependabotAlert, error)
	SecretScanningAlerts(ctx context.Context, owner, repo string) ([]SecretScanningAlert, error)
}

var (
	_ API                  = (*Client)(nil)
	_ collectors.Collector = (*Collector)(nil)
	_ collectors.Timeouter = (*Collector)(nil)
)

// Collector is the GitHub graph collector for one Connection.
type Collector struct {
	connectionID string
	api          API
	repos        []string
	interval     time.Duration
	now          func() time.Time
}

// Option customizes a Collector.
type Option func(*Collector)

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(c *Collector) { c.now = now } }

// NewCollector builds the collector for connectionID. repos is the
// Connection's repository selection as "owner/name"; nothing outside it is
// read. A nil or empty selection collects nothing.
func NewCollector(connectionID string, api API, repos []string, interval time.Duration, opts ...Option) *Collector {
	if interval <= 0 {
		interval = DefaultInterval
	}
	c := &Collector{connectionID: connectionID, api: api, repos: repos, interval: interval, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name implements collectors.Collector.
func (c *Collector) Name() string { return "connector:github:" + c.connectionID }

// Interval implements collectors.Collector.
func (c *Collector) Interval() time.Duration { return c.interval }

// Timeout implements collectors.Timeouter.
func (c *Collector) Timeout() time.Duration { return collectors.ConnectorTimeout }

// Collect implements collectors.Collector. Per-type failures yield the batch
// collected so far plus a collectors.PartialError; if no selected repository
// could be read, the error is returned with an empty batch so the previous
// observation is kept.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	name := c.Name()
	out := graph.Batch{Collector: name, ObservedAt: c.now().UTC()}
	failed := map[string]bool{}
	var firstErr error
	fail := func(t string, err error) {
		failed[t] = true
		if firstErr == nil {
			firstErr = err
		}
	}

	add := func(kind string, id map[string]string, attrs map[string]any) (identity.ID, bool) {
		id["connection"] = c.connectionID
		h, err := identity.Hash(kind, id)
		if err != nil {
			return "", false
		}
		attrs["source"] = name
		out.Entities = append(out.Entities, batch.Entity{Type: kind, Identity: id, Attributes: attrs})
		return h, true
	}
	relate := func(from, to identity.ID) {
		out.Relations = append(out.Relations, batch.Relation{Type: "owned_by", From: string(from), To: string(to)})
	}

	orgIDs := map[string]identity.ID{}
	resolved := 0
	seen := map[string]bool{}
	for _, sel := range c.repos {
		if err := ctx.Err(); err != nil {
			return graph.Batch{}, err
		}
		owner, rname, ok := strings.Cut(sel, "/")
		key := strings.ToLower(sel)
		if !ok || seen[key] {
			if !ok {
				fail(typeRepo, ErrBadName)
			}
			continue
		}
		seen[key] = true

		repo, err := c.api.Repo(ctx, owner, rname)
		if err != nil {
			fail(typeRepo, err)
			continue
		}
		resolved++
		full := sel
		if repo.FullName != "" && strings.EqualFold(repo.FullName, sel) {
			full = repo.FullName
		}

		ownerLogin := owner
		if repo.Owner.Login != "" && strings.EqualFold(repo.Owner.Login, owner) {
			ownerLogin = repo.Owner.Login
		}
		orgID, have := orgIDs[strings.ToLower(ownerLogin)]
		if !have {
			attrs := map[string]any{}
			if repo.Owner.Type == "Organization" {
				if o, err := c.api.Org(ctx, ownerLogin); err != nil {
					fail(typeOrg, err)
				} else if o.Name != "" {
					attrs["name"] = o.Name
				}
			}
			orgID, _ = add("github_org", map[string]string{"login": ownerLogin}, attrs)
			orgIDs[strings.ToLower(ownerLogin)] = orgID
		}

		visibility := "public"
		if repo.Private {
			visibility = "private"
		}
		repoAttrs := map[string]any{"visibility": visibility, "archived": repo.Archived}
		setStr(repoAttrs, "default_branch", repo.DefaultBranch)
		repoID, _ := add("github_repo", map[string]string{"full_name": full}, repoAttrs)
		relate(repoID, orgID)

		child := func(kind string, idAttrs map[string]string, attrs map[string]any) {
			idAttrs["repo"] = full
			if h, ok := add(kind, idAttrs, attrs); ok {
				relate(h, repoID)
			}
		}

		if wfs, err := c.api.Workflows(ctx, owner, rname); err != nil {
			fail(typeWorkflow, err)
		} else {
			for _, w := range wfs {
				if w.Path == "" {
					continue
				}
				a := map[string]any{}
				setStr(a, "name", w.Name)
				setStr(a, "state", w.State)
				child("github_workflow", map[string]string{"path": w.Path}, a)
			}
		}

		if prs, err := c.api.OpenPullRequests(ctx, owner, rname); err != nil {
			fail(typePullRequest, err)
		} else {
			for _, p := range prs {
				a := map[string]any{"draft": p.Draft}
				setStr(a, "state", p.State)
				setStr(a, "author_login", p.User.Login)
				setStr(a, "base_branch", p.Base.Ref)
				setTime(a, "created_at", p.CreatedAt)
				setTime(a, "updated_at", p.UpdatedAt)
				child("github_pull_request", map[string]string{"number": strconv.Itoa(p.Number)}, a)
			}
		}

		alert := func(kind string, n int, attrs map[string]any, state, url string, created time.Time) {
			setStr(attrs, "state", state)
			setStr(attrs, "url", url)
			setTime(attrs, "created_at", created)
			child("github_alert", map[string]string{"alert_type": kind, "number": strconv.Itoa(n)}, attrs)
		}

		if as, err := c.api.CodeScanningAlerts(ctx, owner, rname); err != nil {
			fail(typeCodeScanning, err)
		} else {
			for _, x := range as {
				a := map[string]any{}
				sev := x.Rule.SecuritySeverityLevel
				if sev == "" {
					sev = x.Rule.Severity
				}
				setStr(a, "severity", sev)
				setStr(a, "rule_id", x.Rule.ID)
				alert("code_scanning", x.Number, a, x.State, x.HTMLURL, x.CreatedAt)
			}
		}

		if as, err := c.api.DependabotAlerts(ctx, owner, rname); err != nil {
			fail(typeDependabot, err)
		} else {
			for _, x := range as {
				a := map[string]any{}
				setStr(a, "severity", x.Advisory.Severity)
				setStr(a, "rule_id", x.Advisory.GHSAID)
				setStr(a, "package", x.Dependency.Package.Name)
				alert("dependabot", x.Number, a, x.State, x.HTMLURL, x.CreatedAt)
			}
		}

		if as, err := c.api.SecretScanningAlerts(ctx, owner, rname); err != nil {
			fail(typeSecretScanning, err)
		} else {
			for _, x := range as {
				a := map[string]any{}
				// The alert's secret value is not part of the type; only the
				// detector id is kept, under the name "detector".
				setStr(a, "detector", x.Detector)
				alert("secret_scanning", x.Number, a, x.State, x.HTMLURL, x.CreatedAt)
			}
		}
	}

	if len(c.repos) > 0 && resolved == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("github: no selected repository could be read")
		}
		return graph.Batch{}, firstErr
	}
	if len(failed) == 0 {
		return out, nil
	}
	types := make([]string, 0, len(failed))
	for t := range failed {
		types = append(types, t)
	}
	sort.Strings(types)
	return out, collectors.PartialError{Types: types}
}

func setStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func setTime(m map[string]any, k string, t time.Time) {
	if !t.IsZero() {
		m[k] = t.UTC().Format(time.RFC3339)
	}
}
