package github

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

type fakeAPI struct {
	repos   map[string]Repo
	errs    map[string]error // key: method or method:owner/repo
	calls   []string
	secrets []SecretScanningAlert
}

func (f *fakeAPI) err(m, o, r string) error {
	if e, ok := f.errs[m+":"+o+"/"+r]; ok {
		return e
	}
	return f.errs[m]
}

func (f *fakeAPI) Org(_ context.Context, org string) (Org, error) {
	f.calls = append(f.calls, "Org:"+org)
	return Org{Login: org, Name: "Org " + org}, f.err("Org", org, "")
}

func (f *fakeAPI) Repo(_ context.Context, o, r string) (Repo, error) {
	f.calls = append(f.calls, "Repo:"+o+"/"+r)
	if e := f.err("Repo", o, r); e != nil {
		return Repo{}, e
	}
	return f.repos[o+"/"+r], nil
}

func (f *fakeAPI) Workflows(_ context.Context, o, r string) ([]Workflow, error) {
	f.calls = append(f.calls, "Workflows:"+o+"/"+r)
	return []Workflow{{Name: "CI", Path: ".github/workflows/ci.yml", State: "active"}}, f.err("Workflows", o, r)
}

func (f *fakeAPI) OpenPullRequests(_ context.Context, o, r string) ([]PullRequest, error) {
	f.calls = append(f.calls, "PRs:"+o+"/"+r)
	p := PullRequest{Number: 7, Title: "do not ingest", State: "open", CreatedAt: time.Unix(1700000000, 0)}
	p.User.Login = "alice"
	p.Base.Ref = "main"
	return []PullRequest{p}, f.err("PRs", o, r)
}

func (f *fakeAPI) CodeScanningAlerts(_ context.Context, o, r string) ([]CodeScanningAlert, error) {
	a := CodeScanningAlert{Number: 1, State: "open"}
	a.Rule.ID, a.Rule.Severity = "go/sql", "warning"
	return []CodeScanningAlert{a}, f.err("CodeScanningAlerts", o, r)
}

func (f *fakeAPI) DependabotAlerts(_ context.Context, o, r string) ([]DependabotAlert, error) {
	a := DependabotAlert{Number: 2, State: "open"}
	a.Advisory.Severity = "high"
	a.Dependency.Package.Name = "lodash"
	return []DependabotAlert{a}, f.err("DependabotAlerts", o, r)
}

func (f *fakeAPI) SecretScanningAlerts(_ context.Context, o, r string) ([]SecretScanningAlert, error) {
	return f.secrets, f.err("SecretScanningAlerts", o, r)
}

func newFake() *fakeAPI {
	return &fakeAPI{
		repos: map[string]Repo{
			"acme/api": {FullName: "acme/api", Private: true, DefaultBranch: "main", Owner: Owner{Login: "acme", Type: "Organization"}},
			"acme/web": {FullName: "acme/web", Owner: Owner{Login: "acme", Type: "Organization"}},
		},
		errs:    map[string]error{},
		secrets: []SecretScanningAlert{{Number: 3, State: "open", Detector: "github_personal_access_token"}},
	}
}

func TestNameTimeoutInterval(t *testing.T) {
	c := NewCollector("cn_1", newFake(), nil, 0)
	if c.Name() != "connector:github:cn_1" {
		t.Fatalf("name %q", c.Name())
	}
	if c.Timeout() != 120*time.Second {
		t.Fatalf("timeout %v", c.Timeout())
	}
	if c.Interval() != DefaultInterval {
		t.Fatalf("interval %v", c.Interval())
	}
}

func TestCollectSelectedReposOnly(t *testing.T) {
	f := newFake()
	c := NewCollector("cn_1", f, []string{"acme/api"}, time.Minute)
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "acme/web") {
			t.Fatalf("unselected repo read: %s", call)
		}
	}
	counts := map[string]int{}
	for _, e := range b.Entities {
		counts[e.Type]++
		if e.Identity["connection"] != "cn_1" {
			t.Fatalf("%s lacks connection identity", e.Type)
		}
		if e.Attributes["source"] != "connector:github:cn_1" {
			t.Fatalf("%s source %v", e.Type, e.Attributes["source"])
		}
		if _, err := identity.Hash(e.Type, e.Identity); err != nil {
			t.Fatalf("%s identity: %v", e.Type, err)
		}
	}
	want := map[string]int{"github_org": 1, "github_repo": 1, "github_workflow": 1, "github_pull_request": 1, "github_alert": 3}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("%s = %d, want %d (%v)", k, counts[k], v, counts)
		}
	}
	if b.Collector != "connector:github:cn_1" {
		t.Fatalf("collector %q", b.Collector)
	}
	// repo, workflow, PR and 3 alerts each owned_by their parent: 1 + 1 + 1 + 3.
	if len(b.Relations) != 6 {
		t.Fatalf("relations = %d", len(b.Relations))
	}
	for _, r := range b.Relations {
		if r.Type != "owned_by" || len(r.Attributes) != 0 {
			t.Fatalf("bad relation %+v", r)
		}
	}
}

func TestAttributeHygiene(t *testing.T) {
	f := newFake()
	c := NewCollector("cn_1", f, []string{"acme/api"}, time.Minute)
	b, _ := c.Collect(context.Background())
	sawDetector := false
	for _, e := range b.Entities {
		for k, v := range e.Attributes {
			l := strings.ToLower(k)
			for _, frag := range []string{"secret", "token", "password", "credential", "private", "hash", "apikey", "data"} {
				if strings.Contains(l, frag) {
					t.Fatalf("attribute %q on %s matches %q", k, e.Type, frag)
				}
			}
			if s, ok := v.(string); ok && s == "do not ingest" {
				t.Fatal("PR title ingested")
			}
		}
		if d, ok := e.Attributes["detector"]; ok {
			sawDetector = d == "github_personal_access_token"
		}
	}
	if !sawDetector {
		t.Fatal("detector attribute missing")
	}
}

func TestPartialErrorPerType(t *testing.T) {
	f := newFake()
	f.errs["Workflows"] = errors.New("boom")
	f.errs["SecretScanningAlerts"] = &StatusError{Status: 403}
	c := NewCollector("cn_1", f, []string{"acme/api"}, time.Minute)
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(pe.Types, ",") != "secret_scanning,workflow" {
		t.Fatalf("types %v", pe.Types)
	}
	counts := map[string]int{}
	for _, e := range b.Entities {
		counts[e.Type]++
	}
	if counts["github_workflow"] != 0 || counts["github_alert"] != 2 || counts["github_pull_request"] != 1 {
		t.Fatalf("counts %v", counts)
	}
}

func TestOneRepoFailingIsPartial(t *testing.T) {
	f := newFake()
	f.errs["Repo:acme/web"] = &StatusError{Status: 404}
	c := NewCollector("cn_1", f, []string{"acme/api", "acme/web"}, time.Minute)
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != "repo" {
		t.Fatalf("err = %v", err)
	}
	if len(b.Entities) == 0 {
		t.Fatal("expected usable batch")
	}
}

func TestAllReposFailingReturnsError(t *testing.T) {
	f := newFake()
	f.errs["Repo"] = &StatusError{Status: 401}
	c := NewCollector("cn_1", f, []string{"acme/api"}, time.Minute)
	b, err := c.Collect(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || !se.Unauthorized() || len(b.Entities) != 0 {
		t.Fatalf("err = %v, entities = %d", err, len(b.Entities))
	}
}

func TestEmptySelectionCollectsNothing(t *testing.T) {
	f := newFake()
	b, err := NewCollector("cn_1", f, nil, time.Minute).Collect(context.Background())
	if err != nil || len(b.Entities) != 0 || len(f.calls) != 0 {
		t.Fatalf("err=%v entities=%d calls=%v", err, len(b.Entities), f.calls)
	}
}
