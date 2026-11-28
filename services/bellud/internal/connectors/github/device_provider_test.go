package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

func deviceCall(rt http.RoundTripper) lifecycle.Call {
	return lifecycle.Call{Connection: store.Connection{Method: MethodDevice}, Client: &http.Client{Transport: rt}}
}

func TestDeviceVerifyUsesUserAndInstallations(t *testing.T) {
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		switch r.URL.Path {
		case "/user":
			return 200, `{"login":"octo"}`, nil
		case "/user/installations":
			if r.URL.Query().Get("per_page") != "1" {
				return 400, `{}`, nil
			}
			return 200, `{"total_count":0,"installations":[]}`, nil
		}
		return 404, `{}`, nil // /user/repos must not be called
	}}
	p := NewProvider(ProviderConfig{})
	call := deviceCall(rt)
	id, err := p.Verify(context.Background(), call)
	if err != nil || id.AccountLabel != "octo" || rt.count() != 2 {
		t.Fatalf("id=%+v err=%v reqs=%d", id, err, rt.count())
	}
	rep, err := p.CheckPermissions(context.Background(), call)
	if err != nil || !rep.Unverifiable {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestDeviceVerifyMapsUnauthorized(t *testing.T) {
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) { return 401, `{}`, nil }}
	_, err := NewProvider(ProviderConfig{}).Verify(context.Background(), deviceCall(rt))
	var le *lifecycle.Error
	if !errors.As(err, &le) || le.Code != lifecycle.CodeInvalidCredential {
		t.Fatalf("err=%v", err)
	}
}

func TestDeviceRefreshNeverCallsGitHub(t *testing.T) {
	rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) { return 500, `{}`, nil }}
	p := NewProvider(ProviderConfig{})
	exp := time.Now().Add(time.Hour)
	call := deviceCall(rt)
	call.Connection.CredentialExpiresAt = &exp
	if _, err := p.Refresh(context.Background(), call); err != nil || rt.count() != 0 {
		t.Fatalf("err=%v reqs=%d", err, rt.count())
	}
	if p.Refreshable(call.Connection) || !p.Refreshable(store.Connection{Method: MethodPAT}) {
		t.Fatal("only device connections are non-refreshable")
	}
}

func repoJSON(names ...string) string {
	items := make([]string, len(names))
	for i, n := range names {
		items[i] = fmt.Sprintf(`{"full_name":%q,"private":false}`, n)
	}
	return `{"repositories":[` + strings.Join(items, ",") + `]}`
}

func TestRepoListUnionsInstallationsAndDeduplicates(t *testing.T) {
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		switch r.URL.Path {
		case "/user/installations":
			return 200, `{"total_count":2,"installations":[{"id":1},{"id":2}]}`, nil
		case "/user/installations/1/repositories":
			return 200, repoJSON("o/a", "o/b"), nil
		case "/user/installations/2/repositories":
			return 200, repoJSON("o/b", "p/c"), nil
		}
		return 404, `{}`, nil
	}}
	l, err := NewProvider(ProviderConfig{}).RepoList(context.Background(), deviceCall(rt))
	if err != nil || l.Installations != 2 || len(l.Repos) != 3 {
		t.Fatalf("list=%+v err=%v", l, err)
	}
	for i, want := range []string{"o/a", "o/b", "p/c"} {
		if l.Repos[i].FullName != want {
			t.Fatalf("repos = %+v", l.Repos)
		}
	}
}

func TestRepoListCapsAtMaxListedRepos(t *testing.T) {
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		if r.URL.Path == "/user/installations" {
			return 200, `{"installations":[{"id":7}]}`, nil
		}
		names := make([]string, perPage)
		page := r.URL.Query().Get("page")
		for i := range names {
			names[i] = fmt.Sprintf("o/r-%s-%d", page, i)
		}
		return 200, repoJSON(names...), nil
	}}
	l, err := NewProvider(ProviderConfig{}).RepoList(context.Background(), deviceCall(rt))
	if err != nil || len(l.Repos) != MaxListedRepos {
		t.Fatalf("n=%d err=%v", len(l.Repos), err)
	}
}

func TestRepoListHonorsDeadline(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-block:
			return nil, errors.New("unreachable")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := NewProvider(ProviderConfig{}).RepoList(ctx, deviceCall(rt)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestValidateSelectionMaximum(t *testing.T) {
	repos := make([]string, MaxSelection)
	for i := range repos {
		repos[i] = fmt.Sprintf("o/r%d", i)
	}
	if err := ValidateSelection(repos); err != nil {
		t.Fatal(err)
	}
	if ValidateSelection(append(repos, "o/extra")) == nil {
		t.Fatal("501 repositories accepted")
	}
}

func TestInstallURLHonorsSlugOverride(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if got := InstallURL(EffectiveAppSlug(get)); got != "https://github.com/apps/bellucode/installations/new" {
		t.Fatal(got)
	}
	env[EnvAppSlug] = " my-fork "
	if got := InstallURL(EffectiveAppSlug(get)); got != "https://github.com/apps/my-fork/installations/new" {
		t.Fatal(got)
	}
}
