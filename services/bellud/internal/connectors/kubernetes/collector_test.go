package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/kubernetes/k8sschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

const secretValue = "c3VwZXItc2VjcmV0" // would appear only if values crossed the wire

type fakeAPI struct {
	mu        sync.Mutex
	podName   string
	accepts   map[string]string // path -> Accept
	status    map[string]int    // path -> forced status
	limited   int               // 429s before pods answers
	ignoreAcc bool              // return a full SecretList although metadata was asked
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepts[r.URL.Path] = r.Header.Get("Accept")
	if r.Method != http.MethodGet {
		http.Error(w, "read only", http.StatusMethodNotAllowed)
		return
	}
	if code := f.status[r.URL.Path]; code != 0 {
		w.WriteHeader(code)
		return
	}
	if r.URL.Path == "/api/v1/pods" && f.limited > 0 {
		f.limited--
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	body := `{"kind":"List","items":[]}`
	switch r.URL.Path {
	case "/version":
		body = `{"gitVersion":"v1.30.0"}`
	case "/api/v1/namespaces":
		body = `{"kind":"NamespaceList","items":[
{"metadata":{"name":"kube-system","uid":"ns-sys"}},{"metadata":{"name":"app","uid":"ns-app"}}]}`
	case "/api/v1/pods":
		body = `{"kind":"PodList","items":[{"metadata":{"name":"` + f.podName + `","namespace":"app","uid":"pod-1"},
"spec":{"serviceAccountName":"web","containers":[{"image":"nginx:1"}]}}]}`
	case "/api/v1/serviceaccounts":
		body = `{"kind":"ServiceAccountList","items":[{"metadata":{"name":"web","namespace":"app","uid":"sa-1"}}]}`
	case "/api/v1/configmaps":
		body = `{"kind":"PartialObjectMetadataList","items":[]}`
	case "/api/v1/secrets":
		if f.ignoreAcc {
			body = `{"kind":"SecretList","items":[{"metadata":{"name":"db","namespace":"app","uid":"sec-1"},"data":{"password":"` + secretValue + `"}}]}`
		} else {
			body = `{"kind":"PartialObjectMetadataList","items":[{"metadata":{"name":"db","namespace":"app","uid":"sec-1"}}]}`
		}
	}
	_, _ = w.Write([]byte(body))
}

func newCollector(t *testing.T, api *fakeAPI) *collector {
	t.Helper()
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	c := NewCollector(srv.Client(), srv.Listener.Addr().String(), store.Connection{ID: "c1"}, store.Selection{}).(*collector)
	c.sleep = func(context.Context, time.Duration) error { return nil }
	c.probeSleep = c.sleep
	return c
}

func newAPI() *fakeAPI {
	return &fakeAPI{podName: "web-1", accepts: map[string]string{}, status: map[string]int{}}
}

func ids(b batch.Batch) map[string]string {
	m := map[string]string{}
	for _, e := range b.Entities {
		n, _ := e.Attributes["name"].(string)
		m[e.Type+"/"+e.Identity["uid"]] = n
	}
	return m
}

func TestCollectSecretsAreMetadataOnlyAndIdsSurviveRename(t *testing.T) {
	api := newAPI()
	c := newCollector(t, api)
	b1, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := api.accepts["/api/v1/secrets"]; !strings.Contains(got, "as=PartialObjectMetadataList") {
		t.Fatalf("secrets Accept = %q", got)
	}
	if got := api.accepts["/api/v1/configmaps"]; !strings.Contains(got, "as=PartialObjectMetadataList") {
		t.Fatalf("configmaps Accept = %q", got)
	}
	if ids(b1)[k8sschema.KindSecretRef+"/sec-1"] != "db" {
		t.Fatalf("missing secret ref: %v", ids(b1))
	}
	api.podName = "renamed"
	b2, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(b1.Entities) != len(b2.Entities) || len(b1.Relations) != len(b2.Relations) {
		t.Fatal("second run differs")
	}
	for i := range b1.Entities {
		if b1.Entities[i].Identity["uid"] != b2.Entities[i].Identity["uid"] {
			t.Fatal("identity changed")
		}
	}
	if ids(b2)[k8sschema.KindPod+"/pod-1"] != "renamed" {
		t.Fatal("name must be a plain attribute")
	}
	rel := map[string]int{}
	for _, r := range b1.Relations {
		rel[r.Type]++
	}
	if rel[k8sschema.RelRunsAsSA] != 1 || rel[k8sschema.RelInNamespace] < 2 {
		t.Fatalf("relations = %v", rel)
	}
}

func TestCollectDiscardsListThatCarriesValues(t *testing.T) {
	api := newAPI()
	api.ignoreAcc = true
	b, err := newCollector(t, api).Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || !strings.Contains(strings.Join(pe.Types, ","), "secrets") {
		t.Fatalf("err = %v", err)
	}
	for _, e := range b.Entities {
		if e.Type == k8sschema.KindSecretRef {
			t.Fatal("secret ref kept from a non-metadata list")
		}
		for _, v := range e.Attributes {
			if s, ok := v.(string); ok && strings.Contains(s, secretValue) {
				t.Fatal("secret value in batch")
			}
		}
	}
}

func TestCollectTypeFailureIsGapAndPartial(t *testing.T) {
	api := newAPI()
	api.status["/apis/rbac.authorization.k8s.io/v1/roles"] = http.StatusForbidden
	c := newCollector(t, api)
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != "roles" {
		t.Fatalf("err = %v", err)
	}
	if len(b.Entities) == 0 || len(b.Retain) == 0 {
		t.Fatal("batch of other types and retention expected")
	}
	g := c.RunStatus().Gaps
	if len(g) != 1 || g[0].ResourceType != "roles" || g[0].Reason != collectors.GapMissingPermission {
		t.Fatalf("gaps = %+v", g)
	}
}

func TestCollectRetriesRateLimit(t *testing.T) {
	api := newAPI()
	api.limited = 2
	c := newCollector(t, api)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(c.RunStatus().RateLimitWaits); n != 2 {
		t.Fatalf("waits = %d", n)
	}
}

func TestCollectProbeRejectedLeavesNoBatch(t *testing.T) {
	api := newAPI()
	api.status["/version"] = http.StatusUnauthorized
	c := newCollector(t, api)
	b, err := c.Collect(context.Background())
	var pe *collectors.ProbeError
	var hs *lifecycle.HTTPStatusError
	if !errors.As(err, &pe) || pe.Kind != collectors.ProbeCredentialsRejected || !errors.As(err, &hs) || hs.Code != 401 {
		t.Fatalf("err = %v", err)
	}
	if len(b.Entities) != 0 || c.RunStatus().AuthError == "" {
		t.Fatal("no batch and an auth error expected")
	}
}

func TestDatabaseEngine(t *testing.T) {
	for img, want := range map[string]string{
		"postgres:16": "postgres", "docker.io/library/Redis@sha256:ab": "redis",
		"registry.local:5000/bitnami/mongodb:7": "mongodb", "nginx:1": "", "myorg/postgres-exporter:1": "",
	} {
		if got := databaseEngine(img); got != want {
			t.Errorf("%s: got %q want %q", img, got, want)
		}
	}
}
