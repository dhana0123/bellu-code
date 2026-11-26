package azure

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/retry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// loopback sends every request to the test server and keeps the ARM host in the URL.
type loopback struct{ target *url.URL }

func (l loopback) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = l.target.Scheme, l.target.Host
	return http.DefaultTransport.RoundTrip(r2)
}

const sub = "11111111-1111-1111-1111-111111111111"

func newTestCollector(t *testing.T, h http.Handler) *collector {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	c := newCollector(&http.Client{Transport: loopback{u}}, store.Connection{ID: "c1"})
	noSleep := func(context.Context, time.Duration) error { return nil }
	c.probeOpt = []collectors.ProbeOption{collectors.WithProbeSleep(noSleep)}
	c.retryOpt = []retry.Option{retry.WithSleep(noSleep)}
	return c
}

func TestCollectPartialAndRetry(t *testing.T) {
	var rgCalls atomic.Int32
	c := newTestCollector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Path)
		switch {
		case p == "/subscriptions":
			w.Write([]byte(`{"value":[{"subscriptionId":"` + sub + `"}]}`))
		case strings.HasSuffix(p, "/resourcegroups"):
			if rgCalls.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Write([]byte(`{"value":[{"id":"/subscriptions/` + sub + `/resourceGroups/RG1","location":"westeurope"}]}`))
		case strings.HasSuffix(p, "/resources"):
			w.Write([]byte(`{"value":[{"id":"/subscriptions/` + sub + `/resourceGroups/RG1/providers/Microsoft.Compute/virtualMachines/vm1","type":"Microsoft.Compute/virtualMachines","location":"westeurope"},` +
				`{"id":"/subscriptions/` + sub + `/resourceGroups/RG1/providers/Microsoft.Foo/bars/x","type":"Microsoft.Foo/bars"}]}`))
		case strings.HasSuffix(p, "/roleassignments"):
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(p, "/accounts"), strings.HasSuffix(p, "/workspaces"):
			w.Write([]byte(`{"value":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != typeRoleAssignments {
		t.Fatalf("err = %v, want partial role-assignments", err)
	}
	if rgCalls.Load() != 2 {
		t.Fatalf("resource group calls = %d, want 2 (one 429 retry)", rgCalls.Load())
	}
	// subscription, resource group, vm; the unknown type is skipped.
	if len(b.Entities) != 3 {
		t.Fatalf("entities = %d, want 3: %+v", len(b.Entities), b.Entities)
	}
	if len(b.Relations) != 3 { // rg->sub, vm->sub, vm->rg
		t.Fatalf("relations = %d, want 3: %+v", len(b.Relations), b.Relations)
	}
	st := c.RunStatus()
	if len(st.Gaps) != 1 || st.Gaps[0].Reason != collectors.GapMissingPermission || st.Gaps[0].ResourceType != typeRoleAssignments {
		t.Fatalf("gaps = %+v", st.Gaps)
	}
	if len(st.RateLimitWaits) != 1 {
		t.Fatalf("waits = %+v", st.RateLimitWaits)
	}
	if len(b.Retain) == 0 {
		t.Fatal("failed type must be retained")
	}
}

func TestCollectCredentialsRejectedLeavesGraphUnchanged(t *testing.T) {
	c := newTestCollector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	b, err := c.Collect(context.Background())
	var pe *collectors.ProbeError
	if !errors.As(err, &pe) || pe.Kind != collectors.ProbeCredentialsRejected {
		t.Fatalf("err = %v, want credentials_rejected", err)
	}
	if len(b.Entities) != 0 || c.RunStatus().AuthError == "" {
		t.Fatalf("batch must be empty and auth error set: %+v", c.RunStatus())
	}
}
