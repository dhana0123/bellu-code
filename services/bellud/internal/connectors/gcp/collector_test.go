package gcp

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
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gcp/gcpschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// loopback sends every request to srv, whatever its host.
type loopback struct{ srv *httptest.Server }

func (l loopback) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(l.srv.URL)
	r = r.Clone(r.Context())
	r.Header.Set("X-Orig-Host", r.URL.Host)
	r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(r)
}

func TestCollectorTypesFailIndependently(t *testing.T) {
	var throttled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, p := r.Header.Get("X-Orig-Host"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case host == ResourceManagerHost:
			_, _ = w.Write([]byte(`{"projects":[{"projectId":"p1","state":"ACTIVE"}]}`))
		case strings.HasSuffix(p, "/global/networks"):
			_, _ = w.Write([]byte(`{"items":[{"selfLink":"https://www.googleapis.com/compute/v1/projects/p1/global/networks/default"}]}`))
		case strings.HasSuffix(p, "/aggregated/instances"):
			if throttled.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			_, _ = w.Write([]byte(`{"items":{"zones/us-central1-a":{"instances":[{"selfLink":"https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm1","zone":"https://x/zones/us-central1-a"}]}}}`))
		case host == StorageHost:
			w.WriteHeader(http.StatusForbidden)
		case host == IAMHost:
			_, _ = w.Write([]byte(`{"accounts":[{"name":"projects/p1/serviceAccounts/sa@p1.iam.gserviceaccount.com"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := NewCollector(&http.Client{Transport: loopback{srv}}, store.Connection{ID: "c1"}, store.Selection{}).(*collector)
	c.retryOpts = []retry.Option{retry.WithSleep(func(context.Context, time.Duration) error { return nil })}
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != gcpschema.TypeBucket {
		t.Fatalf("want partial on bucket, got %v", err)
	}
	st := c.RunStatus()
	if len(st.Gaps) != 1 || st.Gaps[0].Reason != collectors.GapMissingPermission || st.Gaps[0].Scope != "p1" {
		t.Fatalf("gaps: %+v", st.Gaps)
	}
	if len(st.RateLimitWaits) != 1 {
		t.Fatalf("rate limit waits: %+v", st.RateLimitWaits)
	}
	// project + network + instance + service account
	if len(b.Entities) != 4 || len(b.Retain) != 1 {
		t.Fatalf("entities=%d retain=%d", len(b.Entities), len(b.Retain))
	}
}
