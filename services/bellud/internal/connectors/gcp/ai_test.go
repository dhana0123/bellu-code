package gcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

func aiServer(fail bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Orig-Host") {
		case ResourceManagerHost:
			_, _ = w.Write([]byte(`{"projects":[{"projectId":"p1","state":"ACTIVE"}]}`))
		case AIPlatformHost:
			if fail {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"endpoints":[` +
				`{"name":"projects/1/locations/us-central1/endpoints/e1","displayName":"pub","labels":{"criticality":"high"}},` +
				`{"name":"projects/1/locations/us-central1/endpoints/e2","network":"projects/1/global/networks/n"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

func TestCollectAIEndpoints(t *testing.T) {
	srv := aiServer(false)
	defer srv.Close()
	c := NewCollector(&http.Client{Transport: loopback{srv}}, store.Connection{ID: "c1"}, store.Selection{})
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, e := range b.Entities {
		if e.Type == aischema.KindService {
			got[e.Attributes["name"].(string)] = e.Attributes
		}
	}
	if len(got) != 2 {
		t.Fatalf("ai_service entities = %d", len(got))
	}
	if got["pub"]["public_access"] != "enabled" || got["pub"]["criticality"] != 0.75 || got["pub"]["location"] != "us-central1" {
		t.Fatalf("public endpoint = %v", got["pub"])
	}
	if _, ok := got[""]["public_access"]; ok {
		t.Fatalf("private endpoint reported public: %v", got[""])
	}
}

func TestCollectAIFailureAddsNothingAndRetains(t *testing.T) {
	srv := aiServer(true)
	defer srv.Close()
	c := NewCollector(&http.Client{Transport: loopback{srv}}, store.Connection{ID: "c1"}, store.Selection{})
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != TypeAIEndpoint {
		t.Fatalf("err = %v", err)
	}
	retain := false
	for _, e := range b.Entities {
		if e.Type == aischema.KindService {
			t.Fatal("failed scope emitted ai_service")
		}
	}
	for _, r := range b.Retain {
		retain = retain || r.Kind == aischema.KindService
	}
	if !retain {
		t.Fatal("no retain rule for ai_service")
	}
}
