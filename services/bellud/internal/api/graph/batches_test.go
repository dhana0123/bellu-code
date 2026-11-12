package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// resolvingEngine adds an Extended surface whose Resolve maps one Local_ID.
type resolvingEngine struct {
	*fakeEngine
	graph.Extended
}

func (r resolvingEngine) Resolve(_ context.Context, ref string) (graph.EntityID, error) {
	switch ref {
	case "@abcdef":
		return idA, nil
	case string(idB):
		return idB, nil
	}
	return "", fmt.Errorf("%w: %s", graph.ErrNotFound, ref)
}

func TestLocalIDResolution(t *testing.T) {
	h := New(resolvingEngine{fakeEngine: newFake()}, nil)
	code, body := get(t, h, "/entities/@abcdef")
	if code != 200 || body["id"] != string(idA) {
		t.Fatalf("local id: %d %v", code, body)
	}
	if code, _ := get(t, h, "/entities/"+string(idB)); code != 200 {
		t.Fatalf("entity id: %d", code)
	}
	if code, _ := get(t, h, "/entities/@zzzzzz"); code != 404 {
		t.Fatalf("unresolved: %d", code)
	}
	// 0, 1, l and o are outside the Local_ID alphabet.
	if code, _ := get(t, h, "/entities/@abc10l"); code != 400 {
		t.Fatalf("bad alphabet: %d", code)
	}
	// Without an Extended surface a Local_ID passes through unresolved.
	if code, _ := get(t, New(newFake(), nil), "/entities/@abcdef"); code != 404 {
		t.Fatalf("fallback: %d", code)
	}
}

func post(h http.Handler, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, Prefix+"/batches", bytes.NewReader(body)))
	return rec
}

func TestPostBatches(t *testing.T) {
	ctx := context.Background()
	en, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close(ctx) })
	h := New(en, nil)

	ok := `{"collector":"host","observed_at":"2025-01-02T03:04:05Z","entities":[{"type":"host","identity":{"hostname":"h9"},"attributes":{"os":"linux"}}]}`
	rec := post(h, []byte(ok))
	var rc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rc)
	if rec.Code != 200 || rc["entities"] != float64(1) || rc["id"] == "" {
		t.Fatalf("ok: %d %s", rec.Code, rec.Body)
	}
	id, _ := facade.Hash("host", map[string]string{"hostname": "h9"})
	if code, _ := get(t, h, "/entities/"+string(id)); code != 200 {
		t.Fatalf("ingested entity: %d", code)
	}

	bad := `{"collector":"host","entities":[{"type":"nosuchkind","identity":{"x":"y"}}]}`
	if rec := post(h, []byte(bad)); rec.Code != 400 {
		t.Fatalf("validation: %d %s", rec.Code, rec.Body)
	}
	if rec := post(h, []byte(`{`)); rec.Code != 400 {
		t.Fatalf("malformed: %d", rec.Code)
	}
	big := `{"collector":"` + strings.Repeat("a", maxBatchBytes) + `"}`
	if rec := post(h, []byte(big)); rec.Code != 413 {
		t.Fatalf("too large: %d", rec.Code)
	}

	f := newFake()
	f.state = graph.State{Kind: graph.StateStarting}
	rec = post(New(f, nil), []byte(ok))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "graph_unavailable") {
		t.Fatalf("unavailable: %d %s", rec.Code, rec.Body)
	}
	if rec := post(New(nil, nil), []byte(ok)); rec.Code != 503 {
		t.Fatalf("nil engine: %d", rec.Code)
	}
}
