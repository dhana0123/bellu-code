package contract

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func mustFixtures(t *testing.T) []Fixture {
	t.Helper()
	fx, err := LoadFixtures("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(fx) == 0 {
		t.Fatal("no fixtures")
	}
	return fx
}

// Recorded TS bodies must validate against their schemas (proves schema + validator correctness).
func TestRecordedFixturesMatchSchemas(t *testing.T) {
	s, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range mustFixtures(t) {
		if f.Body == nil {
			continue
		}
		sc, ok := s.Response(f.OperationID, f.Status, baseType(f.ContentType))
		if !ok {
			t.Errorf("%s/%s: no schema for %d %s", f.OperationID, f.Name, f.Status, f.ContentType)
			continue
		}
		for _, m := range s.Validate(sc, f.Body, true) {
			t.Errorf("%s/%s: %s", f.OperationID, f.Name, m)
		}
	}
}

func TestRecordedSSEEventsMatchSchemas(t *testing.T) {
	s, _ := Embedded()
	for _, f := range mustFixtures(t) {
		if len(f.Events) == 0 {
			continue
		}
		sc, _ := s.Response(f.OperationID, f.Status, "text/event-stream")
		ds := sc.(map[string]any)["properties"].(map[string]any)["data"].(map[string]any)
		inner := s.deref(ds)
		for i, e := range f.Events {
			if msgs := s.Validate(inner, e, true); len(msgs) > 0 {
				t.Errorf("%s event %d: %v", f.Name, i, msgs)
			}
		}
	}
}

func TestBrokenBodyFails(t *testing.T) {
	s, _ := Embedded()
	sc, _ := s.Response("server.info", 200, "application/json")
	broken := []any{
		map[string]any{"version": "1", "pid": "not-a-number", "urls": []any{}, "paths": map[string]any{"tmp": "/t"}},
		map[string]any{"version": "1", "urls": []any{}, "paths": map[string]any{"tmp": "/t"}},
		map[string]any{"version": "1", "pid": 1.0, "urls": []any{}, "paths": map[string]any{"tmp": "/t"}, "extra": true},
	}
	for i, b := range broken {
		if len(s.Validate(sc, b, false)) == 0 {
			t.Errorf("broken body %d unexpectedly valid", i)
		}
	}
	// Placeholders are only tolerated when requested.
	ph := map[string]any{"version": "<VERSION>", "pid": "<NUMBER>", "urls": []any{}, "paths": map[string]any{"tmp": "/t"}}
	if len(s.Validate(sc, ph, false)) == 0 || len(s.Validate(sc, ph, true)) != 0 {
		t.Error("placeholder handling wrong")
	}
}

// replayHandler serves each fixture's recorded response (optionally mutated) so Check can be exercised.
func replayHandler(fx []Fixture, mutate func(*Fixture)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, f := range fx {
			if f.Method != r.Method || f.Path != r.URL.Path || f.Request.Headers["authorization"] != "" != (r.Header.Get("Authorization") != "") {
				continue
			}
			if mutate != nil {
				mutate(&f)
			}
			w.Header().Set("Content-Type", f.ContentType)
			w.WriteHeader(f.Status)
			if len(f.Events) > 0 {
				for _, e := range f.Events {
					b, _ := json.Marshal(e)
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
				}
				return
			}
			b, _ := json.Marshal(f.Body)
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	})
}

func TestCheckAcceptsValidAndRejectsBroken(t *testing.T) {
	fx := mustFixtures(t)
	var info []Fixture
	for _, f := range fx {
		if f.OperationID == "server.info" && f.Name == "info-ok" {
			f.Body = map[string]any{"version": "1", "pid": 1.0, "urls": []any{}, "paths": map[string]any{"tmp": "/t"}}
			info = append(info, f)
		}
	}
	opts := Options{Auth: func(Fixture) string { return "Bearer x" }}
	if v := Check("server.info", replayHandler(info, nil), info, opts); len(v) != 0 {
		t.Fatalf("valid replay produced violations: %v", v)
	}
	bad := replayHandler(info, func(f *Fixture) { f.Body = map[string]any{"version": 7.0} })
	v := Check("server.info", bad, info, opts)
	if len(v) == 0 || !strings.Contains(v[0].Message, "schema") {
		t.Fatalf("expected schema violation, got %v", v)
	}
	wrongStatus := replayHandler(info, func(f *Fixture) { f.Status = 500 })
	if v := Check("server.info", wrongStatus, info, opts); len(v) == 0 {
		t.Fatal("expected status violation")
	}
}

func TestCheckSSESequence(t *testing.T) {
	var sse []Fixture
	for _, f := range mustFixtures(t) {
		if f.Name == "event-stream-ok" {
			sse = append(sse, f)
		}
	}
	if len(sse) != 1 {
		t.Fatal("missing sse fixture")
	}
	opts := Options{Auth: func(Fixture) string { return "Bearer x" }}
	good := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"server.connected\",\"id\":\"e1\",\"data\":{}}\n\n")
	})
	if v := Check("event.subscribe", good, sse, opts); len(v) != 0 {
		t.Fatalf("unexpected violations: %v", v)
	}
	wrong := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"server.nope\",\"id\":\"e1\",\"data\":{}}\n\n")
	})
	if v := Check("event.subscribe", wrong, sse, opts); len(v) == 0 {
		t.Fatal("expected violation for wrong event type")
	}
}
