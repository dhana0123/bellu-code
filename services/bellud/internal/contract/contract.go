// Package contract replays golden request/response fixtures captured from the TS server against a Go
// handler and validates the responses against the JSON Schemas derived from packages/protocol.
package contract

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fixture is one recorded request/response pair (testdata/<operationId>.<name>.json).
type Fixture struct {
	OperationID string `json:"operationId"`
	Name        string `json:"name"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Request     struct {
		Headers map[string]string `json:"headers"`
		Body    any               `json:"body,omitempty"`
	} `json:"request"`
	Status      int              `json:"status"`
	ContentType string           `json:"contentType"`
	Body        any              `json:"body,omitempty"`
	Events      []map[string]any `json:"events,omitempty"`
}

// Violation is one contract mismatch.
type Violation struct {
	Operation string
	Fixture   string
	Message   string
}

func (v Violation) String() string { return v.Operation + "/" + v.Fixture + ": " + v.Message }

// Options configures a Check run.
type Options struct {
	// Schemas defaults to the embedded set.
	Schemas *Schemas
	// Auth resolves "<AUTH:name>" header placeholders to a full Authorization header value.
	Auth func(f Fixture) string
	// Params substitutes other placeholders (e.g. "<CODE>") in request paths and headers.
	Params map[string]string
	// SSEWait bounds how long to wait for the expected events (default 3s).
	SSEWait time.Duration
}

// LoadFixtures reads every *.json fixture in dir, sorted by file name.
func LoadFixtures(dir string) ([]Fixture, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	out := make([]Fixture, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var f Fixture
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func baseType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(ct))
	}
	return mt
}

func (o Options) subst(s string, f Fixture) string {
	for k, v := range o.Params {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

// Check replays the fixtures of operation op against h and returns all violations.
// Each fixture must yield the recorded status and content type, a body valid against the operation's schema
// for that status, and for SSE operations events whose payloads validate and whose type sequence matches.
func Check(op string, h http.Handler, fixtures []Fixture, opts Options) []Violation {
	var out []Violation
	schemas := opts.Schemas
	if schemas == nil {
		s, err := Embedded()
		if err != nil {
			return []Violation{{Operation: op, Message: "load schemas: " + err.Error()}}
		}
		schemas = s
	}
	for _, f := range fixtures {
		if f.OperationID != op {
			continue
		}
		add := func(format string, args ...any) {
			out = append(out, Violation{Operation: op, Fixture: f.Name, Message: fmt.Sprintf(format, args...)})
		}
		sse := baseType(f.ContentType) == "text/event-stream"
		var status int
		var ct string
		var body []byte
		var events []sseEvent
		var err error
		if sse {
			status, ct, events, err = replaySSE(h, f, opts)
		} else {
			status, ct, body, err = replay(h, f, opts)
		}
		if err != nil {
			add("replay: %v", err)
			continue
		}
		if status != f.Status {
			add("status %d, want %d", status, f.Status)
		}
		if baseType(ct) != baseType(f.ContentType) {
			add("content type %q, want %q", ct, f.ContentType)
			continue
		}
		schema, ok := schemas.Response(op, status, baseType(ct))
		if !ok {
			add("no schema declared for status %d %s", status, baseType(ct))
			continue
		}
		if sse {
			out = append(out, checkSSE(op, f, schema, schemas, events)...)
			continue
		}
		var got any
		if err := json.Unmarshal(body, &got); err != nil {
			add("body is not JSON: %v", err)
			continue
		}
		for _, m := range schemas.Validate(schema, got, false) {
			add("schema: %s", m)
		}
		if want, ok := f.Body.(map[string]any); ok && status >= 400 {
			if g, ok := got.(map[string]any); ok && want["_tag"] != nil && want["_tag"] != g["_tag"] {
				add("error _tag %v, want %v", g["_tag"], want["_tag"])
			}
		}
	}
	return out
}

func newRequest(ctx context.Context, f Fixture, opts Options, base string) (*http.Request, error) {
	var rd io.Reader
	if f.Request.Body != nil {
		b, _ := json.Marshal(f.Request.Body)
		rd = strings.NewReader(opts.subst(string(b), f))
	}
	req, err := http.NewRequestWithContext(ctx, f.Method, base+opts.subst(f.Path, f), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range f.Request.Headers {
		if strings.HasPrefix(v, "<AUTH:") {
			if opts.Auth == nil {
				continue
			}
			v = opts.Auth(f)
		}
		req.Header.Set(k, opts.subst(v, f))
	}
	if f.Request.Body != nil && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}
	return req, nil
}

func replay(h http.Handler, f Fixture, opts Options) (int, string, []byte, error) {
	req, err := newRequest(context.Background(), f, opts, "http://contract.test")
	if err != nil {
		return 0, "", nil, err
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Content-Type"), b, err
}

type sseEvent struct {
	Name string
	Data string
}

func replaySSE(h http.Handler, f Fixture, opts Options) (int, string, []sseEvent, error) {
	wait := opts.SSEWait
	if wait == 0 {
		wait = 3 * time.Second
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	req, err := newRequest(ctx, f, opts, srv.URL)
	if err != nil {
		return 0, "", nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer res.Body.Close()
	var events []sseEvent
	if baseType(res.Header.Get("Content-Type")) != "text/event-stream" {
		return res.StatusCode, res.Header.Get("Content-Type"), nil, nil
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var cur sseEvent
	var has bool
	for sc.Scan() && len(events) < len(f.Events) {
		line := sc.Text()
		switch {
		case line == "":
			if has {
				events = append(events, cur)
			}
			cur, has = sseEvent{}, false
		case strings.HasPrefix(line, "event:"):
			cur.Name, has = strings.TrimSpace(line[6:]), true
		case strings.HasPrefix(line, "data:"):
			if cur.Data != "" {
				cur.Data += "\n"
			}
			cur.Data += strings.TrimPrefix(line[5:], " ")
			has = true
		}
	}
	return res.StatusCode, res.Header.Get("Content-Type"), events, nil
}

// checkSSE validates each event payload (the stream schema's data is JSON text of the event schema) and
// the event type sequence against the fixture.
func checkSSE(op string, f Fixture, schema any, schemas *Schemas, events []sseEvent) []Violation {
	var out []Violation
	add := func(format string, args ...any) {
		out = append(out, Violation{Operation: op, Fixture: f.Name, Message: fmt.Sprintf(format, args...)})
	}
	var dataSchema any
	if m, ok := schema.(map[string]any); ok {
		if props, ok := m["properties"].(map[string]any); ok {
			dataSchema = props["data"]
		}
	}
	if len(events) < len(f.Events) {
		add("got %d events, want %d", len(events), len(f.Events))
	}
	for i, e := range events {
		if i >= len(f.Events) {
			break
		}
		var payload any
		if err := json.Unmarshal([]byte(e.Data), &payload); err != nil {
			add("event %d: data is not JSON: %v", i, err)
			continue
		}
		if dataSchema != nil {
			// The schema describes JSON text; validate the decoded payload against its contentSchema.
			if ds, ok := dataSchema.(map[string]any); ok && ds["contentSchema"] != nil {
				dataSchema = ds["contentSchema"]
			} else if ok && ds["$ref"] != nil {
				dataSchema = schemas.deref(ds)
			}
			for _, m := range schemas.Validate(dataSchema, payload, false) {
				add("event %d: schema: %s", i, m)
			}
		}
		gotType := ""
		if m, ok := payload.(map[string]any); ok {
			gotType, _ = m["type"].(string)
		}
		if gotType == "" {
			gotType = e.Name
		}
		if want, _ := f.Events[i]["type"].(string); want != gotType {
			add("event %d: type %q, want %q", i, gotType, want)
		}
	}
	return out
}

func (s *Schemas) deref(m map[string]any) any {
	ref, _ := m["$ref"].(string)
	t, ok := s.Components[strings.TrimPrefix(ref, "#/components/schemas/")]
	if !ok {
		return m
	}
	if tm, ok := t.(map[string]any); ok && tm["contentSchema"] != nil {
		return tm["contentSchema"]
	}
	return t
}
