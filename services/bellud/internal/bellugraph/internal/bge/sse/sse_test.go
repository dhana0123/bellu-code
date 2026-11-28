package sse

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/subscribe"
)

func meta(cv engine.ChangeView) subscribe.Meta {
	return subscribe.Meta{Seq: cv.Seq, Kind: string(cv.Kind), Subject: string(cv.Subject),
		EntityKind: cv.EntityKind, Entity: cv.Entity, From: cv.From, To: cv.To}
}

type fakeSrc struct {
	hub     *subscribe.Hub[engine.ChangeView]
	history []engine.ChangeView
	oldest  uint64
	opts    chan engine.SubscribeOpts
	buf     int
}

func newFake() *fakeSrc {
	return &fakeSrc{hub: subscribe.NewHub(meta, nil, nil), opts: make(chan engine.SubscribeOpts, 4), oldest: 1}
}

func (f *fakeSrc) Resolve(ref string) (engine.EntityID, error) {
	if ref == "@nope" {
		return "", errs.NotFound
	}
	if ref == "@a" {
		return "host:aa", nil
	}
	return ref, nil
}
func (f *fakeSrc) LocalID(id engine.EntityID) string { return "@" + id }
func (f *fakeSrc) Subscribe(ctx context.Context, o engine.SubscribeOpts) (*subscribe.Sub[engine.ChangeView], error) {
	f.opts <- o
	if o.From == nil {
		return f.hub.Subscribe(subscribe.Filter{}, f.buf), nil
	}
	if *o.From < f.oldest {
		return nil, &engine.GoneError{From: *o.From, Oldest: f.oldest}
	}
	sub := f.hub.SubscribeReplay(subscribe.Filter{}, f.buf)
	sub.StartReplay(func(emit func(engine.ChangeView) bool) error {
		for _, cv := range f.history {
			if cv.Seq > *o.From && !emit(cv) {
				return nil
			}
		}
		return nil
	})
	return sub, nil
}

func change(seq uint64) engine.ChangeView {
	return engine.ChangeView{Seq: seq, Kind: engine.ChangeAdded, Subject: engine.SubjectEntity,
		Entity: "host:aa", EntityKind: "host",
		ObservedAt: time.Unix(10, 0).UTC(), RecordedAt: time.Unix(20, 0).UTC()}
}

// stream starts the handler on a test server and returns a line reader.
func stream(t *testing.T, h http.Handler, path string, hdr map[string]string) (*http.Response, *bufio.Reader) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, bufio.NewReader(resp.Body)
}

// frame reads one blank-line terminated frame.
func frame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for {
			l, err := r.ReadString('\n')
			sb.WriteString(l)
			if err != nil || l == "\n" {
				break
			}
		}
		done <- sb.String()
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("timeout reading frame")
	}
	return ""
}

func TestFramingAndHeaders(t *testing.T) {
	f := newFake()
	resp, r := stream(t, New(f, Options{}), "/subscribe?entity=@a&kind=added&entity_kind=host", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" ||
		resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("bad response %d %v", resp.StatusCode, resp.Header)
	}
	o := <-f.opts
	if o.From != nil || o.Filter.Entity != "host:aa" || o.Filter.Kind != engine.ChangeAdded || o.Filter.EntityKind != "host" {
		t.Fatalf("opts %+v", o)
	}
	f.hub.Publish([]engine.ChangeView{change(7)})
	want := "id: 7\nevent: change\ndata: " +
		`{"seq":7,"kind":"added","subject":"entity","entity":"host:aa","local_id":"@host:aa","from":"","to":"","relation_type":"","observed_at":"1970-01-01T00:00:10Z","recorded_at":"1970-01-01T00:00:20Z"}` + "\n\n"
	if got := frame(t, r); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestResumeNoGap(t *testing.T) {
	f := newFake()
	f.history = []engine.ChangeView{change(1), change(2), change(3)}
	_, r := stream(t, New(f, Options{}), "/subscribe", map[string]string{"Last-Event-ID": "1"})
	if o := <-f.opts; o.From == nil || *o.From != 1 {
		t.Fatalf("from %v", o.From)
	}
	for _, seq := range []string{"id: 2\n", "id: 3\n"} {
		if got := frame(t, r); !strings.HasPrefix(got, seq) {
			t.Fatalf("got %q want %q", got, seq)
		}
	}
	// the from query wins over the header
	_, r2 := stream(t, New(f, Options{}), "/subscribe?from=2", map[string]string{"Last-Event-ID": "1"})
	if o := <-f.opts; *o.From != 2 {
		t.Fatalf("from %d", *o.From)
	}
	f.hub.Publish([]engine.ChangeView{change(4)})
	if got := frame(t, r2); !strings.HasPrefix(got, "id: 3\n") {
		t.Fatalf("got %q", got)
	}
	if got := frame(t, r2); !strings.HasPrefix(got, "id: 4\n") {
		t.Fatalf("got %q", got)
	}
}

func TestGone(t *testing.T) {
	f := newFake()
	f.oldest = 10
	_, r := stream(t, New(f, Options{}), "/subscribe?from=3", nil)
	want := "event: error\ndata: {\"code\":\"graph_gone\",\"oldest_seq\":10}\n\n"
	if got := frame(t, r); got != want {
		t.Fatalf("got %q", got)
	}
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("stream should be closed")
	}
}

func TestOverflow(t *testing.T) {
	f := newFake()
	f.buf = 2
	_, r := stream(t, New(f, Options{}), "/subscribe", nil)
	<-f.opts
	// Publish a fast burst; the 2-slot buffer overflows before the handler drains it.
	var seq uint64
	go func() {
		for i := 0; i < 100000 && f.hub.Len() > 0; i++ {
			seq++
			f.hub.Publish([]engine.ChangeView{change(seq)})
		}
	}()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no overflow")
		default:
		}
		got := frame(t, r)
		if strings.HasPrefix(got, "event: error") {
			if !strings.Contains(got, `"code":"graph_overflow","resume_from":`) {
				t.Fatalf("got %q", got)
			}
			break
		}
	}
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("stream should be closed")
	}
}

func TestKeepAlive(t *testing.T) {
	f := newFake()
	_, r := stream(t, New(f, Options{PingInterval: 10 * time.Millisecond}), "/subscribe", nil)
	for i := 0; i < 2; i++ {
		if got := frame(t, r); got != ": ping\n\n" {
			t.Fatalf("got %q", got)
		}
	}
}

func TestBadParams(t *testing.T) {
	f := newFake()
	h := New(f, Options{})
	for path, want := range map[string]int{
		"/s?from=abc":     400,
		"/s?kind=bogus":   400,
		"/s?subject=zzz":  400,
		"/s?entity=@nope": 404,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: %d want %d", path, rec.Code, want)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/s", nil))
	if rec.Code != 405 {
		t.Errorf("post %d", rec.Code)
	}
}

// ChangeView carries no relation attributes, so the relation frame does not
// either. The design (section 4.6) lists evidence/confidence/observed_at on the
// SSE frame; the code leaves the frame unchanged. This pins the actual shape.
func TestRelationFrameCarriesNoAttributes(t *testing.T) {
	f := newFake()
	_, r := stream(t, New(f, Options{}), "/subscribe?subject=relation", nil)
	<-f.opts
	f.hub.Publish([]engine.ChangeView{{Seq: 3, Kind: engine.ChangeChanged, Subject: engine.SubjectRelation,
		From: "host:aa", To: "host:bb", RelationType: "depends_on",
		ObservedAt: time.Unix(10, 0).UTC(), RecordedAt: time.Unix(20, 0).UTC()}})
	want := "id: 3\nevent: change\ndata: " +
		`{"seq":3,"kind":"changed","subject":"relation","entity":"","local_id":"","from":"host:aa","to":"host:bb","relation_type":"depends_on","observed_at":"1970-01-01T00:00:10Z","recorded_at":"1970-01-01T00:00:20Z"}` + "\n\n"
	if got := frame(t, r); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
