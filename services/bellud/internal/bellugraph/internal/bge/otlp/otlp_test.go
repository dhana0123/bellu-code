package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/metrics"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

type fakeApplier struct {
	got  []batch.Batch
	mode []engine.Mode
	err  error
}

func (f *fakeApplier) Apply(_ context.Context, b batch.Batch, m engine.Mode) (engine.Receipt, error) {
	if f.err != nil {
		return engine.Receipt{}, f.err
	}
	f.got = append(f.got, b)
	f.mode = append(f.mode, m)
	return engine.Receipt{ID: "x"}, nil
}

func addResource(l plog.Logs, collector string, full bool) plog.LogRecordSlice {
	rl := l.ResourceLogs().AppendEmpty()
	if collector != "" {
		rl.Resource().Attributes().PutStr(AttrCollector, collector)
	}
	if full {
		rl.Resource().Attributes().PutBool(AttrFullObservation, true)
	}
	return rl.ScopeLogs().AppendEmpty().LogRecords()
}

func entityRec(rs plog.LogRecordSlice, kind string, ts time.Time) plog.LogRecord {
	r := rs.AppendEmpty()
	r.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	a := r.Attributes()
	a.PutStr(AttrRecord, "entity")
	a.PutStr(AttrKind, kind)
	a.PutStr(PrefixIdentity+"name", "web")
	a.PutStr(PrefixAttr+"s", "v")
	a.PutBool(PrefixAttr+"b", true)
	a.PutInt(PrefixAttr+"i", 7)
	a.PutDouble(PrefixAttr+"d", 1.5)
	sl := a.PutEmptySlice(PrefixAttr + "l")
	sl.AppendEmpty().SetStr("p")
	sl.AppendEmpty().SetStr("q")
	return r
}

func TestConvert(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	t1, t2 := time.Unix(10, 0).UTC(), time.Unix(20, 0).UTC()
	logs := plog.NewLogs()
	rs := addResource(logs, "c1", true)
	entityRec(rs, "service", t1)
	entityRec(rs, "service", t2)
	rel := rs.AppendEmpty().Attributes()
	rel.PutStr(AttrRecord, "relation")
	rel.PutStr(AttrRelationType, "calls")
	rel.PutStr(AttrRelationFrom, "a")
	rel.PutStr(AttrRelationTo, "b")
	rs2 := addResource(logs, "", false) // no collector
	entityRec(rs2, "service", t1)
	rs3 := addResource(logs, "c3", false)
	rs3.AppendEmpty().Attributes().PutStr(AttrRecord, "weird")
	addResource(logs, "c4", false) // empty: skipped
	rs5 := addResource(logs, "c5", false)
	entityRec(rs5, "service", time.Time{}).SetTimestamp(0)

	items, rejs := Convert(logs, now)
	if len(items) != 2 || len(rejs) != 2 {
		t.Fatalf("items=%d rejs=%d", len(items), len(rejs))
	}
	it := items[0]
	if it.Batch.Collector != "otlp/c1" || it.Mode != engine.ModeFull || it.Records != 3 {
		t.Fatalf("bad item %+v", it)
	}
	if !it.Batch.ObservedAt.Equal(t2) {
		t.Fatalf("valid time %v", it.Batch.ObservedAt)
	}
	e := it.Batch.Entities[0]
	if e.Type != "service" || e.Identity["name"] != "web" || e.Attributes["i"] != int64(7) ||
		e.Attributes["d"] != 1.5 || e.Attributes["b"] != true || e.Attributes["s"] != "v" ||
		len(e.Attributes["l"].([]string)) != 2 {
		t.Fatalf("bad entity %+v", e)
	}
	if r := it.Batch.Relations[0]; r.Type != "calls" || r.From != "a" || r.To != "b" {
		t.Fatalf("bad relation %+v", r)
	}
	if items[1].Mode != engine.ModePartial || !items[1].Batch.ObservedAt.Equal(now) {
		t.Fatalf("bad item %+v", items[1])
	}
	if rejs[0].Records != 1 || rejs[0].Reason == "" {
		t.Fatalf("bad rejection %+v", rejs[0])
	}
}

func post(t *testing.T, h http.Handler, ct, enc string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func sampleLogs() plog.Logs {
	logs := plog.NewLogs()
	entityRec(addResource(logs, "good", false), "service", time.Unix(5, 0))
	addResource(logs, "", false).AppendEmpty().Attributes().PutStr(AttrRecord, "entity")
	return logs
}

func TestHandlerProtoJSONGzipAndPartialSuccess(t *testing.T) {
	ms := metrics.New()
	f := &fakeApplier{}
	h := New(Config{Applier: f, Metrics: ms}).Handler()
	req := plogotlp.NewExportRequestFromLogs(sampleLogs())

	pb, _ := req.MarshalProto()
	js, _ := req.MarshalJSON()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(pb)
	_ = zw.Close()

	for name, w := range map[string]*httptest.ResponseRecorder{
		"proto": post(t, h, "application/x-protobuf", "", pb),
		"json":  post(t, h, "application/json", "", js),
		"gzip":  post(t, h, "application/x-protobuf", "gzip", gz.Bytes()),
	} {
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", name, w.Code, w.Body)
		}
		resp := plogotlp.NewExportResponse()
		var err error
		if name == "json" {
			err = resp.UnmarshalJSON(w.Body.Bytes())
		} else {
			err = resp.UnmarshalProto(w.Body.Bytes())
		}
		if err != nil {
			t.Fatal(err)
		}
		if resp.PartialSuccess().RejectedLogRecords() != 1 || resp.PartialSuccess().ErrorMessage() == "" {
			t.Fatalf("%s: partial success %+v", name, resp.PartialSuccess())
		}
	}
	if len(f.got) != 3 || f.got[0].Collector != "otlp/good" {
		t.Fatalf("applied %+v", f.got)
	}
}

func TestHandlerErrors(t *testing.T) {
	logs := plogotlp.NewExportRequestFromLogs(sampleLogs())
	pb, _ := logs.MarshalProto()
	f := &fakeApplier{}

	t.Run("undecodable", func(t *testing.T) {
		if w := post(t, New(Config{Applier: f}).Handler(), "application/json", "", []byte("{")); w.Code != 400 {
			t.Fatal(w.Code)
		}
	})
	t.Run("content type", func(t *testing.T) {
		if w := post(t, New(Config{Applier: f}).Handler(), "text/plain", "", pb); w.Code != 415 {
			t.Fatal(w.Code)
		}
	})
	t.Run("too large", func(t *testing.T) {
		big := make([]byte, MaxBodyBytes+1)
		if w := post(t, New(Config{Applier: f}).Handler(), "application/x-protobuf", "", big); w.Code != 413 {
			t.Fatal(w.Code)
		}
	})
	t.Run("too large after gzip", func(t *testing.T) {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(make([]byte, MaxBodyBytes+1))
		_ = zw.Close()
		if w := post(t, New(Config{Applier: f}).Handler(), "application/x-protobuf", "gzip", gz.Bytes()); w.Code != 413 {
			t.Fatal(w.Code)
		}
	})
	t.Run("auth", func(t *testing.T) {
		h := New(Config{Applier: f, Authorize: func(*http.Request) error { return errors.New("no") }}).Handler()
		if w := post(t, h, "application/x-protobuf", "", pb); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatal(w.Code)
		}
		h = New(Config{Applier: f, Authorize: func(*http.Request) error { return errs.Forbidden }}).Handler()
		if w := post(t, h, "application/x-protobuf", "", pb); w.Code != 403 {
			t.Fatal(w.Code)
		}
	})
	t.Run("not ready", func(t *testing.T) {
		h := New(Config{Applier: f, Ready: func() error { return errs.Unavailable }}).Handler()
		if w := post(t, h, "application/x-protobuf", "", pb); w.Code != 503 {
			t.Fatal(w.Code)
		}
		h = New(Config{Applier: &fakeApplier{err: errs.Unavailable}}).Handler()
		if w := post(t, h, "application/x-protobuf", "", pb); w.Code != 503 {
			t.Fatal(w.Code)
		}
	})
	t.Run("apply validation rejects resource", func(t *testing.T) {
		h := New(Config{Applier: &fakeApplier{err: errs.Validation}}).Handler()
		w := post(t, h, "application/x-protobuf", "", pb)
		resp := plogotlp.NewExportResponse()
		if w.Code != 200 || resp.UnmarshalProto(w.Body.Bytes()) != nil || resp.PartialSuccess().RejectedLogRecords() != 2 {
			t.Fatal(w.Code, w.Body)
		}
	})
	t.Run("method", func(t *testing.T) {
		w := httptest.NewRecorder()
		New(Config{Applier: f}).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/logs", nil))
		if w.Code != 405 {
			t.Fatal(w.Code)
		}
	})
}

func TestServeShutdown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeApplier{}
	s := New(Config{Applier: f})
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	pb, _ := plogotlp.NewExportRequestFromLogs(sampleLogs()).MarshalProto()
	resp, err := http.Post("http://"+l.Addr().String()+"/v1/logs", "application/x-protobuf", bytes.NewReader(pb))
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err, resp)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEngineIntegration(t *testing.T) {
	c, err := engine.Open(t.TempDir(), engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	logs := plog.NewLogs()
	rs := addResource(logs, "it", false)
	r := rs.AppendEmpty()
	r.Attributes().PutStr(AttrRecord, "entity")
	r.Attributes().PutStr(AttrKind, "host")
	r.Attributes().PutStr(PrefixIdentity+"hostname", "web")
	pb, _ := plogotlp.NewExportRequestFromLogs(logs).MarshalProto()
	w := post(t, New(Config{Applier: c}).Handler(), "application/x-protobuf", "", pb)
	resp := plogotlp.NewExportResponse()
	if w.Code != 200 || resp.UnmarshalProto(w.Body.Bytes()) != nil || resp.PartialSuccess().RejectedLogRecords() != 0 {
		t.Fatal(w.Code, w.Body.String(), resp.PartialSuccess().ErrorMessage())
	}
}

func TestConvertRejectsMalformedResources(t *testing.T) {
	cases := map[string]func(rl plog.ResourceLogs){
		"full_observation not bool": func(rl plog.ResourceLogs) {
			rl.Resource().Attributes().PutStr(AttrFullObservation, "true")
		},
		"relation missing to": func(rl plog.ResourceLogs) {
			a := rl.ScopeLogs().At(0).LogRecords().AppendEmpty().Attributes()
			a.PutStr(AttrRecord, "relation")
			a.PutStr(AttrRelationType, "calls")
			a.PutStr(AttrRelationFrom, "a")
		},
		"entity missing kind": func(rl plog.ResourceLogs) {
			rl.ScopeLogs().At(0).LogRecords().AppendEmpty().Attributes().PutStr(AttrRecord, "entity")
		},
		"identity not string": func(rl plog.ResourceLogs) {
			a := rl.ScopeLogs().At(0).LogRecords().AppendEmpty().Attributes()
			a.PutStr(AttrRecord, "entity")
			a.PutStr(AttrKind, "host")
			a.PutInt(PrefixIdentity+"x", 1)
		},
		"unsupported attr type": func(rl plog.ResourceLogs) {
			a := rl.ScopeLogs().At(0).LogRecords().AppendEmpty().Attributes()
			a.PutStr(AttrRecord, "entity")
			a.PutStr(AttrKind, "host")
			a.PutEmptyMap(PrefixAttr + "m")
		},
		"non-string array element": func(rl plog.ResourceLogs) {
			a := rl.ScopeLogs().At(0).LogRecords().AppendEmpty().Attributes()
			a.PutStr(AttrRecord, "entity")
			a.PutStr(AttrKind, "host")
			a.PutEmptySlice(PrefixAttr + "l").AppendEmpty().SetInt(1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			logs := plog.NewLogs()
			entityRec(addResource(logs, "c", false), "service", time.Unix(1, 0))
			mutate(logs.ResourceLogs().At(0))
			items, rejs := Convert(logs, time.Unix(1, 0))
			if len(items) != 0 || len(rejs) != 1 || rejs[0].Reason == "" || rejs[0].Records < 1 {
				t.Fatalf("items=%v rejs=%+v", items, rejs)
			}
		})
	}
}

func TestHandlerEncodingAndFailureGaps(t *testing.T) {
	pb, _ := plogotlp.NewExportRequestFromLogs(sampleLogs()).MarshalProto()
	t.Run("invalid gzip", func(t *testing.T) {
		if w := post(t, New(Config{Applier: &fakeApplier{}}).Handler(), "application/x-protobuf", "gzip", []byte("nope")); w.Code != 400 {
			t.Fatal(w.Code)
		}
	})
	t.Run("unsupported encoding", func(t *testing.T) {
		if w := post(t, New(Config{Applier: &fakeApplier{}}).Handler(), "application/x-protobuf", "br", pb); w.Code != 415 {
			t.Fatal(w.Code)
		}
	})
	t.Run("undecodable protobuf", func(t *testing.T) {
		if w := post(t, New(Config{Applier: &fakeApplier{}}).Handler(), "application/x-protobuf", "", []byte{0xff, 0xff, 0xff}); w.Code != 400 {
			t.Fatal(w.Code)
		}
	})
	t.Run("json with charset and gzip", func(t *testing.T) {
		js, _ := plogotlp.NewExportRequestFromLogs(sampleLogs()).MarshalJSON()
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(js)
		_ = zw.Close()
		f := &fakeApplier{}
		if w := post(t, New(Config{Applier: f}).Handler(), "application/json; charset=utf-8", "gzip", gz.Bytes()); w.Code != 200 || len(f.got) != 1 {
			t.Fatal(w.Code, w.Body)
		}
	})
	t.Run("unexpected apply error is 500", func(t *testing.T) {
		if w := post(t, New(Config{Applier: &fakeApplier{err: errors.New("boom")}}).Handler(), "application/x-protobuf", "", pb); w.Code != 500 {
			t.Fatal(w.Code)
		}
	})
	t.Run("clean export has no partial success", func(t *testing.T) {
		logs := plog.NewLogs()
		entityRec(addResource(logs, "ok", false), "service", time.Unix(5, 0))
		clean, _ := plogotlp.NewExportRequestFromLogs(logs).MarshalProto()
		f := &fakeApplier{}
		w := post(t, New(Config{Applier: f}).Handler(), "application/x-protobuf", "", clean)
		resp := plogotlp.NewExportResponse()
		if w.Code != 200 || resp.UnmarshalProto(w.Body.Bytes()) != nil || resp.PartialSuccess().RejectedLogRecords() != 0 || len(f.got) != 1 {
			t.Fatal(w.Code, w.Body)
		}
	})
}
