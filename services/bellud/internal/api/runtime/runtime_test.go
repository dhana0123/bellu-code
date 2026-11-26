package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

type fake struct{ ingested []string }

func (f *fake) Events(_ context.Context, _ string, before int64, limit int) ([]runtimeevents.Stored, error) {
	var out []runtimeevents.Stored
	for s := int64(5); s > 0 && len(out) < limit; s-- {
		if before <= 0 || s < before {
			out = append(out, runtimeevents.Stored{Seq: s})
		}
	}
	return out, nil
}
func (f *fake) Sensors(context.Context) ([]runtimeevents.Sensor, error) { return nil, nil }
func (f *fake) Rejected() int64                                         { return 3 }
func (f *fake) Ingest(_ context.Context, node string, _ wire.Event) error {
	f.ingested = append(f.ingested, node)
	return nil
}

func do(mux *http.ServeMux, method, url, body string, tlsState *tls.ConnectionState) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	r.TLS = tlsState
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestDisabledAnswers404(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, &fake{}, false)
	if w := do(mux, "GET", Prefix+"/status", "", nil); w.Code != 404 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestStatusEventsPaging(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, &fake{}, true)
	if w := do(mux, "GET", Prefix+"/status", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"rejectedTotal":3`) {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	w := do(mux, "GET", Prefix+"/events?limit=2", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "nextCursor") {
		t.Fatalf("events %d %s", w.Code, w.Body)
	}
	if w := do(mux, "GET", Prefix+"/events?type=bogus", "", nil); w.Code != 400 {
		t.Fatalf("bad type %d", w.Code)
	}
}

func TestIngestRequiresMTLS(t *testing.T) {
	f := &fake{}
	mux := http.NewServeMux()
	Mount(mux, f, true)
	body := `{"type":"process_exec"}`
	if w := do(mux, "POST", Prefix+"/ingest", body, nil); w.Code != 403 || len(f.ingested) != 0 {
		t.Fatalf("plain %d", w.Code)
	}
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "node-1"
	st := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	if w := do(mux, "POST", Prefix+"/ingest", body, st); w.Code != 204 || f.ingested[0] != "node-1" {
		t.Fatalf("mtls %d %v", w.Code, f.ingested)
	}
}
