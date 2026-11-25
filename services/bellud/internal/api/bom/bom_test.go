package bom

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDisabledAnswers404(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, nil, true)
	for _, p := range []string{Prefix + "/sbom", Prefix + "/sbom/a/export"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 404 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}
