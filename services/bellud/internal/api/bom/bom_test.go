package bom

import (
	"context"
	"github.com/bellu/bellucode/services/bellud/internal/bom"
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

type fakeDocs struct{}

func (fakeDocs) AI(context.Context) (bom.Document, error) {
	v := "1"
	return bom.Document{Kind: bom.KindAI, SBOM: bom.SBOM{Packages: []bom.Package{{Type: "library", Name: "torch", Version: &v}}}}, nil
}
func (fakeDocs) Cloud(context.Context) (bom.Document, error) {
	return bom.Document{Kind: bom.KindCloud}, nil
}

func TestDocsRoutes(t *testing.T) {
	mux := http.NewServeMux()
	MountDocs(mux, fakeDocs{}, true, false)
	for path, want := range map[string]int{
		Prefix + "/ai": 200, Prefix + "/ai/export": 200, Prefix + "/ai/export?format=bogus": 400,
		Prefix + "/cloud": 404, Prefix + "/cloud/export": 404,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: got %d want %d: %s", path, rec.Code, want, rec.Body)
		}
	}
}
