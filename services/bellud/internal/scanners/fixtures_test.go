package scanners

import (
	"archive/tar"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixtureReposExist(t *testing.T) {
	for dir, marker := range map[string]string{
		"go": "go.mod", "npm": "package-lock.json", "python": "requirements.txt",
		"java": "pom.xml", "rust": "Cargo.lock", "ruby": "Gemfile.lock",
		"php": "composer.lock", "dotnet": "packages.lock.json",
		"apk": "lib/apk/db/installed", "deb": "var/lib/dpkg/status", "rpm": "README.md",
	} {
		if _, err := os.Stat(filepath.Join("testdata", "repos", dir, marker)); err != nil {
			t.Errorf("fixture %s: %v", dir, err)
		}
	}
	for _, f := range []string{"npm/package-lock.json", "php/composer.lock", "dotnet/packages.lock.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", "repos", f))
		if err != nil || !json.Valid(b) {
			t.Errorf("%s is not valid JSON (%v)", f, err)
		}
	}
}

func TestSampleTarIsOCILayout(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "images", "sample.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name], _ = io.ReadAll(tr)
	}
	if _, ok := files["oci-layout"]; !ok {
		t.Fatal("missing oci-layout")
	}
	var index struct {
		Manifests []struct{ Digest string } `json:"manifests"`
	}
	if err := json.Unmarshal(files["index.json"], &index); err != nil || len(index.Manifests) == 0 {
		t.Fatalf("bad index.json: %v", err)
	}
	var m struct {
		Layers []struct{ Digest string } `json:"layers"`
	}
	blob := files["blobs/"+strings.Replace(index.Manifests[0].Digest, ":", "/", 1)]
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Layers) < 2 {
		t.Fatalf("layers = %d, want >= 2", len(m.Layers))
	}
	for _, l := range m.Layers {
		if _, ok := files["blobs/"+strings.Replace(l.Digest, ":", "/", 1)]; !ok {
			t.Errorf("missing layer blob %s", l.Digest)
		}
	}
}
