//go:build ignore

// gen builds a deterministic two-layer OCI image layout tarball (sample.tar).
// Run from this directory: go run gen.go
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

var epoch = time.Unix(0, 0)

type file struct{ name, body string }

func writeTar(files []file) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range files {
		must(tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: epoch, Format: tar.FormatPAX}))
		_, err := tw.Write([]byte(f.body))
		must(err)
	}
	must(tw.Close())
	return b.Bytes()
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func jsonb(v any) []byte { b, err := json.Marshal(v); must(err); return b }

func main() {
	layer1 := writeTar([]file{
		{"etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.13.5\n"},
		{"lib/apk/db/installed", "C:Q1fixtureopenssl0000000000000=\nP:libcrypto1.1\nV:1.1.1k-r0\nA:x86_64\nT:SSL shared libraries\nL:OpenSSL\no:openssl\n\n"},
	})
	layer2 := writeTar([]file{
		{"app/package.json", "{\"name\":\"fixture-image\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"4.17.20\"}}\n"},
		{"app/package-lock.json", "{\"name\":\"fixture-image\",\"version\":\"1.0.0\",\"lockfileVersion\":2,\"requires\":true,\"packages\":{\"\":{\"name\":\"fixture-image\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"4.17.20\"}},\"node_modules/lodash\":{\"version\":\"4.17.20\"}},\"dependencies\":{\"lodash\":{\"version\":\"4.17.20\"}}}\n"},
	})
	config := jsonb(map[string]any{
		"architecture": "amd64", "os": "linux", "created": "1970-01-01T00:00:00Z",
		"config": map[string]any{},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + digest(layer1), "sha256:" + digest(layer2)}},
	})
	desc := func(mt string, b []byte) map[string]any {
		return map[string]any{"mediaType": mt, "digest": "sha256:" + digest(b), "size": len(b)}
	}
	manifest := jsonb(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": desc("application/vnd.oci.image.config.v1+json", config),
		"layers": []any{
			desc("application/vnd.oci.image.layer.v1.tar", layer1),
			desc("application/vnd.oci.image.layer.v1.tar", layer2),
		},
	})
	index := jsonb(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{desc("application/vnd.oci.image.manifest.v1+json", manifest)},
	})
	out := writeTar([]file{
		{"oci-layout", `{"imageLayoutVersion":"1.0.0"}`},
		{"index.json", string(index)},
		{"blobs/sha256/" + digest(manifest), string(manifest)},
		{"blobs/sha256/" + digest(config), string(config)},
		{"blobs/sha256/" + digest(layer1), string(layer1)},
		{"blobs/sha256/" + digest(layer2), string(layer2)},
	})
	must(os.WriteFile("sample.tar", out, 0o644))
	fmt.Println("wrote sample.tar", len(out), "bytes")
}
