package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

type member struct {
	name string
	body []byte
}

// ExportJSONL serializes vulns as JSON Lines sorted by ID.
func ExportJSONL(vulns []model.Vuln) ([]byte, error) {
	sorted := append([]model.Vuln(nil), vulns...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var out []byte
	for _, v := range sorted {
		line, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out = append(append(out, line...), '\n')
	}
	return out, nil
}

// Build makes a signed .tar.zst bundle.
func Build(vulns []model.Vuln, priv ed25519.PrivateKey, createdAt time.Time) ([]byte, error) {
	data, err := ExportJSONL(vulns)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	manifest, err := json.MarshalIndent(Manifest{
		Version:   ManifestVersion,
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
		Files:     []FileEntry{{Name: DataFileName, Size: int64(len(data)), Sha256: hex.EncodeToString(sum[:])}},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return writeTarZst([]member{
		{DataFileName, data},
		{ManifestFileName, manifest},
		{SignatureFileName, ed25519.Sign(priv, manifest)},
	})
}

// writeTarZst packs arbitrary members, so tests can build malformed bundles.
func writeTarZst(members []member) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), ModTime: time.Unix(0, 0)}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(m.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalPointer encodes a pointer for tests.
func MarshalPointer(p Pointer) ([]byte, error) { return json.Marshal(p) }

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
