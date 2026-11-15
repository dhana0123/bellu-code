// Package bundle verifies signed intel release bundles and parses the latest.json
// pointer. It performs no network access and has no side effects.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

// Archive member names. Only these three are accepted.
const (
	DataFileName      = "intel.jsonl"
	ManifestFileName  = "manifest.json"
	SignatureFileName = "manifest.json.sig"
	ManifestVersion   = 1
)

// Limits against hostile archives.
const (
	MaxMembers       = 8
	MaxTotalBytes    = 1 << 30
	MaxMemberBytes   = 512 << 20
	decoderMaxMemory = 256 << 20
)

// ErrVerification wraps every failure that makes a bundle untrusted, including
// archive limit violations.
var ErrVerification = errors.New("bundle: verification failed")

// FileEntry records one data file in the manifest.
type FileEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
}

// Manifest is the signed index of a bundle.
type Manifest struct {
	Version   int         `json:"version"`
	CreatedAt string      `json:"created_at"`
	Files     []FileEntry `json:"files"`
}

// Verified is an authenticated, integrity-checked bundle.
type Verified struct {
	Manifest Manifest
	JSONL    []byte
}

// Vulns parses the verified intel.jsonl.
func (v Verified) Vulns() ([]model.Vuln, error) { return ParseJSONL(v.JSONL) }

// Verify unpacks a .tar.zst bundle and checks it. Order: the ed25519 signature
// over the exact manifest.json bytes, then size and sha256 of every listed
// file, then rejection of unlisted members.
func Verify(r io.Reader, pub ed25519.PublicKey) (Verified, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Verified{}, fmt.Errorf("bundle: invalid ed25519 public key size %d", len(pub))
	}
	members, err := readTarZst(r)
	if err != nil {
		return Verified{}, err
	}
	manifestBytes, ok := members[ManifestFileName]
	if !ok {
		return Verified{}, fmt.Errorf("%w: missing %q", ErrVerification, ManifestFileName)
	}
	sig, ok := members[SignatureFileName]
	if !ok {
		return Verified{}, fmt.Errorf("%w: missing %q", ErrVerification, SignatureFileName)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return Verified{}, fmt.Errorf("%w: signature does not match pinned key", ErrVerification)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Verified{}, fmt.Errorf("%w: decode manifest: %v", ErrVerification, err)
	}
	if manifest.Version != ManifestVersion {
		return Verified{}, fmt.Errorf("%w: unsupported manifest version %d", ErrVerification, manifest.Version)
	}
	listed := map[string]bool{}
	for _, fe := range manifest.Files {
		if fe.Name != DataFileName {
			return Verified{}, fmt.Errorf("%w: manifest lists unexpected file %q", ErrVerification, fe.Name)
		}
		if listed[fe.Name] {
			return Verified{}, fmt.Errorf("%w: manifest lists %q twice", ErrVerification, fe.Name)
		}
		listed[fe.Name] = true
		body, ok := members[fe.Name]
		if !ok {
			return Verified{}, fmt.Errorf("%w: manifest lists %q but the bundle has no such file", ErrVerification, fe.Name)
		}
		if int64(len(body)) != fe.Size {
			return Verified{}, fmt.Errorf("%w: file %q size %d does not match manifest size %d", ErrVerification, fe.Name, len(body), fe.Size)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != fe.Sha256 {
			return Verified{}, fmt.Errorf("%w: file %q sha256 %s does not match manifest %s", ErrVerification, fe.Name, got, fe.Sha256)
		}
	}
	for name := range members {
		if name != ManifestFileName && name != SignatureFileName && !listed[name] {
			return Verified{}, fmt.Errorf("%w: bundle has unlisted file %q", ErrVerification, name)
		}
	}
	return Verified{Manifest: manifest, JSONL: members[DataFileName]}, nil
}

// ParseJSONL decodes one model.Vuln per record. Blank lines are skipped.
func ParseJSONL(data []byte) ([]model.Vuln, error) {
	var out []model.Vuln
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var v model.Vuln
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode jsonl record %d: %w", len(out), err)
		}
		out = append(out, v)
	}
}

// readTarZst reads the archive into memory, enforcing member names, duplicate,
// count, per-member, and total size limits.
func readTarZst(r io.Reader) (map[string][]byte, error) {
	zr, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(decoderMaxMemory), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, fmt.Errorf("%w: new zstd reader: %v", ErrVerification, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	members := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return members, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read archive: %v", ErrVerification, err)
		}
		if len(members) >= MaxMembers {
			return nil, fmt.Errorf("%w: more than %d members", ErrVerification, MaxMembers)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: member %q is not a regular file", ErrVerification, hdr.Name)
		}
		if hdr.Name != DataFileName && hdr.Name != ManifestFileName && hdr.Name != SignatureFileName {
			return nil, fmt.Errorf("%w: unexpected member %q", ErrVerification, hdr.Name)
		}
		if _, dup := members[hdr.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate member %q", ErrVerification, hdr.Name)
		}
		if hdr.Size > MaxMemberBytes {
			return nil, fmt.Errorf("%w: member %q exceeds %d bytes", ErrVerification, hdr.Name, int64(MaxMemberBytes))
		}
		body, err := io.ReadAll(io.LimitReader(tr, MaxMemberBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: read member %q: %v", ErrVerification, hdr.Name, err)
		}
		if len(body) > MaxMemberBytes {
			return nil, fmt.Errorf("%w: member %q exceeds %d bytes", ErrVerification, hdr.Name, int64(MaxMemberBytes))
		}
		total += int64(len(body))
		if total > MaxTotalBytes {
			return nil, fmt.Errorf("%w: archive exceeds %d bytes", ErrVerification, int64(MaxTotalBytes))
		}
		members[hdr.Name] = body
	}
}
