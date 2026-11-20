package cveupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const maxManifestBytes = 1 << 20

// ImportPack installs the snapshot or delta pack at file with no network
// access. sigFile is the detached signature; when empty it is file+".sig".
// The pack is verified against the pinned keys before its manifest is read,
// then installed through the same staging, verification, apply, integrity
// check and atomic swap as a download. The user's file is never modified or
// deleted. On failure the installed snapshot is unchanged and one audit row
// is appended.
func (u *Updater) ImportPack(ctx context.Context, file, sigFile string) (Result, error) {
	if u.Dir == "" || u.Verifier == nil {
		return Result{}, errors.New("cveupdate: Dir and Verifier are required")
	}
	if sigFile == "" {
		sigFile = file + pkgSigSuffix
	}
	name := "import " + filepath.Base(file)
	data, sig, err := readImport(file, sigFile)
	var m packManifest
	if err == nil {
		err = u.Verifier.VerifyPack(name, data, SHA256Hex(data), int64(len(data)), sig)
	}
	if err == nil {
		m, err = readManifest(data)
	}
	if err != nil {
		err = stepErr(StepVerify, err)
		return Result{Source: SourceImport}, u.auditFailure(ctx, err)
	}

	idx := &Index{Latest: Snapshot{ID: m.SnapshotID, CreatedAt: m.CreatedAt}}
	var check func(Plan) error
	if m.Kind == "delta" {
		idx.Latest.ID = m.Target
		d := Delta{Base: m.Base, Target: m.Target, SHA256: SHA256Hex(data), Size: int64(len(data))}
		idx.Deltas = []Delta{d}
		check = func(p Plan) error {
			if p.Full {
				return fmt.Errorf("delta %s->%s does not apply: installed snapshot is not %s", m.Base, m.Target, m.Base)
			}
			return nil
		}
	} else {
		idx.Latest.SHA256, idx.Latest.Size = SHA256Hex(data), int64(len(data))
	}
	fetch := func(_ context.Context, staging string, i int, _ packRef) (string, []byte, error) {
		path := filepath.Join(staging, "pack-"+strconv.Itoa(i)+".tar.gz")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", nil, err
		}
		return path, sig, nil
	}
	return u.install(ctx, idx, fetch, SourceImport, check)
}

type packManifest struct {
	Kind       string    `json:"kind"`
	SnapshotID string    `json:"snapshot_id"`
	Base       string    `json:"base_snapshot_id"`
	Target     string    `json:"target_snapshot_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func readImport(file, sigFile string) (data, sig []byte, err error) {
	if data, err = os.ReadFile(file); err != nil {
		return nil, nil, err
	}
	if sig, err = os.ReadFile(sigFile); err != nil {
		return nil, nil, fmt.Errorf("reading signature (use --sig): %w", err)
	}
	if len(sig) > maxSigBytes {
		return nil, nil, errors.New("signature file too large")
	}
	return data, sig, nil
}

// readManifest reads manifest.json from a verified pack.
func readManifest(data []byte) (m packManifest, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return m, fmt.Errorf("pack is not a gzip archive: %w", err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return m, errors.New("pack has no manifest.json")
		}
		if err != nil {
			return m, err
		}
		if filepath.Clean(h.Name) != "manifest.json" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes))
		if err != nil {
			return m, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return m, fmt.Errorf("manifest.json: %w", err)
		}
		if m.Kind == "delta" && (m.Base == "" || m.Target == "") || m.Kind != "delta" && m.SnapshotID == "" {
			return m, errors.New("manifest.json lacks a snapshot id")
		}
		return m, nil
	}
}

// auditFailure appends the failure row for an import rejected before the
// shared install ran, and returns err (joined with any audit failure).
func (u *Updater) auditFailure(ctx context.Context, err error) error {
	if u.Audit == nil {
		return err
	}
	e := AuditEntry{At: u.now(), Action: "cve-update", Outcome: "failure", Source: SourceImport, Step: StepVerify, Cause: err.Error()}
	if aerr := u.Audit.AppendCVEUpdate(context.WithoutCancel(ctx), e); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit row not written: %w", aerr))
	}
	return err
}
