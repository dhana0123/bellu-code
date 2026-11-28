package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Name is the adapter name.
const Name = "gitleaks"

// pinnedVersion is the Gitleaks version in go.mod.
const pinnedVersion = "v8.30.1"

// Adapter implements scanners.Adapter for working-tree secret scans.
type Adapter struct {
	opts Options
	now  func() time.Time
	// historyCommits is the commits per ref scanned in git history. Zero
	// scans the working tree only.
	historyCommits int
}

var _ scanners.Adapter = Adapter{}

// NewAdapter returns the adapter. The engine is built per Run, so a bad custom
// config fails the job before any file is read.
func NewAdapter(o Options) Adapter { return Adapter{opts: o, now: time.Now} }

// WithHistory returns the adapter that also scans up to n commits per ref of
// git history (secrets.history_commits). A path that is not a git repository
// reports a scanner error for the history part only.
func (a Adapter) WithHistory(n int) Adapter { a.historyCommits = n; return a }

func (Adapter) Kind() scanners.Kind { return scanners.KindSecret }

func (Adapter) Info() scanners.Info {
	return scanners.Info{Name: Name, Version: pinnedVersion, License: "MIT",
		Libraries: map[string]string{"gitleaks": pinnedVersion}}
}

func (Adapter) Applies(t scanners.TargetType) bool { return t == scanners.TargetRepository }

// Digest hashes the relative path, size and mtime of every scannable file.
func (Adapter) Digest(ctx context.Context, t scanners.Target) (string, error) {
	h := sha256.New()
	err := Walk(ctx, t.Path, DefaultSkipDirs, func(p string, b []byte) {
		rel, _ := filepath.Rel(t.Path, p)
		h.Write([]byte(rel + "\x00" + strconv.Itoa(len(b)) + "\x00"))
		h.Write(b)
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Run scans the working tree and reports one Finding per detection.
func (a Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	name := t.ID
	if name == "" {
		name = t.Path
	}
	fail := func(cause error) error {
		if rerr := out.ScannerError(name, cause.Error()); rerr != nil {
			return errors.Join(cause, rerr)
		}
		return cause
	}
	if t.Path == "" {
		return fail(fmt.Errorf("secretscan: asset %q: no path to scan: %w", name, scanners.ErrTargetUnreachable))
	}
	eng, err := New(a.opts)
	if err != nil {
		return fail(err)
	}
	now := a.now().UTC()
	var fs []findings.Finding
	err = Walk(ctx, t.Path, DefaultSkipDirs, func(p string, b []byte) {
		rel, rerr := filepath.Rel(t.Path, p)
		if rerr != nil {
			rel = p
		}
		for _, h := range eng.ScanContent(ctx, rel, b) {
			fs = append(fs, finding(t.ID, h, now))
		}
	})
	if err != nil {
		return fail(fmt.Errorf("secretscan: asset %q: %w", name, err))
	}
	if err := out.Findings(fs); err != nil {
		return err
	}
	if a.historyCommits > 0 {
		h := Targets{Eng: eng, Asset: t.ID, Out: out, Now: a.now}
		if err := h.ScanHistory(ctx, t.Path, a.historyCommits); err != nil {
			return fail(err)
		}
	}
	return nil
}

func finding(asset string, h Hit, now time.Time) findings.Finding {
	sev, unmapped := findings.MapSeverity("gitleaks", h.RuleID)
	details, _ := json.Marshal(map[string]any{
		"file": h.File, "line": h.Line, "commit": h.Commit,
		"fingerprint": h.Fingerprint, "prefix": h.Prefix,
	})
	return findings.Finding{
		ID:       findings.ID(h.RuleID, asset, h.File+":"+strconv.Itoa(h.Line)+":"+h.Fingerprint),
		RuleID:   h.RuleID,
		Title:    "Secret detected: " + h.RuleID,
		Category: schema.OvSecrets,
		Type:     findings.TypeSecret,
		Severity: sev, UnmappedSeverity: unmapped,
		Status:    findings.StatusOpen,
		AssetID:   asset,
		Evidence:  []findings.EvidenceRef{{Kind: "file", Ref: h.File, Line: h.Line, Excerpt: h.Excerpt}},
		FirstSeen: now, LastSeen: now,
		Source:  Name,
		Details: details,
	}
}
