// Package syncgraph vendors a pinned upstream Toise commit into
// internal/bellugraph, applying the ordered rename map.
//
// Design choices (see also cmd/sync-bellu-graph):
//   - Upstream's engine lives under internal/, so after the module-path rename
//     it sits at internal/bellugraph/internal/<pkg>. Go's internal rule makes
//     those importable only from inside internal/bellugraph/..., so the bellud
//     facade lives at internal/bellugraph/facade. The nested internal/ segment
//     is kept (no path rule strips it), which keeps rename rules simple and the
//     output a faithful mirror of upstream. The facade directory is bellud-owned
//     and carried over untouched by every sync (see PreservedDirs).
//   - Upstream go.mod/go.sum/go.work are not vendored: the tree must be part of
//     the bellud module. Dependencies are merged into bellud's go.mod by hand.
//   - Upstream commits generated proto/GraphQL code; the rename map rewrites it
//     in place. Regeneration is an optional, configurable step (RegenMode).
package syncgraph

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/rename"
)

const (
	// ToolVersion is bumped whenever output could change for the same inputs.
	ToolVersion  = "1"
	UpstreamRepo = "https://github.com/toise-dev/toise"
	License      = "Apache-2.0"
	DefaultBase  = "https://codeload.github.com/toise-dev/toise/tar.gz/"

	// ModifiedMarker is inserted exactly once into each transformed .go file.
	ModifiedMarker = "// Modified by the Bellu project from upstream Toise (see NOTICE and UPSTREAM.md)."

	maxFileSize = 64 << 20
)

// PreservedDirs are bellud-owned top-level directories of the vendored tree
// that are carried over from the old tree into every new one.
var PreservedDirs = []string{"facade"}

// Regeneration modes.
const (
	RegenAuto     = "auto"     // run buf/gqlgen when config and binary exist; skip otherwise
	RegenSkip     = "skip"     // never regenerate
	RegenRequired = "required" // fail if a generator is missing or fails
)

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ValidateCommit enforces exactly 40 lowercase hex characters.
func ValidateCommit(c string) error {
	if !commitRe.MatchString(c) {
		return fmt.Errorf("invalid commit argument %q: want exactly 40 lowercase hexadecimal characters", c)
	}
	return nil
}

// Options configure a Sync run.
type Options struct {
	Commit      string
	Out         string // vendored tree, e.g. internal/bellugraph
	MapPath     string
	SumPath     string // checksum file ("<sha> <sha256-of-tarball>" per line)
	Record      bool   // trust-on-first-use: record the tarball sum if absent
	SrcDir      string // local tree instead of fetching (no checksum)
	BaseURL     string // tarball URL prefix; defaults to DefaultBase
	Regen       string
	KeepStaging bool
	Stderr      io.Writer
}

// StepError identifies the failed step.
type StepError struct {
	Step string
	Err  error
}

func (e *StepError) Error() string { return fmt.Sprintf("step %q failed: %v", e.Step, e.Err) }
func (e *StepError) Unwrap() error { return e.Err }

func step(name string, err error) error {
	if err == nil {
		return nil
	}
	return &StepError{Step: name, Err: err}
}

type entry struct {
	data []byte
	mode fs.FileMode
}

// Sync runs the full pipeline. On any error the staging dir is removed (unless
// KeepStaging) and Out is left untouched.
func Sync(o Options) (err error) {
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.Regen == "" {
		o.Regen = RegenAuto
	}
	if err := step("validate-commit", ValidateCommit(o.Commit)); err != nil {
		return err
	}
	m, e := rename.LoadFile(o.MapPath) // validates rules before any tree access
	if err := step("load-rename-map", e); err != nil {
		return err
	}

	var files map[string]entry
	var tarSum string
	if o.SrcDir != "" {
		files, e = readDir(o.SrcDir)
		if err := step("read-source", e); err != nil {
			return err
		}
	} else {
		var tb []byte
		tb, e = fetch(o.BaseURL, o.Commit)
		if err := step("fetch", e); err != nil {
			return err
		}
		sum := sha256.Sum256(tb)
		tarSum = hex.EncodeToString(sum[:])
		if err := step("checksum", verifySum(o, tarSum)); err != nil {
			return err
		}
		files, e = readTar(tb)
		if err := step("extract", e); err != nil {
			return err
		}
	}

	parent := filepath.Dir(o.Out)
	if e = os.MkdirAll(parent, 0o755); e != nil {
		return step("stage", e)
	}
	staging, e := os.MkdirTemp(parent, ".bellugraph-staging-*")
	if e != nil {
		return step("stage", e)
	}
	defer func() {
		if err != nil && !o.KeepStaging {
			os.RemoveAll(staging)
		}
	}()

	if err := step("transform", transform(m, files, staging, o.Commit)); err != nil {
		return err
	}
	if err := step("regenerate", regenerate(staging, o.Regen, o.Stderr)); err != nil {
		return err
	}
	// Regenerated files lose the marker; reapply it (idempotent).
	if err := step("remark", remark(staging)); err != nil {
		return err
	}
	if offenders := Scan(staging); len(offenders) > 0 {
		for _, l := range offenders {
			fmt.Fprintln(o.Stderr, l)
		}
		return step("leftover-scan", fmt.Errorf("%d occurrence(s) of upstream name outside allow-list", len(offenders)))
	}
	if err := step("preserve", preserve(o.Out, staging)); err != nil {
		return err
	}
	if err := step("replace", atomicReplace(o.Out, staging)); err != nil {
		return err
	}
	if o.Record && o.SrcDir == "" {
		if err := step("record-checksum", recordSum(o.SumPath, o.Commit, tarSum)); err != nil {
			return err
		}
	}
	return nil
}

func fetch(base, commit string) ([]byte, error) {
	if base == "" {
		base = DefaultBase
	}
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(base + commit)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s%s: HTTP %d (commit may not exist upstream)", base, commit, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<30))
}

func readSums(p string) (map[string]string, error) {
	out := map[string]string{}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			out[f[0]] = f[1]
		}
	}
	return out, nil
}

func verifySum(o Options, got string) error {
	sums, err := readSums(o.SumPath)
	if err != nil {
		return err
	}
	want, ok := sums[o.Commit]
	switch {
	case ok && want != got:
		return fmt.Errorf("checksum mismatch for %s: recorded %s, fetched %s", o.Commit, want, got)
	case !ok && !o.Record:
		return fmt.Errorf("no recorded checksum for %s in %s (first sync: re-run with -record to trust on first use)", o.Commit, o.SumPath)
	}
	return nil
}

func recordSum(p, commit, sum string) error {
	sums, err := readSums(p)
	if err != nil {
		return err
	}
	if _, ok := sums[commit]; ok {
		return nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", commit, sum)
	return err
}

func readTar(tb []byte) (map[string]entry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string]entry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue // dirs, symlinks, pax global headers
		}
		i := strings.IndexByte(h.Name, '/')
		if i < 0 {
			continue
		}
		rel := path.Clean(h.Name[i+1:])
		if !fs.ValidPath(rel) || rel == "." {
			return nil, fmt.Errorf("unsafe path in tarball: %q", h.Name)
		}
		if h.Size > maxFileSize {
			return nil, fmt.Errorf("file too large: %q", h.Name)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[rel] = entry{b, fs.FileMode(h.Mode) & 0o111}
	}
	return files, nil
}

func readDir(dir string) (map[string]entry, error) {
	files := map[string]entry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = entry{b, info.Mode() & 0o111}
		return nil
	})
	return files, err
}

func excluded(rel string) bool {
	if strings.HasPrefix(rel, "internal/demo/") || strings.HasPrefix(rel, "cmd/toise-demo/") {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".git" {
			return true
		}
	}
	if strings.HasPrefix(rel, "scratch/") { // upstream experiments, not part of the engine
		return true
	}
	switch path.Base(rel) {
	case "go.mod", "go.sum", "go.work", "go.work.sum": // tree joins the bellud module, nested modules too
		return true
	}
	return false
}

// attributionRe marks upstream copyright/license/patent/trademark lines. Such
// lines are kept verbatim (Apache-2.0 4(c)) and are part of the scan Allow_List.
var attributionRe = regexp.MustCompile(`(?i)copyright|licensed under|spdx-license|trademark|patent|modified by the bellu project`)

func isAttribution(line string) bool { return attributionRe.MatchString(line) }

// renameContent applies the map line by line, leaving attribution lines intact.
func renameContent(m *rename.Map, rel string, b []byte) []byte {
	if bytes.IndexByte(b, 0) >= 0 {
		return b
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if isAttribution(l) {
			continue
		}
		lines[i] = string(m.ApplyText(rel, []byte(l)))
	}
	return []byte(strings.Join(lines, "\n"))
}

// MarkModified inserts the modification notice exactly once, after the upstream
// license header and before the package clause. Idempotent.
func MarkModified(src []byte) []byte {
	s := string(src)
	if strings.Contains(s, ModifiedMarker) {
		return src
	}
	lines := strings.Split(s, "\n")
	p := -1
	inBlock := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if inBlock {
			if strings.Contains(t, "*/") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(t, "/*") && !strings.Contains(t[2:], "*/") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(l, "package ") {
			p = i
			break
		}
	}
	if p < 0 {
		return src
	}
	// Comment block directly adjacent to the package clause.
	q := p
	for q > 0 && (strings.HasPrefix(lines[q-1], "//") && !strings.HasPrefix(lines[q-1], "//go:") ||
		strings.HasSuffix(strings.TrimSpace(lines[q-1]), "*/")) {
		if strings.HasSuffix(strings.TrimSpace(lines[q-1]), "*/") { // walk back over a /* */ block
			j := q - 1
			for j >= 0 && !strings.Contains(lines[j], "/*") {
				j--
			}
			if j < 0 {
				break
			}
			q = j
			continue
		}
		q--
	}
	var out []string
	switch {
	case q == p: // no adjacent comment
		out = append(out, lines[:p]...)
		out = append(out, ModifiedMarker, "")
		out = append(out, lines[p:]...)
	default:
		block := strings.Join(lines[q:p], "\n")
		if isAttribution(block) { // license header: marker goes after it
			out = append(out, lines[:p]...)
			out = append(out, "", ModifiedMarker, "")
			out = append(out, lines[p:]...)
		} else { // package doc: marker goes before it
			out = append(out, lines[:q]...)
			out = append(out, ModifiedMarker, "")
			out = append(out, lines[q:]...)
		}
	}
	return []byte(strings.Join(out, "\n"))
}

func transform(m *rename.Map, files map[string]entry, staging, commit string) error {
	rels := make([]string, 0, len(files))
	for r := range files {
		rels = append(rels, r)
	}
	sort.Strings(rels) // bytewise
	lic, ok := files["LICENSE"]
	if !ok {
		return errors.New("upstream LICENSE is missing")
	}
	written := map[string]string{}
	for _, rel := range rels {
		if excluded(rel) || rel == "LICENSE" || rel == "NOTICE" {
			continue
		}
		e := files[rel]
		b := e.data
		if bytes.IndexByte(b, 0) < 0 {
			b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
			b = renameContent(m, rel, b)
			if strings.HasSuffix(rel, ".go") {
				b = MarkModified(b)
			}
		}
		dst := m.ApplyPath(rel)
		if prev, dup := written[dst]; dup {
			return fmt.Errorf("path collision: %q and %q both map to %q", prev, rel, dst)
		}
		written[dst] = rel
		if err := writeFile(staging, dst, b, 0o644|e.mode); err != nil {
			return err
		}
	}
	if err := writeFile(staging, "LICENSE", lic.data, 0o644); err != nil { // byte-for-byte
		return err
	}
	notice := "Bellu Graph Engine\n\n" +
		"This directory contains software derived from Toise (" + UpstreamRepo + "),\n" +
		"synced at commit " + commit + ",\n" +
		"licensed under the Apache License, Version 2.0 (see LICENSE).\n" +
		"Files were renamed and modified by the Bellu project.\n"
	if up, ok := files["NOTICE"]; ok {
		notice += "\n--- Upstream NOTICE (retained verbatim) ---\n" + string(up.data)
		if !bytes.HasSuffix(up.data, []byte("\n")) {
			notice += "\n"
		}
	}
	if err := writeFile(staging, "NOTICE", []byte(notice), 0o644); err != nil {
		return err
	}
	upstream := "# Upstream\n\n" +
		"- Repository: " + UpstreamRepo + "\n" +
		"- Commit: " + commit + "\n" +
		"- License: " + License + "\n" +
		"- Sync tool version: " + ToolVersion + "\n"
	return writeFile(staging, "UPSTREAM.md", []byte(upstream), 0o644)
}

func writeFile(root, rel string, b []byte, mode fs.FileMode) error {
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, mode)
}

func remark(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if nb := MarkModified(b); !bytes.Equal(nb, b) {
			return os.WriteFile(p, nb, 0o644)
		}
		return nil
	})
}
func regenerate(staging, mode string, log io.Writer) error {
	switch mode {
	case RegenSkip:
		return nil
	case RegenAuto, RegenRequired:
	default:
		return fmt.Errorf("unknown regen mode %q", mode)
	}
	gens := []struct {
		cfg, bin string
		args     []string
	}{
		{"buf.gen.yaml", "buf", []string{"generate"}},
		{"gqlgen.yml", "gqlgen", []string{"generate"}},
	}
	for _, g := range gens {
		if _, err := os.Stat(filepath.Join(staging, g.cfg)); err != nil {
			if mode == RegenRequired {
				return fmt.Errorf("%s not found in vendored tree", g.cfg)
			}
			continue
		}
		bin, err := exec.LookPath(g.bin)
		if err != nil {
			if mode == RegenRequired {
				return fmt.Errorf("%s not installed", g.bin)
			}
			fmt.Fprintf(log, "note: %s not installed; keeping renamed generated code\n", g.bin)
			continue
		}
		cmd := exec.Command(bin, g.args...)
		cmd.Dir = staging
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", g.bin, err)
		}
	}
	return nil
}

// Scan reports each case-insensitive "toise" in paths and text content outside
// the Allow_List (NOTICE, UPSTREAM.md, attribution lines). One line per hit:
// "path" for a path match, "path:line" for a content match.
func Scan(root string) []string {
	var out []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "NOTICE" || rel == "UPSTREAM.md" {
			return nil
		}
		if strings.Contains(strings.ToLower(rel), "toise") {
			out = append(out, rel)
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(b, 0) >= 0 {
			return nil
		}
		for i, l := range strings.Split(string(b), "\n") {
			if strings.Contains(strings.ToLower(l), "toise") && !isAttribution(l) {
				out = append(out, fmt.Sprintf("%s:%d", rel, i+1))
			}
		}
		return nil
	})
	return out
}

func preserve(old, staging string) error {
	for _, d := range PreservedDirs {
		src := filepath.Join(old, d)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyTree(src, filepath.Join(staging, d)); err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, info.Mode().Perm())
	})
}

// atomicReplace swaps staging into out with renames, rolling back on failure.
func atomicReplace(out, staging string) error {
	_, err := os.Stat(out)
	if errors.Is(err, fs.ErrNotExist) {
		return os.Rename(staging, out)
	}
	if err != nil {
		return err
	}
	old := staging + ".old"
	if err := os.Rename(out, old); err != nil {
		return err
	}
	if err := os.Rename(staging, out); err != nil {
		os.Rename(old, out)
		return err
	}
	return os.RemoveAll(old)
}
