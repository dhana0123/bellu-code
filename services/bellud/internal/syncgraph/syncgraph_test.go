package syncgraph

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef01234567"
const license = "Apache License\r\nVersion 2.0 (upstream bytes, CRLF kept)\r\n"

var fixture = map[string]string{
	"LICENSE":                license,
	"go.mod":                 "module github.com/toise-dev/toise\n",
	"internal/demo/d.go":     "package demo\n",
	".git/config":            "toise\n",
	"cmd/toised/main.go":     "// Copyright 2025 Toise Authors\n// Licensed under the Apache License, Version 2.0\n\npackage main\r\n\r\nimport \"github.com/toise-dev/toise/internal/store\"\r\n\r\nvar _ = store.X\r\nconst Name = \"Toise engine\"\nconst Env = \"TOISE_ADDR\"\n",
	"internal/store/s.go":    "package store\n\nvar X = \"toise_events\"\n",
	"proto/toise/v1/e.proto": "package toise.v1;\n",
	"README.md":              "# Toise\n",
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for k, v := range files {
		p := filepath.Join(dir, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mapPath(t *testing.T) string {
	t.Helper()
	p, _ := filepath.Abs("../../script/rename.map.yaml")
	return p
}

func opts(t *testing.T, src, out string) Options {
	return Options{Commit: sha, Out: out, MapPath: mapPath(t), SumPath: filepath.Join(t.TempDir(), "sum"), SrcDir: src, Regen: RegenSkip}
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(root, p)
			m[rel] = string(b)
		}
		return nil
	})
	return m
}

func TestSyncTransformsAndIsIdempotent(t *testing.T) {
	src := writeTree(t, fixture)
	out := filepath.Join(t.TempDir(), "bellugraph")
	o := opts(t, src, out)
	if err := Sync(o); err != nil {
		t.Fatal(err)
	}
	first := snapshot(t, out)
	if err := Sync(o); err != nil {
		t.Fatal(err)
	}
	second := snapshot(t, out)
	if len(first) != len(second) {
		t.Fatalf("file lists differ")
	}
	for k, v := range first {
		if second[k] != v {
			t.Fatalf("%s differs between runs", k)
		}
	}
	if first["LICENSE"] != license {
		t.Fatal("LICENSE not byte-identical")
	}
	for _, gone := range []string{"go.mod", "internal/demo/d.go", ".git/config"} {
		if _, ok := first[gone]; ok {
			t.Fatalf("%s should be excluded", gone)
		}
	}
	main := first["cmd/bellugraphd/main.go"]
	if main == "" {
		t.Fatalf("path not renamed: %v", keys(first))
	}
	if strings.Contains(main, "\r") {
		t.Fatal("CRLF not converted")
	}
	if strings.Count(main, ModifiedMarker) != 1 {
		t.Fatal("marker count != 1")
	}
	if !strings.Contains(main, "Copyright 2025 Toise Authors") {
		t.Fatal("upstream notice altered")
	}
	if strings.Index(main, ModifiedMarker) > strings.Index(main, "package main") ||
		strings.Index(main, ModifiedMarker) < strings.Index(main, "Licensed under") {
		t.Fatal("marker not between license header and package")
	}
	if !strings.Contains(main, "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/store") ||
		!strings.Contains(main, "BELLU_GRAPH_ADDR") || !strings.Contains(main, "Bellu Graph Engine engine") {
		t.Fatalf("rename not applied:\n%s", main)
	}
	if !strings.Contains(first["NOTICE"], sha) || !strings.Contains(first["UPSTREAM.md"], sha) {
		t.Fatal("NOTICE/UPSTREAM.md missing sha")
	}
	if off := Scan(out); len(off) != 0 {
		t.Fatalf("leftovers: %v", off)
	}
}

func keys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

func TestMarkModifiedIdempotent(t *testing.T) {
	for _, in := range []string{
		"package a\n",
		"// Package a does x.\npackage a\n",
		"/* Copyright X\n Licensed under Apache */\npackage a\n",
		"//go:build linux\n\npackage a\n",
	} {
		once := MarkModified([]byte(in))
		twice := MarkModified(once)
		if !bytes.Equal(once, twice) || strings.Count(string(once), ModifiedMarker) != 1 {
			t.Fatalf("not idempotent for %q: %q", in, once)
		}
	}
}

func TestInvalidCommitLeavesTreeUntouched(t *testing.T) {
	out := writeTree(t, map[string]string{"keep.txt": "x"})
	for _, c := range []string{"", "ABCDEF0123456789abcdef0123456789abcdef01", "abc", sha + "0"} {
		o := opts(t, writeTree(t, fixture), out)
		o.Commit = c
		if err := Sync(o); err == nil {
			t.Fatalf("want error for %q", c)
		}
	}
	if got := snapshot(t, out); len(got) != 1 || got["keep.txt"] != "x" {
		t.Fatal("tree changed")
	}
}

func TestScanReportsOneLinePerOffenderOutsideAllowList(t *testing.T) {
	root := writeTree(t, map[string]string{
		"NOTICE": "Toise", "UPSTREAM.md": "toise",
		"a/b.go":    "x\n// Copyright Toise\nvar t = \"TOISE\"\n",
		"toise.txt": "ok",
	})
	got := strings.Join(Scan(root), ",")
	if got != "a/b.go:3,toise.txt" && got != "toise.txt,a/b.go:3" {
		t.Fatalf("scan = %s", got)
	}
}

func TestMissingLicenseFailsAndPreservesTree(t *testing.T) {
	files := map[string]string{"a.go": "package a\n"}
	out := writeTree(t, map[string]string{"old.txt": "old"})
	if err := Sync(opts(t, writeTree(t, files), out)); err == nil || !strings.Contains(err.Error(), "LICENSE") {
		t.Fatalf("want LICENSE error, got %v", err)
	}
	if got := snapshot(t, out); len(got) != 1 {
		t.Fatalf("tree changed: %v", keys(got))
	}
	entries, _ := os.ReadDir(filepath.Dir(out))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".bellugraph-staging") {
			t.Fatal("staging not removed")
		}
	}
}

func TestReplaceRemovesDeletedUpstreamAndPreservesFacade(t *testing.T) {
	out := writeTree(t, map[string]string{"removed.txt": "x", "facade/f.go": "package facade\n"})
	if err := Sync(opts(t, writeTree(t, fixture), out)); err != nil {
		t.Fatal(err)
	}
	got := snapshot(t, out)
	if _, ok := got["removed.txt"]; ok {
		t.Fatal("removed file survived")
	}
	if got["facade/f.go"] != "package facade\n" {
		t.Fatal("facade not preserved")
	}
}

func tarball(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header"})
	for k, v := range files {
		tw.WriteHeader(&tar.Header{Name: "toise-" + sha + "/" + k, Mode: 0o644, Size: int64(len(v)), Typeflag: tar.TypeReg})
		tw.Write([]byte(v))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestFetchChecksumAndRecord(t *testing.T) {
	tb := tarball(fixture)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+sha {
			http.NotFound(w, r)
			return
		}
		w.Write(tb)
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "bg")
	o := opts(t, "", out)
	o.BaseURL = srv.URL + "/"

	if err := Sync(o); err == nil || !strings.Contains(err.Error(), "-record") {
		t.Fatalf("want no-recorded-sum error, got %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("tree written despite checksum failure")
	}
	o.Record = true
	if err := Sync(o); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tb)
	rec, _ := os.ReadFile(o.SumPath)
	if string(rec) != sha+" "+hex.EncodeToString(sum[:])+"\n" {
		t.Fatalf("recorded %q", rec)
	}
	o.Record = false
	if err := Sync(o); err != nil {
		t.Fatalf("verified sync: %v", err)
	}
	os.WriteFile(o.SumPath, []byte(sha+" "+strings.Repeat("0", 64)+"\n"), 0o644)
	before := snapshot(t, out)
	if err := Sync(o); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("want mismatch, got %v", err)
	}
	if after := snapshot(t, out); len(after) != len(before) {
		t.Fatal("tree changed")
	}
	o.Commit = strings.Repeat("a", 40)
	if err := Sync(o); err == nil || !strings.Contains(err.Error(), "fetch") {
		t.Fatalf("want fetch error, got %v", err)
	}
}
