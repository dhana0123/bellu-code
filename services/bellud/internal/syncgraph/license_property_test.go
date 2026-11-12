package syncgraph

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 3: License preservation.
// **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

var lpAttribution = []string{
	"Copyright 2024 The Upstream Authors",
	"Copyright (c) 2023 Acme Corp. All rights reserved.",
	"Licensed under the Apache License, Version 2.0 (the \"License\");",
	"This software is covered by a patent grant, see PATENTS.",
	"Trademark of Acme: the Acme logo is a registered trademark.",
	"SPDX-License-Identifier: Apache-2.0",
	"Copyright © 2022 Zoë Müller 日本語",
}

var lpPlain = []string{
	"Package x does things.", "helper utilities", "internal notes", "naïve café ✓", "",
}

var lpBodies = []string{
	"", "func A() int { return 1 }\n", "import \"fmt\"\n\nfunc B() { fmt.Println(\"hi\") }\n",
	"const c = \"© text\"\n", "var s = `// not a comment\npackage fake`\n",
}

type lpFile struct {
	name    string
	content string
	attrib  []string // upstream attribution lines that must survive verbatim
}

func lpLicenseBytes() *rapid.Generator[[]byte] {
	return rapid.Custom(func(t *rapid.T) []byte {
		var b bytes.Buffer
		n := rapid.IntRange(0, 8).Draw(t, "lic_parts")
		for i := 0; i < n; i++ {
			switch rapid.IntRange(0, 3).Draw(t, "kind") {
			case 0:
				b.WriteString("Apache License\r\n")
			case 1:
				b.WriteString("Version 2.0 — «non-ASCII» ✓\n")
			case 2:
				b.Write(rapid.SliceOfN(rapid.Byte(), 0, 16).Draw(t, "raw"))
			default:
				b.WriteString(rapid.String().Draw(t, "str") + "\r\n")
			}
		}
		return b.Bytes()
	})
}

func lpGoFile(t *rapid.T, i int) lpFile {
	var sb strings.Builder
	var attrib []string
	tag := rapid.Bool().Draw(t, "tag")
	tagFirst := rapid.Bool().Draw(t, "tag_first")
	if tag && tagFirst {
		sb.WriteString("//go:build linux || darwin\n\n")
	}
	if rapid.Bool().Draw(t, "header") {
		lines := rapid.SliceOfN(rapid.SampledFrom(lpAttribution), 1, 4).Draw(t, "attr")
		attrib = append(attrib, lines...)
		if rapid.Bool().Draw(t, "block") {
			sb.WriteString("/*\n" + strings.Join(lines, "\n") + "\n*/\n\n")
		} else {
			for _, l := range lines {
				sb.WriteString("// " + l + "\n")
			}
			sb.WriteString("\n")
		}
	}
	if tag && !tagFirst {
		sb.WriteString("//go:build linux || darwin\n\n")
	}
	if rapid.Bool().Draw(t, "doc") {
		for _, l := range rapid.SliceOfN(rapid.SampledFrom(lpPlain[:4]), 1, 3).Draw(t, "doc_lines") {
			sb.WriteString("// " + l + "\n")
		}
	}
	sb.WriteString("package pkg\n\n")
	sb.WriteString(rapid.SampledFrom(lpBodies).Draw(t, "body"))
	// an attribution line in the body must also survive
	if rapid.Bool().Draw(t, "body_attr") {
		l := rapid.SampledFrom(lpAttribution).Draw(t, "body_attr_line")
		sb.WriteString("// " + l + "\n")
		attrib = append(attrib, l)
	}
	return lpFile{name: fmt.Sprintf("pkg/f%d.go", i), content: sb.String(), attrib: attrib}
}

// lpMarkerChecks verifies marker count, position and attribution retention.
func lpMarkerChecks(t interface {
	Helper()
	Fatalf(string, ...any)
}, name, out string, attrib []string) {
	t.Helper()
	if c := strings.Count(out, ModifiedMarker); c != 1 {
		t.Fatalf("%s: marker count %d\n%s", name, c, out)
	}
	lines := strings.Split(out, "\n")
	mi, pi, lastHdr := -1, -1, -1
	for i, l := range lines {
		if strings.Contains(l, ModifiedMarker) {
			mi = i
		}
		if pi < 0 && strings.HasPrefix(l, "package ") {
			pi = i
		}
	}
	if mi < 0 || pi < 0 || mi >= pi {
		t.Fatalf("%s: marker (line %d) not before package clause (line %d)\n%s", name, mi, pi, out)
	}
	for i := 0; i < pi; i++ {
		if i != mi && lpAttrLine(lines[i]) {
			lastHdr = i
		}
	}
	// A license header directly adjacent to the package clause precedes the marker;
	// a header separated by a blank line must also precede it.
	if lastHdr > mi {
		// only acceptable when the attribution is inside a package doc comment placed after the marker
		t.Fatalf("%s: marker (line %d) precedes license header line %d\n%s", name, mi, lastHdr, out)
	}
	for _, a := range attrib {
		if !strings.Contains(out, a) {
			t.Fatalf("%s: attribution line altered or lost: %q\n%s", name, a, out)
		}
	}
}

func lpAttrLine(l string) bool { return isAttribution(l) && !strings.Contains(l, ModifiedMarker) }

func TestPropertyLicensePreservation(t *testing.T) {
	mp := filepath.Join("..", "..", "script", "rename.map.yaml")
	rapid.Check(t, func(t *rapid.T) {
		commit := rapid.StringMatching(`[0-9a-f]{40}`).Draw(t, "commit")
		lic := lpLicenseBytes().Draw(t, "license")
		n := rapid.IntRange(1, 5).Draw(t, "n")
		base, err := os.MkdirTemp("", "lp-sync-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(base)
		src := filepath.Join(base, "src")
		files := []lpFile{}
		tree := map[string]string{"LICENSE": string(lic)}
		for i := 0; i < n; i++ {
			f := lpGoFile(t, i)
			files = append(files, f)
			tree[f.name] = f.content
		}
		rpWrite(t, src, tree)
		out := filepath.Join(base, "o", "bellugraph")
		opt := Options{Commit: commit, Out: out, MapPath: mp, SumPath: filepath.Join(base, "sum"), SrcDir: src, Regen: RegenSkip}
		if err := Sync(opt); err != nil {
			t.Fatalf("sync: %v", err)
		}
		first := rpSnap(t, out)
		if err := Sync(opt); err != nil { // second run: identical, marker still once
			t.Fatalf("sync again: %v", err)
		}
		second := rpSnap(t, out)

		for _, snap := range []map[string]string{first, second} {
			got, err := os.ReadFile(filepath.Join(out, "LICENSE"))
			if err != nil || !bytes.Equal(got, lic) {
				t.Fatalf("LICENSE not byte-identical: %v", err)
			}
			if !strings.Contains(snap["NOTICE"], commit) {
				t.Fatalf("NOTICE lacks full SHA %s:\n%s", commit, snap["NOTICE"])
			}
			for _, f := range files {
				o, ok := snap[filepath.FromSlash(f.name)]
				if !ok {
					t.Fatalf("missing output for %s", f.name)
				}
				lpMarkerChecks(t, f.name, o, f.attrib)
				if !strings.Contains(o, "package pkg") {
					t.Fatalf("%s lost package clause", f.name)
				}
				if strings.Contains(f.content, "//go:build") && !strings.Contains(o, "//go:build linux || darwin") {
					t.Fatalf("%s lost build tag", f.name)
				}
			}
		}
		for k, v := range first {
			if second[k] != v {
				t.Fatalf("second run changed %s", k)
			}
		}
	})
}

// The real vendored tree must satisfy the same obligations.
func TestVendoredTreeLicense(t *testing.T) {
	root := filepath.Join("..", "bellugraph")
	up, err := os.ReadFile(filepath.Join(root, "UPSTREAM.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^- Commit: ([0-9a-f]{40})$`).FindSubmatch(up)
	if m == nil {
		t.Fatal("no 40-hex commit in UPSTREAM.md")
	}
	sum := string(m[1])
	notice, err := os.ReadFile(filepath.Join(root, "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(notice), sum) {
		t.Fatalf("NOTICE lacks SHA %s", sum)
	}
	if st, err := os.Stat(filepath.Join(root, "LICENSE")); err != nil || st.Size() == 0 {
		t.Fatalf("LICENSE missing or empty: %v", err)
	}
	count := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() && rel == "facade" { // bellud-owned, not transformed
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		count++
		if c := strings.Count(string(b), ModifiedMarker); c != 1 {
			t.Errorf("%s: marker count %d", rel, c)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("no .go files found in vendored tree")
	}
}
