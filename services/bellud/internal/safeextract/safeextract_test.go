package safeextract

import (
	"archive/tar"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name, link string
	typ        byte
	data       string
}

func mk(t *testing.T, es ...ent) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Linkname: e.link, Mode: 0o644}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	return &b
}

func TestValidateTar(t *testing.T) {
	small := Limits{MaxBytes: 100, MaxEntries: 3}
	cases := []struct {
		name string
		es   []ent
		ok   bool
	}{
		{"valid", []ent{{name: "a/b.txt", data: "hi"}, {name: "a/l", link: "b.txt", typ: tar.TypeSymlink}}, true},
		{"dotdot", []ent{{name: "a/../../x", data: "x"}}, false},
		{"absolute", []ent{{name: "/etc/passwd", data: "x"}}, false},
		{"symlink outside", []ent{{name: "a/l", link: "../../etc", typ: tar.TypeSymlink}}, false},
		{"symlink absolute", []ent{{name: "l", link: "/etc", typ: tar.TypeSymlink}}, false},
		{"too many", []ent{{name: "1"}, {name: "2"}, {name: "3"}, {name: "4"}}, false},
		{"too big", []ent{{name: "big", data: strings.Repeat("x", 101)}}, false},
		{"deep", []ent{{name: strings.Repeat("d/", 40) + "f"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var cb error
			err := ValidateTar(mk(t, c.es...), small, func(e error) { cb = e })
			if c.ok != (err == nil) {
				t.Fatalf("err = %v", err)
			}
			if !c.ok && (!errors.Is(err, ErrViolation) || cb == nil) {
				t.Fatalf("want violation and callback, got %v / %v", err, cb)
			}
		})
	}
}

func TestExtractCleansUp(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out")
	buf := mk(t, ent{name: "ok.txt", data: "hi"}, ent{name: "../evil", data: "x"})
	n := 0
	err := ExtractTar(buf, dst, Limits{}, func(error) { n++ })
	if !errors.Is(err, ErrViolation) || n != 1 {
		t.Fatalf("err=%v callbacks=%d", err, n)
	}
	if _, err := os.Stat(filepath.Join(dst, "ok.txt")); !os.IsNotExist(err) {
		t.Fatal("partial output left behind")
	}
}

func TestDirFS(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644)
	os.Symlink(outside, filepath.Join(root, "esc"))

	var cb error
	f, err := DirFS(root, Limits{}, func(e error) { cb = e })
	if err != nil {
		t.Fatal(err)
	}
	if b, err := fs.ReadFile(f, "a.txt"); err != nil || string(b) != "hello" {
		t.Fatalf("read: %q %v", b, err)
	}
	if _, err := f.Open("esc/secret"); !errors.Is(err, ErrViolation) || cb == nil {
		t.Fatalf("symlink escape not rejected: %v", err)
	}
	if _, err := fs.ReadFile(f, "a.txt"); !errors.Is(err, ErrViolation) {
		t.Fatalf("FS should stay stopped: %v", err)
	}
}

func TestDirFSBytes(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "big"), []byte(strings.Repeat("x", 50)), 0o644)
	f, _ := DirFS(root, Limits{MaxBytes: 10}, nil)
	if _, err := fs.ReadFile(f, "big"); !errors.Is(err, ErrViolation) {
		t.Fatalf("err = %v", err)
	}
}
