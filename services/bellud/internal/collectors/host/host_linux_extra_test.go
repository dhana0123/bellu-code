//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, i os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if i.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		d, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), d, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An unreadable /proc/<pid>/fd leaves the process observed but its sockets unowned.
func TestUnreadableFdSkipped(t *testing.T) {
	root := t.TempDir()
	copyDir(t, "testdata/proc", root)
	fd := filepath.Join(root, "100", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(fd, "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fd, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fd, 0o755) })
	b, err := New(time.Second, WithProcRoot(root), WithHostname("h1")).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	procs := 0
	for _, e := range b.Entities {
		if e.Type == "process" {
			procs++
		}
	}
	if procs != 2 {
		t.Fatalf("processes = %d", procs)
	}
	for _, r := range b.Relations {
		if r.Type == "owned_by" {
			t.Fatalf("unexpected owned_by %+v", r)
		}
	}
}

func TestMissingProcRootErrors(t *testing.T) {
	c := New(time.Second, WithProcRoot(filepath.Join(t.TempDir(), "none")), WithHostname("h"))
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("want error for unreadable proc root")
	}
}

func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(time.Second, WithProcRoot("testdata/proc"), WithHostname("h"))
	if _, err := c.Collect(ctx); err == nil {
		t.Fatal("want context error")
	}
}
