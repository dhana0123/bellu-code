package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

func envOf(flags string) (func(string) string, func(string) (string, bool)) {
	get := func(k string) string {
		if k == "BELLUCODE_FLAGS" {
			return flags
		}
		return ""
	}
	return get, func(k string) (string, bool) { v := get(k); return v, v != "" }
}

func TestFindingsFlagOffStartsNothing(t *testing.T) {
	dir := t.TempDir()
	get, lookup := envOf("-security_findings")
	w := openFindings(nopLog{}, get, lookup, dir, nil)
	if w != nil {
		t.Fatal("wiring must be nil with the flag off")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("data dir touched while flag off: %v", entries)
	}
	if len(w.collectorOptions()) != 0 {
		t.Fatal("nil wiring must add no collector option")
	}
	w.project(nil)
	w.stop()
	w.release() // must not panic
}

func TestFindingsFlagOnStartsStoreAndQueue(t *testing.T) {
	dir, repo := t.TempDir(), t.TempDir()
	get, lookup := envOf("security_findings")
	w := openFindings(nopLog{}, get, lookup, dir, []string{repo})
	if w == nil {
		t.Fatal("wiring must start with the flag on")
	}
	if len(w.collectorOptions()) != 1 {
		t.Fatal("want the auto-scan batch hook")
	}
	if _, err := os.Stat(filepath.Join(dir, "workspaces")); err != nil {
		t.Fatalf("workspace database not created: %v", err)
	}
	id, err := identity.Hash("repository", map[string]string{"path": repo})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := w.mgr.Get(ctx, "none"); err != scanners.ErrJobNotFound {
		t.Fatalf("queue not serving: %v", err)
	}
	// With no adapters, enqueue is rejected as not applicable, not failed.
	if _, err := w.mgr.Enqueue(ctx, scanners.KindSecret, scanners.Target{Type: scanners.TargetRepository, ID: string(id)}); err == nil {
		t.Fatal("enqueue without adapters must be rejected")
	}
	if _, _, err := w.store.Get(ctx, "missing"); err == nil {
		t.Fatal("store must answer lookups")
	}
	done := make(chan struct{})
	go func() { w.stop(); w.release(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestResolveTarget(t *testing.T) {
	repo := t.TempDir()
	res := resolveTarget([]string{repo})
	id, _ := identity.Hash("repository", map[string]string{"path": repo})
	got, ok, err := res(context.Background(), scanners.TargetRepository, string(id))
	if err != nil || !ok || got.Path != repo {
		t.Fatalf("repository: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := res(context.Background(), scanners.TargetRepository, "other"); ok {
		t.Fatal("unknown repository must not resolve")
	}
	name, _ := os.Hostname()
	hid, _ := identity.Hash("host", map[string]string{"hostname": name})
	if _, ok, _ := res(context.Background(), scanners.TargetHost, string(hid)); !ok {
		t.Fatal("this host must resolve")
	}
	if _, ok, _ := res(context.Background(), scanners.TargetImage, string(id)); ok {
		t.Fatal("images are not resolvable yet")
	}
}
