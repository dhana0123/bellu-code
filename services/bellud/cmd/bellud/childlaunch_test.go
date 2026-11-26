package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestChildLaunchCLIBin(t *testing.T) {
	// A bad repo must be ignored when cli-bin is set.
	cmd, dir, err := childLaunch("/opt/app/bellucode-cli", "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/app/bellucode-cli", "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"}
	if !reflect.DeepEqual(cmd, want) || dir != "" {
		t.Fatalf("got %v, %q", cmd, dir)
	}
}

func TestChildLaunchDefaultUsesBun(t *testing.T) {
	repo := t.TempDir()
	cli := filepath.Join(repo, "packages", "cli")
	if err := os.MkdirAll(cli, 0o755); err != nil {
		t.Fatal(err)
	}
	bunDir := t.TempDir()
	bun := filepath.Join(bunDir, "bun")
	if err := os.WriteFile(bun, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bunDir)
	cmd, dir, err := childLaunch("  ", repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{bun, "run", "src/index.ts", "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"}
	if !reflect.DeepEqual(cmd, want) || dir != cli {
		t.Fatalf("got %v, %q", cmd, dir)
	}
}

func TestChildLaunchDefaultMissingRepo(t *testing.T) {
	if _, _, err := childLaunch("", t.TempDir()); err == nil {
		t.Fatal("expected error for repo without packages/cli")
	}
}
