package syft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Digest implements scanners.Adapter. It is cheaper than a scan and stable
// across calls on unchanged content:
//
//   - image archive: SHA-256 of the archive file, which contains the manifest
//     and so covers the manifest digest and every layer;
//   - OCI directory: SHA-256 of index.json, which names every manifest digest;
//   - repository: SHA-256 over the sorted (relative path, size, mtime) of the
//     package manifest and lock files, and of the OS package databases, found
//     under the directory (".git" is skipped);
//   - host: empty. Walking a host root is as costly as a scan, so the job
//     always runs.
func (Adapter) Digest(ctx context.Context, t scanners.Target) (string, error) {
	switch t.Type {
	case scanners.TargetImage:
		return imageDigest(t)
	case scanners.TargetRepository:
		return dirDigest(ctx, t.Path)
	}
	return "", nil
}

func imageDigest(t scanners.Target) (string, error) {
	fi, err := os.Stat(t.Path)
	if err != nil {
		return "", unreadable(t, err)
	}
	path := t.Path
	if fi.IsDir() {
		path = filepath.Join(t.Path, "index.json")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", unreadable(t, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", unreadable(t, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// manifestNames are file base names that Syft's cataloger set reads.
var manifestNames = map[string]bool{
	"go.mod": true, "go.sum": true,
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"requirements.txt": true, "pipfile.lock": true, "poetry.lock": true, "pyproject.toml": true, "setup.py": true,
	"pom.xml": true, "build.gradle": true, "gradle.lockfile": true,
	"cargo.toml": true, "cargo.lock": true,
	"gemfile": true, "gemfile.lock": true,
	"composer.json": true, "composer.lock": true,
	"packages.lock.json": true, "packages.config": true,
	"installed": true, "status": true, "packages": true, "packages.db": true, "rpmdb.sqlite": true, "os-release": true,
}

var manifestSuffixes = []string{".csproj", ".gemspec", ".deps.json", ".jar", ".war", ".ear", ".whl"}

func isManifest(name string) bool {
	n := strings.ToLower(name)
	if manifestNames[n] {
		return true
	}
	for _, s := range manifestSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

func dirDigest(ctx context.Context, root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !isManifest(d.Name()) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), fi.Size(), fi.ModTime().UnixNano())
		return err
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
