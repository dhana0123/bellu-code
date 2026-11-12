// Package codesec is the code-security collector: it reads dependency
// manifests and GitHub workflows under configured repository roots and emits
// repository, dependency, workflow and secret_ref entities (Requirements
// 14.4, 14.7, 14.9).
//
// Rescan: no fsnotify is vendored, so change detection is a cheap stat poll.
// Interval is 5s (the rescan bound); each Collect walks the tree with stat
// only and, when no relevant file's (path, mtime, size) changed since the
// last run, returns the cached full observation without re-reading files.
// Files over 1 MiB and node_modules/.git are never read or descended into.
// secret_ref carries the secret NAME only, never a value.
package codesec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

const (
	// Name is the collector name.
	Name = "codesec"
	// RescanInterval bounds how long a file change takes to be observed.
	RescanInterval = 5 * time.Second
	// MaxFileSize is the largest file the collector will read.
	MaxFileSize = 1 << 20
)

// Collector scans repository roots.
type Collector struct {
	roots []string

	mu    sync.Mutex
	sig   string
	cache graph.Batch
	have  bool
}

// New returns a collector for the given repository root paths.
func New(roots ...string) *Collector {
	rs := make([]string, 0, len(roots))
	for _, r := range roots {
		if abs, err := filepath.Abs(r); err == nil {
			r = abs
		}
		rs = append(rs, filepath.Clean(r))
	}
	return &Collector{roots: rs}
}

// Name implements collectors.Collector.
func (c *Collector) Name() string { return Name }

// Interval implements collectors.Collector.
func (c *Collector) Interval() time.Duration { return RescanInterval }

var skipDirs = map[string]bool{"node_modules": true, ".git": true}

type file struct {
	root, abs, rel string
	kind           string // package.json|bun.lock|go.mod|requirements.txt|workflow
}

// discover lists relevant files (stat only), sorted.
func (c *Collector) discover(ctx context.Context) ([]file, string, error) {
	var files []file
	h := sha256.New()
	for _, root := range c.roots {
		fi, err := os.Stat(root)
		if err != nil || !fi.IsDir() {
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			kind := ""
			switch d.Name() {
			case "package.json", "bun.lock", "go.mod", "requirements.txt":
				kind = d.Name()
			default:
				ext := filepath.Ext(rel)
				if (ext == ".yml" || ext == ".yaml") && filepath.ToSlash(filepath.Dir(rel)) == ".github/workflows" {
					kind = "workflow"
				}
			}
			if kind == "" {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileSize {
				return nil
			}
			files = append(files, file{root: root, abs: p, rel: rel, kind: kind})
			h.Write([]byte(p + "|" + info.ModTime().UTC().Format(time.RFC3339Nano) + "|" +
				itoa(info.Size()) + "\n"))
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		h.Write([]byte("root:" + root + "\n"))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].abs < files[j].abs })
	return files, hex.EncodeToString(h.Sum(nil)), nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Collect implements collectors.Collector.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	files, sig, err := c.discover(ctx)
	if err != nil {
		return graph.Batch{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.have && sig == c.sig {
		return c.cache, nil
	}
	b := c.build(files)
	c.sig, c.cache, c.have = sig, b, true
	return b, nil
}

func (c *Collector) build(files []file) graph.Batch {
	b := &builder{ents: map[string]*batch.Entity{}, rels: map[[3]string]bool{}}
	for _, r := range c.roots {
		if fi, err := os.Stat(r); err == nil && fi.IsDir() {
			b.repo(r)
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f.abs)
		if err != nil || int64(len(data)) > MaxFileSize {
			continue
		}
		switch f.kind {
		case "package.json":
			parsePackageJSON(b, f, data)
		case "bun.lock":
			parseBunLock(b, f, data)
		case "go.mod":
			parseGoMod(b, f, data)
		case "requirements.txt":
			parseRequirements(b, f, data)
		case "workflow":
			parseWorkflow(b, f, data)
		}
	}
	return b.batch()
}

// builder accumulates deduplicated entities and relations deterministically.
type builder struct {
	ents map[string]*batch.Entity // by entity id
	rels map[[3]string]bool
}

func (b *builder) add(kind string, id map[string]string, attrs map[string]any) (string, *batch.Entity) {
	h, err := identity.Hash(kind, id)
	if err != nil {
		return "", nil
	}
	key := string(h)
	if e, ok := b.ents[key]; ok {
		return key, e
	}
	e := &batch.Entity{Type: kind, Identity: id, Attributes: attrs}
	if e.Attributes == nil {
		e.Attributes = map[string]any{}
	}
	b.ents[key] = e
	return key, e
}

func (b *builder) rel(typ, from, to string) {
	if from == "" || to == "" {
		return
	}
	b.rels[[3]string{typ, from, to}] = true
}

func (b *builder) repo(root string) string {
	k, _ := b.add("repository", map[string]string{"path": root}, map[string]any{"name": filepath.Base(root)})
	return k
}

// dep records a dependency of the repo declared by manifest src.
func (b *builder) dep(f file, name, rng, ecosystem, scope string) {
	if name == "" {
		return
	}
	if rng == "" {
		rng = "*"
	}
	repo := b.repo(f.root)
	k, e := b.add("dependency", map[string]string{"repo": f.root, "name": name, "range": rng},
		map[string]any{"ecosystem": ecosystem, "scope": scope, "manifest": f.rel})
	if e == nil {
		return
	}
	// Same dependency in several manifests: keep the first (sorted) source.
	b.rel("declared_in", k, repo)
	b.rel("depends_on", repo, k)
}

func (b *builder) batch() graph.Batch {
	keys := make([]string, 0, len(b.ents))
	for k := range b.ents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := graph.Batch{Collector: Name, ObservedAt: time.Now().UTC()}
	for _, k := range keys {
		out.Entities = append(out.Entities, *b.ents[k])
	}
	rs := make([][3]string, 0, len(b.rels))
	for r := range b.rels {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool {
		for x := 0; x < 3; x++ {
			if rs[i][x] != rs[j][x] {
				return rs[i][x] < rs[j][x]
			}
		}
		return false
	})
	for _, r := range rs {
		out.Relations = append(out.Relations, batch.Relation{Type: r[0], From: r[1], To: r[2]})
	}
	return out
}
