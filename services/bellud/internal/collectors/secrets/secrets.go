// Package secrets implements the secrets collector: a Gitleaks scan (through
// scanners/secretscan) of configured roots that emits secret_finding entities
// carrying only {path, line, rule_id, hash_prefix}. The secret value never
// leaves the engine; hash_prefix is the first 8 hex chars of its fingerprint.
package secrets

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/secretscan"
)

const (
	// Name is the collector name and batch source.
	Name = "secrets"
	// MaxFileSize is the largest file scanned; bigger files are skipped.
	MaxFileSize = secretscan.MaxFileSize
	// DefaultInterval is the scan period.
	DefaultInterval = 10 * time.Minute
	hashPrefixLen   = 8
)

// skipDirs are never descended into. "testdata" is skipped on purpose: this
// repository's own fixtures hold fake secrets and would self-report. The
// configured root itself is always scanned, whatever its name.
var skipDirs = map[string]bool{"node_modules": true, ".git": true, "dist": true, "testdata": true}

// Collector scans Roots for secrets.
type Collector struct {
	Roots     []string
	IntervalD time.Duration
	Now       func() time.Time
	// WorkspaceDir holds the fingerprint salt; empty uses a built-in salt.
	WorkspaceDir string
	// ConfigPath is an optional custom Gitleaks config.
	ConfigPath string
}

// New returns a collector scanning roots.
func New(roots ...string) *Collector { return &Collector{Roots: roots} }

func (c *Collector) Name() string { return Name }

func (c *Collector) Interval() time.Duration {
	if c.IntervalD > 0 {
		return c.IntervalD
	}
	return DefaultInterval
}

// Collect scans every root and returns the full current observation.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	eng, err := secretscan.New(secretscan.Options{WorkspaceDir: c.WorkspaceDir, ConfigPath: c.ConfigPath})
	if err != nil {
		return graph.Batch{}, err
	}
	b := batch.Batch{Collector: Name, ObservedAt: now().UTC()}
	seen := map[string]bool{}
	for _, root := range c.Roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return graph.Batch{}, err
		}
		repoID, err := facade.Hash("repository", map[string]string{"path": abs})
		if err != nil {
			return graph.Batch{}, err
		}
		b.Entities = append(b.Entities, batch.Entity{
			Type: "repository", Identity: map[string]string{"path": abs},
		})
		err = secretscan.Walk(ctx, abs, skipDirs, func(p string, content []byte) {
			for _, h := range eng.ScanContent(ctx, p, content) {
				key := p + "\x00" + strconv.Itoa(h.Line) + "\x00" + h.RuleID
				if seen[key] {
					continue
				}
				seen[key] = true
				id := map[string]string{"path": p, "line": strconv.Itoa(h.Line), "rule": h.RuleID}
				fid, herr := facade.Hash("secret_finding", id)
				if herr != nil {
					continue
				}
				b.Entities = append(b.Entities, batch.Entity{Type: "secret_finding", Identity: id,
					Attributes: map[string]any{
						"path": p, "line": h.Line, "rule_id": h.RuleID,
						"hash_prefix": h.Fingerprint[:hashPrefixLen], "repo": abs,
					}})
				b.Relations = append(b.Relations, batch.Relation{Type: "found_in", From: string(fid), To: string(repoID)})
			}
		})
		if err != nil {
			return graph.Batch{}, err
		}
	}
	sort.SliceStable(b.Entities, func(i, j int) bool { return b.Entities[i].Type < b.Entities[j].Type })
	return b, nil
}
