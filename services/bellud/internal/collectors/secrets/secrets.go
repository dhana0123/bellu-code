// Package secrets implements the secrets collector: a rule-based scan of
// configured roots that emits secret_finding entities carrying only
// {path, line, rule_id, hash_prefix}. Matched text never leaves scanLine.
package secrets

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

const (
	// Name is the collector name and batch source.
	Name = "secrets"
	// MaxFileSize is the largest file scanned; bigger files are skipped.
	MaxFileSize = 1 << 20
	// DefaultInterval is the scan period.
	DefaultInterval = 10 * time.Minute

	hashPrefixLen = 8
	minEntropy    = 3.0
)

// skipDirs are never descended into. "testdata" is skipped on purpose: this
// repository's own fixtures hold fake secrets and would self-report. The
// configured root itself is always scanned, whatever its name.
var skipDirs = map[string]bool{"node_modules": true, ".git": true, "dist": true, "testdata": true}

type rule struct {
	id string
	re *regexp.Regexp
	// group is the capture group holding the secret value (0 = whole match).
	group int
	// entropy requires the value to look random (generic assignments only).
	entropy bool
}

var rules = buildRules()

func buildRules() []rule {
	var out []rule
	// Reuse the redaction value rules so detection and scrubbing agree.
	for _, v := range redact.ValueRules {
		out = append(out, rule{id: v.ID, re: v.Re})
	}
	return append(out,
		rule{id: "generic_assignment", group: 1, entropy: true,
			re: regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9/+_=.-]{12,})`)},
	)
}

type hit struct{ rule, hashPrefix string }

// scanLine is the only place matched text exists. It returns metadata only:
// the rule id and the first 8 hex chars of SHA-256 of the matched value.
func scanLine(line []byte) []hit {
	var hits []hit
	for _, r := range rules {
		m := r.re.FindSubmatch(line)
		if m == nil || r.group >= len(m) {
			continue
		}
		v := m[r.group]
		if r.entropy && entropy(v) < minEntropy {
			continue
		}
		sum := sha256.Sum256(v)
		hits = append(hits, hit{rule: r.id, hashPrefix: hex.EncodeToString(sum[:])[:hashPrefixLen]})
	}
	return hits
}

func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Collector scans Roots for secrets.
type Collector struct {
	Roots     []string
	IntervalD time.Duration
	Now       func() time.Time
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
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil // unreadable entry: skip
			}
			if d.IsDir() {
				if p != abs && skipDirs[d.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			for _, h := range scanFile(p) {
				key := p + "\x00" + strconv.Itoa(h.line) + "\x00" + h.rule
				if seen[key] {
					continue
				}
				seen[key] = true
				id := map[string]string{"path": p, "line": strconv.Itoa(h.line), "rule": h.rule}
				fid, herr := facade.Hash("secret_finding", id)
				if herr != nil {
					return herr
				}
				b.Entities = append(b.Entities, batch.Entity{Type: "secret_finding", Identity: id,
					Attributes: map[string]any{
						"path": p, "line": h.line, "rule_id": h.rule,
						"hash_prefix": h.hashPrefix, "repo": abs,
					}})
				b.Relations = append(b.Relations, batch.Relation{Type: "found_in", From: string(fid), To: string(repoID)})
			}
			return nil
		})
		if err != nil {
			return graph.Batch{}, err
		}
	}
	sort.SliceStable(b.Entities, func(i, j int) bool { return b.Entities[i].Type < b.Entities[j].Type })
	return b, nil
}

type fileHit struct {
	line int
	hit
}

// scanFile skips oversized and binary files and returns per-line metadata.
func scanFile(path string) []fileHit {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > MaxFileSize {
		return nil
	}
	br := bufio.NewReaderSize(f, 64<<10)
	head, _ := br.Peek(8000)
	if bytes.IndexByte(head, 0) >= 0 {
		return nil
	}
	var out []fileHit
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64<<10), MaxFileSize)
	for n := 1; sc.Scan(); n++ {
		for _, h := range scanLine(sc.Bytes()) {
			out = append(out, fileHit{line: n, hit: h})
		}
	}
	return out
}
