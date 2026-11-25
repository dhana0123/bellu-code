package secretscan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/safeextract"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// History commit bounds for `secrets.history_commits` (Requirement 9.2).
const (
	DefaultHistoryCommits = 1000
	MinHistoryCommits     = 1
	MaxHistoryCommits     = 100000
)

// HistoryLimit validates the configured commit count; zero means the default.
func HistoryLimit(n int) (int, error) {
	if n == 0 {
		return DefaultHistoryCommits, nil
	}
	if n < MinHistoryCommits || n > MaxHistoryCommits {
		return 0, fmt.Errorf("secretscan: secrets.history_commits %d outside %d..%d", n, MinHistoryCommits, MaxHistoryCommits)
	}
	return n, nil
}

// Targets scans git history, image layers and connector text with one Engine.
// An unreadable target is reported through Out.ScannerError and skipped; the
// scan continues (Requirement 9.12).
type Targets struct {
	Eng   *Engine
	Asset string
	Out   scanners.Sink
	Now   func() time.Time
}

func (t Targets) emit(hits []Hit) error {
	if len(hits) == 0 {
		return nil
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	fs := make([]findings.Finding, 0, len(hits))
	for _, h := range hits {
		fs = append(fs, finding(t.Asset, h, now().UTC()))
	}
	return t.Out.Findings(fs)
}

func (t Targets) skip(target string, cause error) error {
	return t.Out.ScannerError(target, cause.Error())
}

// ScanText is the hook connector collectors call with configuration text
// (Lambda environment values, EC2 user data). The AWS collector deliberately
// stores no such values, so nothing calls this yet. source names the resource
// and key, for example "lambda:fn-1:env/API_KEY".
func (t Targets) ScanText(ctx context.Context, source, text string) error {
	return t.emit(t.Eng.ScanContent(ctx, source, []byte(text)))
}

// ScanHistory scans the added lines of up to limit commits per ref, counted
// from the most recent commit. Each finding records the commit id.
func (t Targets) ScanHistory(ctx context.Context, repoPath string, limit int) error {
	limit, err := HistoryLimit(limit)
	if err != nil {
		return err
	}
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return t.skip(repoPath, fmt.Errorf("secretscan: git history %q: %w", repoPath, err))
	}
	refs, err := repo.References()
	if err != nil {
		return t.skip(repoPath, fmt.Errorf("secretscan: git history %q: %w", repoPath, err))
	}
	var tips []plumbing.Hash
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		if r.Type() == plumbing.HashReference && (r.Name().IsBranch() || r.Name().IsRemote() || r.Name().IsTag()) {
			tips = append(tips, r.Hash())
		}
		return nil
	})
	seen := map[plumbing.Hash]bool{}
	for _, tip := range tips {
		c, err := repo.CommitObject(tip) // annotated tags and non-commits are skipped
		if err != nil {
			continue
		}
		it := object.NewCommitPreorderIter(c, nil, nil)
		n := 0
		err = it.ForEach(func(c *object.Commit) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if n >= limit {
				return storer.ErrStop
			}
			n++
			if seen[c.Hash] {
				return nil
			}
			seen[c.Hash] = true
			if err := t.scanCommit(ctx, c); err != nil {
				return t.skip(repoPath+"@"+c.Hash.String(), fmt.Errorf("secretscan: commit %s: %w", c.Hash, err))
			}
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

func (t Targets) scanCommit(ctx context.Context, c *object.Commit) error {
	tree, err := c.Tree()
	if err != nil {
		return err
	}
	var parent *object.Tree
	if c.NumParents() > 0 {
		p, err := c.Parent(0)
		if err != nil {
			return err
		}
		if parent, err = p.Tree(); err != nil {
			return err
		}
	}
	changes, err := object.DiffTreeWithOptions(ctx, parent, tree, object.DefaultDiffTreeOptions)
	if err != nil {
		return err
	}
	patch, err := changes.PatchContext(ctx)
	if err != nil {
		return err
	}
	for _, fp := range patch.FilePatches() {
		if fp.IsBinary() {
			continue
		}
		_, to := fp.Files()
		if to == nil {
			continue
		}
		var added strings.Builder
		for _, ch := range fp.Chunks() {
			if ch.Type() == 1 { // diff.Add
				added.WriteString(ch.Content())
				if !strings.HasSuffix(ch.Content(), "\n") {
					added.WriteString("\n")
				}
			}
		}
		if added.Len() == 0 {
			continue
		}
		hits := t.Eng.ScanContent(ctx, to.Path(), []byte(added.String()))
		for i := range hits {
			hits[i].Commit = c.Hash.String()
		}
		if err := t.emit(hits); err != nil {
			return err
		}
	}
	return nil
}

// ScanImage reads the layers of an image tar (docker save or OCI layout)
// through safeextract and scans the file contents. Findings name the layer
// and path.
func (t Targets) ScanImage(ctx context.Context, imageTar string, l safeextract.Limits) error {
	f, err := os.Open(imageTar)
	if err != nil {
		return t.skip(imageTar, fmt.Errorf("secretscan: image %q: %w", imageTar, err))
	}
	defer f.Close()
	tmp, err := os.MkdirTemp("", "secretscan-image-")
	if err != nil {
		return t.skip(imageTar, err)
	}
	defer os.RemoveAll(tmp)
	if err := safeextract.ExtractTar(f, tmp, l, nil); err != nil {
		return t.skip(imageTar, fmt.Errorf("secretscan: image %q: %w", imageTar, err))
	}
	// Layers are the nested tar files, or OCI blobs that are tar streams.
	var layers []string
	_ = filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && isLayer(p) {
			layers = append(layers, p)
		}
		return nil
	})
	scanTree := func(root, label string) {
		_ = Walk(ctx, root, nil, func(p string, b []byte) {
			rel, _ := filepath.Rel(root, p)
			hits := t.Eng.ScanContent(ctx, label+":"+rel, b)
			_ = t.emit(hits)
		})
	}
	if len(layers) == 0 {
		scanTree(tmp, filepath.Base(imageTar))
		return ctx.Err()
	}
	for i, lp := range layers {
		rel, _ := filepath.Rel(tmp, lp)
		dst := filepath.Join(tmp, fmt.Sprintf(".layer-%d", i))
		lf, err := os.Open(lp)
		if err != nil {
			if e := t.skip(rel, err); e != nil {
				return e
			}
			continue
		}
		err = safeextract.ExtractTar(lf, dst, l, nil)
		lf.Close()
		if err != nil {
			if e := t.skip(rel, fmt.Errorf("secretscan: layer %q: %w", rel, err)); e != nil {
				return e
			}
			continue
		}
		scanTree(dst, rel)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func isLayer(p string) bool {
	if strings.HasSuffix(p, ".tar") || strings.HasSuffix(p, ".tar.gz") || strings.HasSuffix(p, ".tgz") {
		return true
	}
	if !strings.Contains(filepath.ToSlash(p), "/blobs/") {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 512)
	n, _ := io.ReadFull(f, b)
	if n >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		return true
	}
	return n == 512 && string(b[257:262]) == "ustar"
}

// Identity is an identity entity with the credential ids it owns, for
// example an IAM user and its access key ids.
type Identity struct {
	EntityID      string
	CredentialIDs []string
}

// LinkCredential returns the identity entity id when credentialID matches the
// credential of exactly one identity (Requirement 9.8). Otherwise it returns
// false and the credential stays unlinked.
func LinkCredential(credentialID string, ids []Identity) (string, bool) {
	if credentialID == "" {
		return "", false
	}
	owner := ""
	for _, id := range ids {
		for _, c := range id.CredentialIDs {
			if c == credentialID {
				if owner != "" && owner != id.EntityID {
					return "", false
				}
				owner = id.EntityID
				break
			}
		}
	}
	return owner, owner != ""
}
