package secretscan

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/bellu/bellucode/services/bellud/internal/safeextract"
)

const fakeKey = "AKIAIOSFODNN7EXAMPLQ"
const fakeLine = "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzR3xAmPl9q\"\naws_access_key_id = \"" + fakeKey + "\"\n"

func newTargets(t *testing.T) (Targets, *sink) {
	eng, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	return Targets{Eng: eng, Asset: "a", Out: s}, s
}

func commitFile(t *testing.T, repo *git.Repository, dir, name, content string) string {
	wt, _ := repo.Worktree()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add(name); err != nil {
		t.Fatal(err)
	}
	h, err := wt.Commit("c", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@e", When: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

func TestHistoryFindsRemovedSecretWithCommit(t *testing.T) {
	dir := t.TempDir()
	repo, _ := git.PlainInit(dir, false)
	c1 := commitFile(t, repo, dir, "cfg.txt", fakeLine)
	commitFile(t, repo, dir, "cfg.txt", "clean\n")
	commitFile(t, repo, dir, "other.txt", "x\n")
	tg, s := newTargets(t)
	if err := tg.ScanHistory(context.Background(), dir, 0); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range s.fs {
		if bytes.Contains(f.Details, []byte(c1)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no finding with commit %s: %+v", c1, s.fs)
	}
	// limit 1 only sees the newest commit, which has no secret.
	tg, s = newTargets(t)
	if err := tg.ScanHistory(context.Background(), dir, 1); err != nil {
		t.Fatal(err)
	}
	if len(s.fs) != 0 {
		t.Fatalf("limit not respected: %d findings", len(s.fs))
	}
	if _, err := HistoryLimit(100001); err == nil {
		t.Fatal("expected range error")
	}
}

func TestImageLayersAndUnreadable(t *testing.T) {
	layer := tarBytes(t, map[string]string{"app/.env": fakeLine})
	img := tarBytes(t, map[string]string{"abc/layer.tar": string(layer)})
	p := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	tg, s := newTargets(t)
	if err := tg.ScanImage(context.Background(), p, safeextract.Limits{}); err != nil {
		t.Fatal(err)
	}
	if len(s.fs) == 0 {
		t.Fatal("no finding in image layer")
	}
	if err := tg.ScanImage(context.Background(), filepath.Join(t.TempDir(), "missing.tar"), safeextract.Limits{}); err != nil {
		t.Fatal(err)
	}
	if len(s.errs) != 1 {
		t.Fatalf("want one scanner error, got %v", s.errs)
	}
	if err := tg.ScanText(context.Background(), "lambda:f:env/KEY", fakeLine); err != nil || len(s.fs) < 2 {
		t.Fatal("ScanText found nothing")
	}
}

func TestLinkCredential(t *testing.T) {
	ids := []Identity{{"u1", []string{"AK1"}}, {"u2", []string{"AK2", "AK3"}}, {"u3", []string{"AK3"}}}
	if id, ok := LinkCredential("AK1", ids); !ok || id != "u1" {
		t.Fatal("AK1 should link to u1")
	}
	if _, ok := LinkCredential("AK3", ids); ok {
		t.Fatal("ambiguous must stay unlinked")
	}
	if _, ok := LinkCredential("none", ids); ok {
		t.Fatal("no match must stay unlinked")
	}
}

func tarBytes(t *testing.T, files map[string]string) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for n, c := range files {
		_ = w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		_, _ = w.Write([]byte(c))
	}
	w.Close()
	return b.Bytes()
}
