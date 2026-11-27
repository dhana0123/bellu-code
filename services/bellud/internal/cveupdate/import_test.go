package cveupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkginstall "github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/install"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/sign"
)

func writePack(t *testing.T, e *env, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".sig", sign.Sign(e.priv, data), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportMatchesDownload(t *testing.T) {
	dl := newEnv(t)
	if _, err := dl.up.InstallIndex(context.Background(), fullIndex(dl, 1, "1", false)); err != nil {
		t.Fatal(err)
	}
	want, _ := (&pkginstall.Installer{DataDir: dl.dir}).Status()

	e := newEnv(t)
	e.up.Client = nil // no network access
	e.srv.Close()
	f := writePack(t, e, "snap.tar.gz", snapshotPack(t, 1, "1", false))
	res, err := e.up.ImportPack(context.Background(), f, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.ToID != want.InstalledID || res.State.InstalledID != want.InstalledID {
		t.Fatalf("import %+v, download %+v", res.State, want)
	}
	if len(e.audit.rows) != 1 || e.audit.rows[0].Outcome != "success" || e.audit.rows[0].Source != SourceImport {
		t.Fatalf("audit %+v", e.audit.rows)
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatal("import removed the user's file")
	}

	// A delta applies on top of the installed snapshot; the same delta again is a no-op, and a delta with another base is rejected.
	d := writePack(t, e, "d.tar.gz", deltaPack(t, 1, 2))
	if res, err = e.up.ImportPack(context.Background(), d, ""); err != nil {
		t.Fatal(err)
	}
	if id, _ := tsnap(2); res.State.InstalledID != id {
		t.Fatalf("got %s", res.State.InstalledID)
	}
	if res, err = e.up.ImportPack(context.Background(), d, ""); err != nil || !res.Unchanged {
		t.Fatalf("re-import: %v %+v", err, res)
	}
	wrong := writePack(t, e, "w.tar.gz", deltaPack(t, 3, 4))
	if _, err := e.up.ImportPack(context.Background(), wrong, ""); err == nil || !strings.Contains(err.Error(), "does not apply") {
		t.Fatalf("got %v", err)
	}
}

func TestImportRejections(t *testing.T) {
	e := newEnv(t)
	e.up.Client = nil
	good := snapshotPack(t, 1, "1", false)
	f := writePack(t, e, "snap.tar.gz", good)
	other := newEnv(t)
	badSig := filepath.Join(t.TempDir(), "bad.sig")
	os.WriteFile(badSig, sign.Sign(other.priv, good), 0o644)
	if _, err := e.up.ImportPack(context.Background(), f, badSig); err == nil || !strings.Contains(err.Error(), "import snap.tar.gz") {
		t.Fatalf("unpinned signature: %v", err)
	}
	if _, err := e.up.ImportPack(context.Background(), f, filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("missing signature accepted")
	}
	corrupt := writePack(t, e, "c.tar.gz", snapshotPack(t, 1, "1", true))
	if _, err := e.up.ImportPack(context.Background(), corrupt, ""); err == nil {
		t.Fatal("corrupt db accepted")
	}
	if _, err := os.Readlink(filepath.Join(e.dir, "current")); err == nil {
		t.Fatal("current set after failures")
	}
	if len(e.audit.rows) != 3 {
		t.Fatalf("want one audit row per failure, got %+v", e.audit.rows)
	}
}
