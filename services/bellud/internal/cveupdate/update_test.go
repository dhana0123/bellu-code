package cveupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	"github.com/bellu/global-cv-graph/pkg/sign"
)

type memState struct{ row *sqlite.CVEUpdateState }

func (m *memState) GetCVEUpdateState(context.Context) (sqlite.CVEUpdateState, bool, error) {
	if m.row == nil {
		return sqlite.CVEUpdateState{}, false, nil
	}
	return *m.row, true, nil
}
func (m *memState) PutCVEUpdateState(_ context.Context, st sqlite.CVEUpdateState) error {
	m.row = &st
	return nil
}
func (m *memState) RecordCVECheck(_ context.Context, at time.Time, etag string) error {
	if m.row == nil {
		m.row = &sqlite.CVEUpdateState{}
	}
	m.row.LastCheckAt = at
	if etag != "" {
		m.row.ETag = etag
	}
	return nil
}

func publishIndex(t *testing.T, e *env, idx *Index, goodSig bool) {
	t.Helper()
	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	sig := sign.Sign(e.priv, raw)
	if !goodSig {
		sig = sign.Sign(e.priv, append(raw, ' '))
	}
	e.mu.Lock()
	e.objects["/cve/v1/index.json"], e.objects["/cve/v1/index.json.sig"] = raw, sig
	e.mu.Unlock()
}

func TestUpdateInstallsAndRecordsState(t *testing.T) {
	e := newEnv(t)
	st := &memState{}
	e.up.State, e.up.Source = st, SourceMirror
	publishIndex(t, e, fullIndex(e, 1, "1", false), true)
	res, err := e.up.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tsnap(1)
	if res.ToID != id || st.row == nil || st.row.SnapshotID != id || st.row.Source != SourceMirror || st.row.LastCheckAt.IsZero() {
		t.Fatalf("res=%+v state=%+v", res, st.row)
	}
}

func TestUpdateRejectsBadIndexSignatureAndAudits(t *testing.T) {
	e := newEnv(t)
	e.up.State = &memState{}
	publishIndex(t, e, fullIndex(e, 1, "1", false), false)
	if _, err := e.up.Update(context.Background()); err == nil {
		t.Fatal("expected a signature error")
	}
	if e.currentID() != "" || len(e.audit.rows) != 1 || e.audit.rows[0].Outcome != "failure" || e.audit.rows[0].Step != StepVerify {
		t.Fatalf("current=%q audit=%+v", e.currentID(), e.audit.rows)
	}
}

func TestInstallPanicAuditsFailure(t *testing.T) {
	e := newEnv(t)
	idx := fullIndex(e, 1, "1", false)
	e.up.AfterStep = func(string) error { panic("boom") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was swallowed")
			}
		}()
		e.up.InstallIndex(context.Background(), idx)
	}()
	if len(e.audit.rows) != 1 || e.audit.rows[0].Outcome != "failure" || !strings.Contains(e.audit.rows[0].Cause, "boom") {
		t.Fatalf("audit=%+v", e.audit.rows)
	}
}

func TestRunCLIStatusNoneInstalledAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	env := CLIEnv{DataDir: t.TempDir(), Config: config.CVE{}, Stdout: &out, Stderr: &errb}
	if err := RunCLI(context.Background(), []string{"status"}, env); err != nil {
		t.Fatal(err)
	}
	if out.String() != "none installed\n" {
		t.Fatalf("status output %q", out.String())
	}
	if err := RunCLI(context.Background(), []string{"import"}, env); err == nil {
		t.Fatal("import without a file must fail")
	}
	if err := RunCLI(context.Background(), []string{"update", "--mirror", "ftp://x"}, env); err == nil {
		t.Fatal("bad mirror must fail")
	}
}
