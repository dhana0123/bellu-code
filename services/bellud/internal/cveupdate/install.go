package cveupdate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pkginstall "github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/install"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/intel"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Install steps, used in InstallError.Step and in the audit row.
const (
	StepPlan      = "plan"
	StepDisk      = "disk-space"
	StepDownload  = "download"
	StepVerify    = "verify"
	StepApply     = "apply"
	StepIntegrity = "integrity"
	StepSwap      = "swap"
)

const (
	maxSigBytes = 64 << 10
	// diskFactor estimates the space needed per downloaded byte: the pack, its
	// extracted database and slack.
	diskFactor = 3
)

// Errors returned by the install.
var (
	ErrDiskSpace      = errors.New("insufficient disk space")
	ErrSchemaMismatch = errors.New("unsupported snapshot schema version")
	ErrIntegrity      = errors.New("snapshot integrity check failed")
	ErrPackSize       = errors.New("pack size differs from the signed index")
)

// InstallError names the step that failed. The installed snapshot, SyncStatus
// and Cache_Key are unchanged whenever one is returned.
type InstallError struct {
	Step string
	Err  error
}

func (e *InstallError) Error() string {
	return fmt.Sprintf("cve install failed at %s: %v", e.Step, e.Err)
}
func (e *InstallError) Unwrap() error { return e.Err }

func stepErr(step string, err error) error {
	var ie *InstallError
	if err == nil || errors.As(err, &ie) {
		return err
	}
	return &InstallError{Step: step, Err: err}
}

// AuditEntry is one row for the audit table (Requirement 19.5).
type AuditEntry struct {
	At      time.Time
	Action  string // "cve-update"
	Outcome string // "success" or "failure"
	FromID  string // installed snapshot id before, "" when none
	Source  string // "import" for a file import, "" for a download
	ToID    string // target snapshot id
	Step    string // failing step, "" on success
	Cause   string // error text, "" on success
}

// AuditSink appends audit rows. It is implemented by the audit store.
type AuditSink interface {
	AppendCVEUpdate(ctx context.Context, e AuditEntry) error
}

// Updater installs the packs named by a verified index into Dir.
//
// Dir layout: snapshots/<id>/{graph.db,manifest.json}, the relative symlink
// current, state.json, and a staging/ directory that is empty between runs.
// Only one Updater may run on a Dir at a time; a lock enforces this.
type Updater struct {
	Dir      string
	Client   *Client
	Verifier *Verifier
	Audit    AuditSink // nil: no audit rows
	// State records SyncStatus after a successful install; nil: not recorded.
	State StateStore
	// Source is recorded in SyncStatus: SourceDownload, SourceMirror or
	// SourceImport. Empty means SourceDownload.
	Source string

	// MaxChain is cve.max_delta_chain; 0 means the default of 30.
	MaxChain       int
	AllowDowngrade bool

	// Test seams. Zero values use production behaviour.
	Now       func() time.Time
	FreeBytes func(dir string) (uint64, error)
	// AfterStep is called after each named step and may fail it.
	AfterStep func(step string) error
}

// Result describes a finished InstallIndex call.
type Result struct {
	Unchanged bool // already up to date, nothing fetched
	FromID    string
	ToID      string
	Source    string // "import" for a file import, "" for a download
	Plan      Plan
	State     pkginstall.State
	// AuditErr is set when the install succeeded but the audit row could not
	// be appended.
	AuditErr error
	// StateErr is set when the swap succeeded but cve_update_state could not
	// be written.
	StateErr error
}

type packRef struct {
	name, url, sigURL, sha string
	size                   int64
}

// InstallIndex installs the latest snapshot named by idx, which the caller has
// already verified with Verifier.VerifyIndex. It downloads into a staging
// directory, verifies every pack before applying any, applies the packs in
// staging, runs the integrity and schema checks, and only then swaps current
// in one atomic rename. On any failure it removes staging, leaves current,
// state.json and therefore SyncStatus and the Cache_Key untouched, and appends
// one audit row.
func (u *Updater) InstallIndex(ctx context.Context, idx *Index) (Result, error) {
	if u.Client == nil {
		return Result{}, errors.New("cveupdate: Client is required to download")
	}
	return u.install(ctx, idx, u.download, "", nil)
}

// fetchFunc obtains pack i into staging and returns its path and detached
// signature. Downloads and file imports differ only here.
type fetchFunc func(ctx context.Context, staging string, i int, p packRef) (string, []byte, error)

// install is the shared core of InstallIndex and ImportPack. checkPlan, when
// set, may reject the chosen plan before anything is fetched.
func (u *Updater) install(ctx context.Context, idx *Index, fetch fetchFunc, source string, checkPlan func(Plan) error) (res Result, err error) {
	if u.Dir == "" || u.Verifier == nil {
		return Result{}, errors.New("cveupdate: Dir and Verifier are required")
	}
	unlock, err := lockDir(u.Dir)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	inst := &pkginstall.Installer{DataDir: u.Dir}
	res.Source = source
	defer func() {
		// A panic leaves err nil, so it must be turned into a failure here or
		// the audit row would claim success. The panic continues after the row
		// is written.
		panicked := recover()
		if panicked != nil {
			err = fmt.Errorf("cve install panicked: %v", panicked)
			defer panic(panicked)
		}
		if res.Unchanged && panicked == nil {
			return
		}
		e := AuditEntry{At: u.now(), Action: "cve-update", Outcome: "success", FromID: res.FromID, ToID: res.ToID, Source: source}
		if err != nil {
			e.Outcome, e.Cause = "failure", err.Error()
			var ie *InstallError
			if errors.As(err, &ie) {
				e.Step = ie.Step
			}
			e.ToID = idx.Latest.ID
		}
		if u.Audit == nil {
			return
		}
		aerr := u.Audit.AppendCVEUpdate(context.WithoutCancel(ctx), e)
		if aerr == nil {
			return
		}
		if err != nil {
			err = errors.Join(err, fmt.Errorf("audit row not written: %w", aerr))
		} else {
			res.AuditErr = aerr
		}
	}()

	if _, err := inst.Reconcile(); err != nil {
		return res, stepErr(StepPlan, err)
	}
	if err := os.RemoveAll(filepath.Join(u.Dir, "staging")); err != nil {
		return res, stepErr(StepPlan, err)
	}
	cur, curErr := inst.Status()
	if curErr != nil && !errors.Is(curErr, pkginstall.ErrNotInstalled) {
		return res, stepErr(StepPlan, curErr)
	}
	res.FromID = cur.InstalledID
	plan, err := PlanUpdate(idx, cur.InstalledID, u.MaxChain)
	if err != nil {
		return res, stepErr(StepPlan, err)
	}
	res.Plan = plan
	if checkPlan != nil {
		if err := checkPlan(plan); err != nil {
			return res, stepErr(StepPlan, err)
		}
	}
	if plan.UpToDate {
		res.Unchanged = true
		return res, nil
	}
	res.ToID = idx.Latest.ID
	if err := CheckDowngrade(cur.CreatedAt, idx.Latest.CreatedAt, u.AllowDowngrade); err != nil {
		return res, stepErr(StepPlan, err)
	}

	packs := packsFor(plan)
	if err := u.checkDisk(packs, cur.InstalledID != ""); err != nil {
		return res, stepErr(StepDisk, err)
	}

	staging, err := os.MkdirTemp(mkdirp(filepath.Join(u.Dir, "staging")), "run-")
	if err != nil {
		return res, stepErr(StepDownload, err)
	}
	defer os.RemoveAll(staging)

	paths := make([]string, len(packs))
	sigs := make([][]byte, len(packs))
	for i, p := range packs {
		if paths[i], sigs[i], err = fetch(ctx, staging, i, p); err != nil {
			return res, stepErr(StepDownload, err)
		}
		if err := u.step(StepDownload); err != nil {
			return res, stepErr(StepDownload, err)
		}
	}
	// Verify every pack before applying any.
	for i, p := range packs {
		if err := u.Verifier.VerifyPackFile(p.name, paths[i], p.sha, p.size, sigs[i]); err != nil {
			return res, stepErr(StepVerify, err)
		}
	}
	if err := u.step(StepVerify); err != nil {
		return res, stepErr(StepVerify, err)
	}

	work := &pkginstall.Installer{DataDir: filepath.Join(staging, "work"), PreSwap: checkSnapshotDir}
	if plan.Full {
		if _, err = work.Install(ctx, paths[0]); err != nil {
			return res, stepErr(applyStep(err), err)
		}
	} else {
		if err := seedWork(work.DataDir, u.Dir, cur); err != nil {
			return res, stepErr(StepApply, err)
		}
		for i := range packs {
			if _, err := work.Apply(ctx, paths[i], pkginstall.ApplyOptions{Threshold: 100_000_000}); err != nil {
				return res, stepErr(applyStep(err), err)
			}
		}
	}
	if err := u.step(StepApply); err != nil {
		return res, stepErr(StepApply, err)
	}
	st, err := work.Status()
	if err != nil {
		return res, stepErr(StepApply, err)
	}
	if st.InstalledID != idx.Latest.ID {
		return res, stepErr(StepApply, fmt.Errorf("applied packs produced snapshot %s, index says %s", st.InstalledID, idx.Latest.ID))
	}
	if err := u.step(StepSwap); err != nil {
		return res, stepErr(StepSwap, err)
	}
	if err := inst.Adopt(filepath.Join(work.DataDir, "snapshots", st.InstalledID), st); err != nil {
		return res, stepErr(StepSwap, err)
	}
	if res.State, err = inst.Status(); err != nil {
		return res, stepErr(StepSwap, err)
	}
	if u.State != nil {
		src := u.Source
		if src == "" {
			src = SourceDownload
		}
		res.StateErr = recordInstall(ctx, u.State, u.Dir, src, res, u.now())
	}
	return res, nil
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now().UTC()
	}
	return time.Now().UTC()
}

func (u *Updater) step(name string) error {
	if u.AfterStep == nil {
		return nil
	}
	return u.AfterStep(name)
}

func packsFor(p Plan) []packRef {
	if p.Full {
		s := p.Snapshot
		return []packRef{{"snapshot " + s.ID, s.URL, s.SigURL, s.SHA256, s.Size}}
	}
	out := make([]packRef, len(p.Deltas))
	for i, d := range p.Deltas {
		out[i] = packRef{"delta " + d.Base + "->" + d.Target, d.URL, d.SigURL, d.SHA256, d.Size}
	}
	return out
}

// applyStep classifies an installer error as an integrity failure (from the
// PreSwap check) or a plain apply failure.
func applyStep(err error) string {
	if errors.Is(err, ErrIntegrity) || errors.Is(err, ErrSchemaMismatch) || errors.Is(err, pkginstall.ErrUnsupportedSchema) {
		return StepIntegrity
	}
	return StepApply
}

func (u *Updater) checkDisk(packs []packRef, haveCurrent bool) error {
	var need uint64
	for _, p := range packs {
		if p.size > 0 {
			need += uint64(p.size) * diskFactor
		}
	}
	if haveCurrent {
		if fi, err := os.Stat(filepath.Join(u.Dir, "current", "graph.db")); err == nil && fi.Size() > 0 {
			need += uint64(fi.Size()) // delta apply copies the base database
		}
	}
	free := u.FreeBytes
	if free == nil {
		free = freeBytes
	}
	if err := os.MkdirAll(u.Dir, 0o755); err != nil {
		return err
	}
	have, err := free(u.Dir)
	if err != nil {
		return fmt.Errorf("checking free space: %w", err)
	}
	if have < need {
		return fmt.Errorf("%w: need about %d bytes, have %d", ErrDiskSpace, need, have)
	}
	return nil
}

// download fetches a pack and its detached signature. The pack is streamed to
// staging with a limit of the size recorded in the signed index.
func (u *Updater) download(ctx context.Context, staging string, i int, p packRef) (string, []byte, error) {
	if p.size <= 0 {
		return "", nil, &PackError{p.name, errors.New("index records no size")}
	}
	sigRef := p.sigURL
	if sigRef == "" {
		sigRef = p.url + pkgSigSuffix
	}
	resp, err := u.Client.FetchPack(ctx, p.url)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", p.name, err)
	}
	defer resp.Body.Close()
	if resp.Length > p.size {
		return "", nil, &PackError{p.name, fmt.Errorf("%w: server announces %d bytes, index says %d", ErrPackSize, resp.Length, p.size)}
	}
	path := filepath.Join(staging, "pack-"+strconv.Itoa(i)+".tar.gz")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, p.size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", nil, fmt.Errorf("%s: %w", p.name, err)
	}
	if n != p.size {
		os.Remove(path)
		return "", nil, &PackError{p.name, fmt.Errorf("%w: received %d bytes, index says %d", ErrPackSize, n, p.size)}
	}
	sr, err := u.Client.FetchPack(ctx, sigRef)
	if err != nil {
		os.Remove(path)
		return "", nil, fmt.Errorf("%s signature: %w", p.name, err)
	}
	defer sr.Body.Close()
	sig, err := io.ReadAll(io.LimitReader(sr.Body, maxSigBytes+1))
	if err != nil || len(sig) > maxSigBytes {
		os.Remove(path)
		if err == nil {
			err = errors.New("signature file too large")
		}
		return "", nil, &PackError{p.name, err}
	}
	return path, sig, nil
}

const pkgSigSuffix = ".sig"

// seedWork prepares a staging data directory that holds the installed
// snapshot, so a delta chain can be applied there without touching dataDir.
func seedWork(workDir, dataDir string, cur pkginstall.State) error {
	snap := filepath.Join(workDir, "snapshots", cur.InstalledID)
	if err := os.MkdirAll(snap, 0o755); err != nil {
		return err
	}
	for _, n := range []string{"graph.db", "manifest.json"} {
		if err := linkOrCopy(filepath.Join(dataDir, "snapshots", cur.InstalledID, n), filepath.Join(snap, n)); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workDir, "state.json"), b, 0o644); err != nil {
		return err
	}
	return os.Symlink(filepath.Join("snapshots", cur.InstalledID), filepath.Join(workDir, "current"))
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func mkdirp(p string) string {
	_ = os.MkdirAll(p, 0o755)
	return p
}

// checkSnapshotDir runs SQLite's integrity check on dir/graph.db and rejects a
// schema version this build cannot read.
func checkSnapshotDir(ctx context.Context, dir string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "graph.db")+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: %s", ErrIntegrity, res)
	}
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&raw); err != nil {
		return fmt.Errorf("%w: reading meta.schema_version: %v", ErrSchemaMismatch, err)
	}
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err != nil || v < 1 || v > intel.MaxSchemaVersion {
		return fmt.Errorf("%w: %q (this build supports up to %d)", ErrSchemaMismatch, raw, intel.MaxSchemaVersion)
	}
	return nil
}
