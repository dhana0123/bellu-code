package cveupdate

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// CLIWorkspace is the workspace whose database holds cve_update_state and the
// audit rows until multiple workspaces are selectable from the command line.
const CLIWorkspace = "default"

// CLIEnv is what the `cve` command needs from its caller.
type CLIEnv struct {
	DataDir string     // bellud data directory; the snapshots live in <DataDir>/cve
	Config  config.CVE // cve.* keys
	Version string     // bellucode version, for the User-Agent
	Stdout  io.Writer
	Stderr  io.Writer
}

const cveUsage = "usage: bellud cve update [--mirror URL] [--allow-downgrade]\n" +
	"       bellud cve status\n" +
	"       bellud cve import FILE [--sig FILE] [--allow-downgrade]"

// RunCLI runs `cve update`, `cve status` or `cve import`. These are the only
// commands that can reach the CVE host, and only `update` does; `status` and
// `import` make no network request, and with cve.auto_update off nothing else
// does either. It returns a non-nil error for a non-zero exit status.
func RunCLI(ctx context.Context, args []string, env CLIEnv) error {
	if len(args) == 0 {
		return errors.New(cveUsage)
	}
	switch args[0] {
	case "update", "status", "import":
		return runCommand(ctx, args[0], args[1:], env)
	}
	return fmt.Errorf("unknown cve command %q\n%s", args[0], cveUsage)
}

func runCommand(ctx context.Context, cmd string, args []string, env CLIEnv) error {
	fs := flag.NewFlagSet("cve "+cmd, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	var mirror, sig string
	var allowDowngrade bool
	if cmd == "update" {
		fs.StringVar(&mirror, "mirror", "", "use this mirror instead of the default host (overrides cve.mirror_url)")
	}
	if cmd != "status" {
		fs.BoolVar(&allowDowngrade, "allow-downgrade", false, "accept a snapshot built before the installed one")
	}
	if cmd == "import" {
		fs.StringVar(&sig, "sig", "", "detached signature file (default FILE.sig)")
	}
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if want := map[string]int{"update": 0, "status": 0, "import": 1}[cmd]; len(files) != want {
		return fmt.Errorf("cve %s takes %d argument(s), got %d\n%s", cmd, want, len(files), cveUsage)
	}
	if mirror != "" {
		if err := config.ValidateMirrorURL(mirror); err != nil {
			return err
		}
	}

	store, err := sqlite.Open(ctx, env.DataDir, CLIWorkspace, sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		return fmt.Errorf("opening workspace store: %w", err)
	}
	defer store.Close()

	switch cmd {
	case "status":
		st, installed, err := LoadSyncStatus(ctx, store, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, FormatStatus(st, installed))
		return err
	case "import":
		verifier, err := NewPinnedVerifier()
		if err != nil {
			return err
		}
		up := &Updater{Dir: cveDir(env), Verifier: verifier, Audit: storeAudit{store}, State: store,
			Source: SourceImport, AllowDowngrade: allowDowngrade}
		res, err := up.ImportPack(ctx, files[0], sig)
		return report(env, res, err)
	}

	mirrorURL := env.Config.MirrorURL
	if mirror != "" {
		mirrorURL = mirror
	}
	client, err := New(Config{MirrorURL: mirrorURL, Version: env.Version,
		UserAgent: env.Config.UserAgent, UserAgentSet: env.Config.UserAgentSet})
	if err != nil {
		return err
	}
	verifier, err := NewPinnedVerifier()
	if err != nil {
		return err
	}
	source := SourceDownload
	if mirrorURL != "" {
		source = SourceMirror
	}
	up := &Updater{Dir: cveDir(env), Client: client, Verifier: verifier, Audit: storeAudit{store}, State: store,
		Source: source, MaxChain: env.Config.MaxChain, AllowDowngrade: allowDowngrade}
	res, err := up.Update(ctx)
	return report(env, res, err)
}

func cveDir(env CLIEnv) string { return filepath.Join(env.DataDir, "cve") }

// report prints the outcome. A failed audit or state write after a successful
// install is reported but does not undo the install.
func report(env CLIEnv, res Result, err error) error {
	if err != nil {
		return err
	}
	switch {
	case res.Unchanged:
		fmt.Fprintln(env.Stdout, "already up to date")
	default:
		fmt.Fprintf(env.Stdout, "installed %s\n", res.ToID)
	}
	for _, w := range []error{res.AuditErr, res.StateErr} {
		if w != nil {
			fmt.Fprintln(env.Stderr, "warning:", w)
		}
	}
	return nil
}

// parseInterspersed parses flags that may appear before or after positional
// arguments, returning the positional ones.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// storeAudit appends update rows to the workspace audit table.
type storeAudit struct{ s *sqlite.Store }

func (a storeAudit) AppendCVEUpdate(ctx context.Context, e AuditEntry) error {
	target := e.ToID
	if target == "" {
		target = "cve-snapshot"
	}
	outcome := e.Outcome
	if e.Outcome != "success" {
		outcome += " at " + e.Step + ": " + e.Cause
	}
	if e.Source != "" {
		outcome += " (" + e.Source + ")"
	}
	return a.s.Write(ctx, CLIWorkspace, func(tx *sql.Tx) error {
		return sqlite.AppendAudit(ctx, tx, CLIWorkspace, sqlite.AuditEntry{
			At: e.At, Actor: "cve-updater", Action: e.Action, Target: target, Outcome: outcome,
		})
	})
}
