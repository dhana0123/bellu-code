// Package misconfig is the IaC misconfiguration scanner adapter. It runs the
// Trivy IaC scanners (Terraform, CloudFormation, Kubernetes, Helm, Dockerfile
// and Azure ARM) over a repository with the embedded trivy-checks bundle. No
// external process starts and nothing is fetched at scan time (Requirements
// 8.1 to 8.5, 8.9, 19.7).
package misconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"gopkg.in/yaml.v3"

	"github.com/bellu/bellucode/services/bellud/internal/collectors/iac"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/safeextract"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Name is the adapter name and the Finding source.
const Name = "misconfig"

// pinnedVersion is the Trivy version in go.mod.
const pinnedVersion = "v0.76.2"

// Engine is the Bellu-owned interface to an IaC scanner. Every Trivy IaC
// scanner satisfies it.
type Engine interface {
	ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error)
}

// Adapter implements scanners.Adapter.
type Adapter struct {
	// Limits bound the input read through safeextract; zero uses the defaults.
	Limits safeextract.Limits
	// engines builds the scanners; nil means the six Trivy IaC scanners.
	engines func() ([]Engine, error)
	// CustomDir is a directory of custom Rego checks loaded in addition to
	// the bundled ones (misconfig.custom_dir, Requirement 8.7).
	CustomDir string
}

var _ scanners.Adapter = Adapter{}

// New returns the misconfiguration adapter.
func New() Adapter { return Adapter{Limits: safeextract.DefaultLimits} }

// WithCustomDir returns the adapter loading the Rego checks of dir as well.
func (a Adapter) WithCustomDir(dir string) Adapter { a.CustomDir = dir; return a }

// trivyEngines builds the six scanners over one rego scanner that holds the
// embedded checks and libraries plus the custom checks of customDir. It uses
// no download. A custom directory that cannot be read, or a custom check that
// does not compile, is skipped and reported through warn (Requirement 8.10).
func trivyEngines(customDir string, warn func(input, cause string) error) ([]Engine, error) {
	custom, err := loadCustom(customDir, warn)
	if err != nil {
		return nil, err
	}
	rs, err := regoScanner(custom)
	if err != nil {
		return nil, fmt.Errorf("load embedded checks: %w", err)
	}
	o := rego.WithRegoScanner(rs)
	return []Engine{
		terraform.New(o), cloudformation.New(o), kubernetes.NewScanner(o),
		helm.New(o), dockerfile.NewScanner(o), arm.New(o),
	}, nil
}

var packageRe = regexp.MustCompile(`(?m)^package\s+([\w.]+)`)

type customCheck struct{ name, src string }

func regoScanner(custom []customCheck) (*rego.Scanner, error) {
	opts := []options.ScannerOption{rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true)}
	for _, c := range custom {
		opts = append(opts, rego.WithPolicyReader(strings.NewReader(c.src)))
		// Trivy only runs checks whose top-level package is a known namespace.
		if m := packageRe.FindStringSubmatch(c.src); m != nil {
			opts = append(opts, rego.WithPolicyNamespaces(strings.Split(m[1], ".")[0]))
		}
	}
	rs := rego.NewScanner(opts...)
	return rs, rs.LoadPolicies(nil)
}

// loadCustom reads the .rego files of dir and keeps those that compile with
// the bundled checks and the checks kept so far.
func loadCustom(dir string, warn func(input, cause string) error) ([]customCheck, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, warn(dir, "custom checks directory skipped: "+err.Error())
	}
	var kept []customCheck
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") || strings.HasSuffix(e.Name(), "_test.rego") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			if werr := warn(p, "custom check skipped: "+err.Error()); werr != nil {
				return nil, werr
			}
			continue
		}
		c := customCheck{name: p, src: string(b)}
		if _, err := regoScanner(append(slices.Clone(kept), c)); err != nil {
			if werr := warn(p, "custom check skipped: "+err.Error()); werr != nil {
				return nil, werr
			}
			continue
		}
		kept = append(kept, c)
	}
	return kept, nil
}

// Kind implements scanners.Adapter.
func (Adapter) Kind() scanners.Kind { return scanners.KindMisconfiguration }

// Applies implements scanners.Adapter.
func (Adapter) Applies(t scanners.TargetType) bool { return t == scanners.TargetRepository }

// Info implements scanners.Adapter.
func (Adapter) Info() scanners.Info {
	v := pinnedVersion
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/aquasecurity/trivy" && d.Version != "" {
				v = d.Version
			}
		}
	}
	return scanners.Info{Name: Name, Version: v, License: "Apache-2.0", Libraries: map[string]string{"trivy": v}}
}

func isIaCName(name string) bool {
	n := strings.ToLower(name)
	switch strings.ToLower(path.Ext(n)) {
	case ".tf", ".yaml", ".yml", ".json":
		return true
	}
	return n == "dockerfile" || strings.HasPrefix(n, "dockerfile.") || strings.HasSuffix(n, ".dockerfile")
}

func skipDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == ".terraform" || name == "vendor"
}

// iacFiles lists the IaC files of the tree, sorted.
func iacFiles(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if isIaCName(d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// Digest implements scanners.Adapter: SHA-256 over the sorted relative paths
// and contents of the IaC files.
func (a Adapter) Digest(ctx context.Context, t scanners.Target) (string, error) {
	if t.Type != scanners.TargetRepository {
		return "", nil
	}
	fsys, err := safeextract.DirFS(t.Path, a.Limits, nil)
	if err != nil {
		return "", err
	}
	files, err := iacFiles(fsys)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, p := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(h, "%s\x00%x\n", p, sum)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// hiddenFS hides the files that failed to parse from the scanners.
type hiddenFS struct {
	fs.FS
	hidden map[string]bool
}

func (h hiddenFS) Open(name string) (fs.File, error) {
	if h.hidden[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return h.FS.Open(name)
}

func (h hiddenFS) ReadDir(name string) ([]fs.DirEntry, error) {
	es, err := fs.ReadDir(h.FS, name)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(es, func(e fs.DirEntry) bool { return h.hidden[path.Join(name, e.Name())] }), nil
}

// parseCheck returns an error when a file with a syntax the adapter can check
// (.tf, .json, .yaml and .yml outside a Helm chart) does not parse.
func parseCheck(p string, data []byte, inChart bool) error {
	switch strings.ToLower(path.Ext(p)) {
	case ".tf":
		_, diags := hclsyntax.ParseConfig(data, p, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return errors.New(diags.Error())
		}
	case ".json":
		if !json.Valid(data) {
			return errors.New("invalid JSON")
		}
	case ".yaml", ".yml":
		if inChart {
			return nil // chart templates are not plain YAML
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var v any
			err := dec.Decode(&v)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Run implements scanners.Adapter.
func (a Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	fsys, err := safeextract.DirFS(t.Path, a.Limits, nil)
	if err != nil {
		return a.fail(out, t, err)
	}
	files, err := iacFiles(fsys)
	if err != nil {
		return a.fail(out, t, err)
	}
	charts := map[string]bool{}
	for _, p := range files {
		if strings.EqualFold(path.Base(p), "Chart.yaml") {
			charts[path.Dir(p)] = true
		}
	}
	hidden := map[string]bool{}
	for _, p := range files {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return a.fail(out, t, err)
		}
		if perr := parseCheck(p, data, inChart(charts, p)); perr != nil {
			hidden[p] = true
			if serr := out.ScannerError(p, "parse: "+perr.Error()); serr != nil {
				return serr
			}
		}
	}
	view := hiddenFS{FS: fsys, hidden: hidden}

	var engines []Engine
	if a.engines != nil {
		engines, err = a.engines()
	} else {
		engines, err = trivyEngines(a.CustomDir, out.ScannerError)
	}
	if err != nil {
		return a.fail(out, t, err)
	}
	var results scan.Results
	for _, e := range engines {
		rs, err := e.ScanFS(ctx, view, ".")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if serr := out.ScannerError(t.Path, fmt.Sprintf("%T: %v", e, err)); serr != nil {
				return serr
			}
			continue
		}
		results = append(results, rs...)
	}

	links := iacLinks(ctx, t.Path)
	fs, err := Convert(results, t, links)
	if err != nil {
		return a.fail(out, t, err)
	}
	return out.Findings(fs)
}

func (Adapter) fail(out scanners.Sink, t scanners.Target, cause error) error {
	if rerr := out.ScannerError(t.Path, cause.Error()); rerr != nil {
		return errors.Join(cause, rerr)
	}
	return cause
}

func inChart(charts map[string]bool, p string) bool {
	for d := path.Dir(p); ; d = path.Dir(d) {
		if charts[d] {
			return true
		}
		if d == "." || d == "/" {
			return false
		}
	}
}

// iacLinks maps "path\x00address" of each iac_resource the iac collector
// produces under root to its Entity_ID. It uses the collector's own identity.
func iacLinks(ctx context.Context, root string) map[string]string {
	b, err := iac.New(root).Collect(ctx)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range b.Entities {
		if e.Type != "iac_resource" {
			continue
		}
		id, err := identity.Hash("iac_resource", e.Identity)
		if err != nil {
			continue
		}
		out[e.Identity["path"]+"\x00"+e.Identity["address"]] = string(id)
	}
	return out
}
