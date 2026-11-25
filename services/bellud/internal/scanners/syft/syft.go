// Package syft is the Syft scanner adapter. It lists every package in a
// folder, image or host with the Syft library (no external process) so the
// product knows what software is installed (Requirements 5.1, 5.2, 5.3, 5.7,
// 5.12, 18.11).
//
// Only local sources are reachable: a directory, an OCI directory, an OCI
// archive or a docker archive. Registry and daemon image sources are not
// selected, and the network enrichment options of the catalogers (remote
// license lookup, Maven Central) are switched off.
package syft

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/safeextract"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
)

// pinnedVersion is the Syft version in go.mod (task 1.5). It is used when the
// build info does not list the module.
const pinnedVersion = "v1.57.2"

// Name is the adapter name.
const Name = "syft"

// ecosystemTags select the catalogers of the listed ecosystems: Go, npm,
// Python, Java, Rust, Ruby, PHP, .NET, apk, deb and rpm. Syft intersects them
// with its image or directory default set.
var ecosystemTags = []string{
	"go", "javascript", "python", "java", "rust", "ruby", "php", "dotnet", "apk", "dpkg", "rpm",
}

// imageSources are the local image providers Syft may try. Pull providers
// (registry, docker, podman, containerd) are not in the list.
var imageSources = []string{"docker-archive", "oci-archive", "oci-dir"}

// Adapter implements scanners.Adapter for Syft.
type Adapter struct {
	store   *sbomstore.Store
	timeout time.Duration
	scan    func(context.Context, scanners.Target) (bom.SBOM, error) // test hook; nil means Scan
}

// DefaultTimeout is the per-asset limit of one scan in Run (Requirement 5.15).
const DefaultTimeout = 600 * time.Second

// WithStore returns a copy of a whose Run saves each SBOM in st.
func (a Adapter) WithStore(st *sbomstore.Store) Adapter { a.store = st; return a }

// WithTimeout returns a copy of a whose Run limits one scan to d.
func (a Adapter) WithTimeout(d time.Duration) Adapter { a.timeout = d; return a }

var _ scanners.Adapter = Adapter{}

// New returns the Syft adapter.
func New() Adapter { return Adapter{} }

// Kind implements scanners.Adapter.
func (Adapter) Kind() scanners.Kind { return scanners.KindSBOM }

// Info implements scanners.Adapter. The version comes from the module build
// info, or the pinned constant when the build info has no entry.
func (Adapter) Info() scanners.Info {
	v := version()
	return scanners.Info{Name: Name, Version: v, License: "Apache-2.0", Libraries: map[string]string{"syft": v}}
}

func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return pinnedVersion
	}
	for _, d := range bi.Deps {
		if d.Path != "github.com/anchore/syft" {
			continue
		}
		if d.Replace != nil && d.Replace.Version != "" {
			return d.Replace.Version
		}
		if d.Version != "" {
			return d.Version
		}
	}
	return pinnedVersion
}

// Applies implements scanners.Adapter.
func (Adapter) Applies(t scanners.TargetType) bool {
	return t == scanners.TargetRepository || t == scanners.TargetImage || t == scanners.TargetHost
}

// Run scans the target within the per-asset timeout, saves the SBOM when the
// adapter has a store, and writes the package graph batch to out. On failure
// it records one scanner_error row, saves nothing (the previous snapshot
// stays) and returns an error that names the asset and the reason. A scan
// that exceeds the timeout is cancelled and recorded with the cause "timeout".
func (a Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	fail := func(cause error) error {
		if rerr := out.ScannerError(assetName(t), cause.Error()); rerr != nil {
			return errors.Join(cause, rerr)
		}
		return cause
	}
	limit := a.timeout
	if limit <= 0 {
		limit = DefaultTimeout
	}
	scan := a.scan
	if scan == nil {
		scan = a.Scan
	}
	sctx, cancel := context.WithTimeout(ctx, limit)
	s, err := scan(sctx, t)
	timedOut := sctx.Err() == context.DeadlineExceeded && ctx.Err() == nil
	cancel()
	if timedOut {
		return fail(fmt.Errorf("syft: asset %q: %s: scan exceeded %s: %w", assetName(t), scanners.ReasonTimeout, limit, context.DeadlineExceeded))
	}
	if err != nil {
		return fail(err)
	}
	b, err := Batch(t, s)
	if err != nil {
		return fail(fmt.Errorf("syft: asset %q: %w", assetName(t), err))
	}
	if a.store != nil {
		digest, _ := a.Digest(ctx, t) // best effort; empty when unavailable
		if err := a.store.Put(ctx, assetName(t), digest, s); err != nil {
			return fail(err)
		}
	}
	return out.Batch(b)
}

// Scan catalogs the target and returns its packages. Absent fields stay nil.
func (a Adapter) Scan(ctx context.Context, t scanners.Target) (bom.SBOM, error) {
	if !a.Applies(t.Type) {
		return bom.SBOM{}, fmt.Errorf("syft: asset %q: target type %q is not supported", assetName(t), t.Type)
	}
	if err := checkReadable(t); err != nil {
		return bom.SBOM{}, err
	}
	if isImage(t) {
		if err := validateImage(t); err != nil {
			return bom.SBOM{}, err
		}
	}
	src, err := openSource(ctx, t)
	if err != nil {
		return bom.SBOM{}, unreadable(t, err)
	}
	defer src.Close()

	s, err := syft.CreateSBOM(ctx, src, createConfig(t))
	if err != nil {
		return bom.SBOM{}, unreadable(t, err)
	}
	return bom.SBOM{Subject: assetName(t), Packages: mapPackages(s.Artifacts.Packages)}, nil
}

func assetName(t scanners.Target) string {
	if t.ID != "" {
		return t.ID
	}
	return t.Path
}

func isImage(t scanners.Target) bool { return t.Type == scanners.TargetImage }

// checkReadable fails fast, with a message that names the asset and the
// reason, when the path is missing or not readable.
func checkReadable(t scanners.Target) error {
	if t.Path == "" {
		return fmt.Errorf("syft: asset %q: no path to scan: %w", assetName(t), scanners.ErrTargetUnreachable)
	}
	fi, err := os.Stat(t.Path)
	if err != nil {
		return unreadable(t, err)
	}
	if fi.IsDir() {
		d, err := os.Open(t.Path)
		if err != nil {
			return unreadable(t, err)
		}
		return d.Close()
	}
	if !isImage(t) {
		return fmt.Errorf("syft: asset %q: %s is not a directory: %w", assetName(t), t.Path, scanners.ErrTargetUnreachable)
	}
	f, err := os.Open(t.Path)
	if err != nil {
		return unreadable(t, err)
	}
	return f.Close()
}

// unreadable wraps cause with the asset name. A missing or permission error
// also matches scanners.ErrTargetUnreachable.
func unreadable(t scanners.Target, cause error) error {
	if errors.Is(cause, os.ErrNotExist) || errors.Is(cause, os.ErrPermission) {
		return fmt.Errorf("syft: asset %q: cannot read %s: %v: %w", assetName(t), t.Path, cause, scanners.ErrTargetUnreachable)
	}
	return fmt.Errorf("syft: asset %q: cannot catalog %s: %w", assetName(t), t.Path, cause)
}

// openSource opens a local source only. The caller closes it.
func openSource(ctx context.Context, t scanners.Target) (source.Source, error) {
	if !isImage(t) {
		return directorysource.New(directorysource.Config{Path: t.Path})
	}
	return syft.GetSource(ctx, t.Path, syft.DefaultGetSourceConfig().WithSources(imageSources...))
}

// validateImage applies the safeextract bounds (Requirements 21.5, 21.6) to
// an image tar, or walks an OCI directory through the bounded FS, before Syft
// reads it. A violation fails the scan; Run records the scanner_error row.
func validateImage(t scanners.Target) error {
	fi, err := os.Stat(t.Path)
	if err != nil {
		return unreadable(t, err)
	}
	var verr error
	if fi.IsDir() {
		bfs, err := safeextract.DirFS(t.Path, ImageLimits, nil)
		if err != nil {
			return unreadable(t, err)
		}
		verr = fs.WalkDir(bfs, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			f, err := bfs.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(io.Discard, f)
			return err
		})
	} else {
		verr = safeextract.ValidateTarFile(t.Path, ImageLimits, nil)
	}
	if errors.Is(verr, safeextract.ErrViolation) {
		return fmt.Errorf("syft: asset %q: %s: %w", assetName(t), scanners.ReasonUnsafeInput, verr)
	}
	return nil // other read errors surface from Syft itself
}

// ImageLimits are the bounds applied to image input; tests lower them.
var ImageLimits = safeextract.DefaultLimits

func createConfig(t scanners.Target) *syft.CreateSBOMConfig {
	pk := pkgcataloging.DefaultConfig()
	pk.JavaArchive = pk.JavaArchive.WithUseNetwork(false).WithUseMavenLocalRepository(false)
	pk.Golang = pk.Golang.WithSearchRemoteLicenses(false)
	pk.JavaScript = pk.JavaScript.WithSearchRemoteLicenses(false)
	pk.Python = pk.Python.WithSearchRemoteLicenses(false)

	// A directory uses Syft's directory default set. An image uses the image
	// and directory sets together: Syft's image set leaves out lock files that
	// no installer has processed (for example package-lock.json), and the
	// product lists those packages too. The sub-selection keeps the listed
	// ecosystems only. No file catalogers run, and Syft keeps its default
	// parallelism (18.11).
	sel := cataloging.NewSelectionRequest().WithSubSelections(ecosystemTags...)
	if isImage(t) {
		sel = sel.WithDefaults(pkgcataloging.ImageTag, pkgcataloging.DirectoryTag)
	}
	return syft.DefaultCreateSBOMConfig().
		WithPackagesConfig(pk).
		WithoutFiles().
		WithCatalogerSelection(sel)
}

func mapPackages(c *pkg.Collection) []bom.Package {
	if c == nil {
		return nil
	}
	var out []bom.Package
	for _, p := range c.Sorted() {
		if p.Name == "" {
			continue
		}
		out = append(out, mapPackage(p))
	}
	return out
}

func mapPackage(p pkg.Package) bom.Package {
	b := bom.Package{Name: p.Name, Version: nonEmpty(p.Version), Purl: nonEmpty(p.PURL)}
	if p.PURL != "" {
		b.Ecosystem = purlType(p.PURL)
	}
	b.Licenses = licenses(p)
	b.Supplier = supplier(p.Metadata)
	b.Hashes = hashes(p.Metadata)

	var layers []string
	for _, l := range p.Locations.ToSlice() {
		if l.RealPath != "" && !slices.Contains(b.Locations, l.RealPath) {
			b.Locations = append(b.Locations, l.RealPath)
		}
		if l.FileSystemID != "" && !slices.Contains(layers, l.FileSystemID) {
			layers = append(layers, l.FileSystemID)
		}
	}
	slices.Sort(b.Locations)
	if len(layers) > 0 {
		slices.Sort(layers)
		b.Properties = map[string]string{"layer_digest": layers[0]}
	}
	return b
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// purlType returns the type of a package URL ("pkg:npm/x@1" gives "npm").
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(t)
}

func licenses(p pkg.Package) []string {
	var out []string
	for _, l := range p.Licenses.ToSlice() {
		v := l.SPDXExpression
		if v == "" {
			v = l.Value
		}
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// supplier reads the maintainer or vendor the package database records.
func supplier(m any) *string {
	switch v := m.(type) {
	case pkg.ApkDBEntry:
		return nonEmpty(v.Maintainer)
	case pkg.DpkgDBEntry:
		return nonEmpty(v.Maintainer)
	case pkg.RpmDBEntry:
		return nonEmpty(v.Vendor)
	}
	return nil
}

// hashes reads content hashes the metadata carries: archive digests of Java
// packages and the Cargo.lock checksum (SHA-256).
func hashes(m any) []bom.Hash {
	switch v := m.(type) {
	case pkg.JavaArchive:
		return fromDigests(v.ArchiveDigests)
	case pkg.RustCargoLockEntry:
		if v.Checksum != "" {
			return []bom.Hash{{Algorithm: "SHA-256", Value: v.Checksum}}
		}
	}
	return nil
}

var algorithmNames = map[string]string{"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}

func fromDigests(ds []file.Digest) []bom.Hash {
	var out []bom.Hash
	for _, d := range ds {
		name, ok := algorithmNames[strings.ToLower(strings.ReplaceAll(d.Algorithm, "-", ""))]
		if !ok || d.Value == "" {
			continue
		}
		out = append(out, bom.Hash{Algorithm: name, Value: d.Value})
	}
	return out
}
