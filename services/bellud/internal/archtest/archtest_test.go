// Package archtest holds architecture tests over the bellud import graph and
// source (Requirements 21.2, 17.19, 23.11). It uses go/parser rather than
// x/tools/go/packages because the rules are syntactic (imports and selector
// expressions), which keeps go.mod unchanged.
package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath = "github.com/bellu/bellucode/services/bellud"
	vaultPkg   = "internal/connectors/vault"
	scannerPfx = "internal/scanners/"
)

// httpAllowed lists package directories (relative to services/bellud, slash
// separated, prefix match on path segments) permitted to construct an
// outbound net/http client.
//
// Permanent entries are the packages the spec names (Requirement 23.11):
// the BSKG client, the intel updater, cveupdate and the configured LLM
// client. A new package must not be added here without a spec change.
//
// Legacy entries are packages that already construct clients on the current
// tree. They are tolerated so the test passes today; each has a reason.
// Do not grow this list: new code should receive a *http.Client from
// connectors/broker or one of the permanent packages.
var httpAllowed = map[string]string{
	// Permanent (Requirement 23.11).
	"internal/bskg":      "BSKG client",
	"internal/intel":     "intel updater",
	"internal/cveupdate": "CVE updater",
	"internal/llm":       "configured LLM client",

	// Legacy, present before this test.
	"internal/seek/bskg":         "legacy: BSKG client for seek (loopback/BSKG)",
	"internal/connectors/broker": "legacy: the single factory for connector HTTP clients (egress allow-listing)",
	"internal/retrieval":         "legacy: loopback retrieval service client",
	"internal/collectors/docker": "legacy: local Docker socket client",
	"internal/tschild":           "legacy: loopback health probe of the TypeScript child",
	"internal/contract":          "legacy: contract stage checks calling the local server via http.DefaultClient",
	"internal/openapi":           "legacy: OpenAPI fetcher falling back to http.DefaultClient",
	// Loopback only: the design has `bellud security` call the local server's
	// experimental HTTP API when it is running.
	"cmd/bellud": "loopback: security CLI calling the local bellud HTTP API",
}

func underAllowed(dir string) (string, bool) {
	for p, why := range httpAllowed {
		if dir == p || strings.HasPrefix(dir, p+"/") {
			return why, true
		}
	}
	return "", false
}

type srcFile struct {
	dir  string // package dir relative to module root
	rel  string // file path relative to module root
	file *ast.File
}

// parseModule parses every non-test Go file under services/bellud.
func parseModule(t *testing.T) []srcFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []srcFile
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "testdata", "dist", ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		out = append(out, srcFile{dir: filepath.ToSlash(filepath.Dir(rel)), rel: rel, file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func importPaths(f *ast.File) map[string]string { // path -> local name
	m := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := filepath.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		m[p] = name
	}
	return m
}

func isScanner(dir string) bool {
	return strings.HasPrefix(dir, scannerPfx) || dir == strings.TrimSuffix(scannerPfx, "/")
}

// Requirements 21.2, 17.19: no scanner adapter may import the vault.
func TestScannersDoNotImportVault(t *testing.T) {
	var bad []string
	for _, f := range parseModule(t) {
		if !isScanner(f.dir) {
			continue
		}
		for p := range importPaths(f.file) {
			if p == modulePath+"/"+vaultPkg || strings.HasPrefix(p, modulePath+"/"+vaultPkg+"/") {
				bad = append(bad, fmt.Sprintf("package %s (%s) imports %s", f.dir, f.rel, p))
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

// httpUses returns descriptions of outbound net/http client construction or
// default-client use in f.
func httpUses(f *ast.File) []string {
	local, ok := importPaths(f)["net/http"]
	if !ok || local == "_" || local == "." {
		return nil
	}
	isHTTP := func(e ast.Expr, name string) bool {
		s, ok := e.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != name {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Name == local
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if isHTTP(x.Type, "Client") {
				out = append(out, "constructs http.Client")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 && isHTTP(x.Args[0], "Client") {
				out = append(out, "constructs http.Client via new")
			}
			for _, fn := range []string{"Get", "Head", "Post", "PostForm"} {
				if isHTTP(x.Fun, fn) {
					out = append(out, "calls http."+fn+" (default client)")
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil && isHTTP(x.Type, "Client") {
				out = append(out, "declares http.Client value")
			}
		case *ast.SelectorExpr:
			if isHTTP(x, "DefaultClient") {
				out = append(out, "uses http.DefaultClient")
			}
		}
		return true
	})
	return out
}

// Requirement 23.11: only the allow-listed packages make outbound HTTP calls.
func TestOutboundHTTPClientsAllowListed(t *testing.T) {
	var bad []string
	used := map[string]bool{}
	for _, f := range parseModule(t) {
		uses := httpUses(f.file)
		if len(uses) == 0 {
			continue
		}
		if _, ok := underAllowed(f.dir); ok {
			used[f.dir] = true
			continue
		}
		for _, u := range uses {
			bad = append(bad, fmt.Sprintf("package %s (%s) %s; allowed only in %s", f.dir, f.rel, u, allowedList()))
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
	if !t.Failed() {
		dirs := make([]string, 0, len(used))
		for d := range used {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)
		t.Logf("packages currently constructing http clients: %s", strings.Join(dirs, ", "))
	}
}

func allowedList() string {
	var l []string
	for p := range httpAllowed {
		l = append(l, p)
	}
	sort.Strings(l)
	return strings.Join(l, ", ")
}
