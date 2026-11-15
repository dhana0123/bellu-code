package connectors

// Architecture import-graph tests (Requirements 5.4, 16.1, 6.12).
//
// These use go/parser over the bellud module directory rather than
// golang.org/x/tools/go/packages: x/tools is only an indirect dependency, and
// the rules below are purely syntactic (imports and selector expressions), so
// parsing is sufficient and keeps go.mod unchanged.

import (
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
	vaultImport = "github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	awsSDKRoot  = "github.com/aws/aws-sdk-go-v2"
)

// parsedFile is a non-test Go source file with its path relative to the
// bellud module root (slash separated).
type parsedFile struct {
	rel  string
	file *ast.File
}

func (p parsedFile) imports() map[string]string { // import path -> local name
	out := map[string]string{}
	for _, im := range p.file.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := filepath.Base(path)
		if im.Name != nil {
			name = im.Name.Name
		}
		out[path] = name
	}
	return out
}

func parseModule(t *testing.T) []parsedFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []parsedFile
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, parsedFile{rel: filepath.ToSlash(rel), file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func find(files []parsedFile, rel string) (parsedFile, bool) {
	for _, f := range files {
		if f.rel == rel {
			return f, true
		}
	}
	return parsedFile{}, false
}

// (a) Collectors reach providers only through their Client interface: they
// must not import net/http or any aws-sdk-go-v2 package.
func TestArchCollectorsDoNotImportHTTPOrAWSSDK(t *testing.T) {
	files := parseModule(t)
	for _, rel := range []string{
		"internal/connectors/aws/collector.go",
		"internal/connectors/github/collector.go",
	} {
		pf, ok := find(files, rel)
		if !ok {
			t.Fatalf("%s not found", rel)
		}
		for path := range pf.imports() {
			if path == "net/http" || strings.HasPrefix(path, "net/http/") ||
				path == awsSDKRoot || strings.HasPrefix(path, awsSDKRoot+"/") {
				t.Errorf("%s imports %q; collectors must stay transport- and SDK-free", rel, path)
			}
		}
	}
}

// (b) Only these files may import the vault package. Exceptions, precisely:
//   - broker/*: the Opener is the broker's credential-injection source.
//   - lifecycle/{manager,supervisor,authconfig}.go: credential lifecycle
//     (store, rotate, forget) and provider auth config assembly.
//   - deviceflow/refresh.go, gcp/provider.go: use vault types (Ref, Opener)
//     in interfaces only; they never construct or open the store.
//   - connectors/service.go: wiring only; it constructs the vault.Store
//     (vault.Open) and reads its own non-credential slots (params,
//     external-id) via Vault.Use when preparing auth config.
//
// Provider packages (aws, github), collectors, policy, store, etc. must not.
func TestArchVaultImportedOnlyByAllowedFiles(t *testing.T) {
	allowed := map[string]bool{
		"internal/connectors/service.go":              true,
		"internal/connectors/broker/broker.go":        true,
		"internal/connectors/broker/auth.go":          true, // vault.ErrNotFound/ErrDecrypt sentinels
		"internal/connectors/deviceflow/refresh.go":   true, // vault.Ref in the token-store interface
		"internal/connectors/gcp/provider.go":         true, // vault.Opener type; Use stays with the broker
		"internal/connectors/lifecycle/manager.go":    true,
		"internal/connectors/lifecycle/supervisor.go": true,
		"internal/connectors/lifecycle/authconfig.go": true,
	}
	seen := map[string]bool{}
	for _, pf := range parseModule(t) {
		if strings.HasPrefix(pf.rel, "internal/connectors/vault/") {
			continue // the vault package itself
		}
		if _, ok := pf.imports()[vaultImport]; !ok {
			continue
		}
		seen[pf.rel] = true
		if !allowed[pf.rel] {
			t.Errorf("%s imports the vault package; allowed only in broker, lifecycle and connectors/service.go", pf.rel)
		}
	}
	var stale []string
	for rel := range allowed {
		if !seen[rel] {
			stale = append(stale, rel)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Logf("allowlist entries that no longer import vault (consider removing): %v", stale)
	}
}

// Provider and collector code must also never call Use on anything: secrets
// are opened only by the broker/lifecycle.
func TestArchProvidersNeverOpenSecrets(t *testing.T) {
	for _, pf := range parseModule(t) {
		if !isProviderFile(pf.rel) {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Use" {
					t.Errorf("%s calls .Use(...); only broker and lifecycle may open vault secrets", pf.rel)
				}
			}
			return true
		})
	}
}

func isProviderFile(rel string) bool {
	return strings.HasPrefix(rel, "internal/connectors/aws/") || strings.HasPrefix(rel, "internal/connectors/github/")
}

// (c) Provider clients get their *http.Client from broker.HTTPClient; aws and
// github non-test code must not construct or use ambient HTTP clients.
func TestArchProviderClientsOnlyFromBroker(t *testing.T) {
	banned := map[string]bool{
		"DefaultClient": true, "DefaultTransport": true,
		"Get": true, "Post": true, "Head": true, "PostForm": true,
	}
	for _, pf := range parseModule(t) {
		if !isProviderFile(pf.rel) {
			continue
		}
		name, ok := pf.imports()["net/http"]
		if !ok {
			continue
		}
		isHTTP := func(e ast.Expr) bool {
			id, ok := e.(*ast.Ident)
			return ok && id.Name == name
		}
		isType := func(e ast.Expr, typ string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			return ok && isHTTP(sel.X) && sel.Sel.Name == typ
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if isHTTP(x.X) && banned[x.Sel.Name] {
					t.Errorf("%s uses http.%s; obtain clients from broker.HTTPClient", pf.rel, x.Sel.Name)
				}
			case *ast.CompositeLit:
				if isType(x.Type, "Client") || isType(x.Type, "Transport") {
					t.Errorf("%s builds a http.Client/Transport literal; obtain clients from broker.HTTPClient", pf.rel)
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 &&
					(isType(x.Args[0], "Client") || isType(x.Args[0], "Transport")) {
					t.Errorf("%s calls new(http.Client/Transport); obtain clients from broker.HTTPClient", pf.rel)
				}
			}
			return true
		})
	}
}
