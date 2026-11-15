package overlay

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoesNotImportFacade(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if strings.Contains(p, "bellugraph") || strings.Contains(p, "net/http") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
