// Package schemaall lists every source declaration and holds the merged
// registry. Adding a source means adding its Declaration to Sources.
package schemaall

import (
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/github/githubschema"
	"github.com/bellu/bellucode/services/bellud/internal/correlate/corrschema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/codeschema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/coreschema"
)

// Sources returns the declaration of every source.
func Sources() []schema.SourceDeclaration {
	return []schema.SourceDeclaration{
		coreschema.Declaration(),
		githubschema.Declaration(),
		awsschema.Declaration(),
		corrschema.Declaration(),
		codeschema.Declaration(),
	}
}

var (
	once sync.Once
	reg  *schema.Registry
	err  error
)

// Default merges Sources once and returns the registry, or the merge error.
func Default() (*schema.Registry, error) {
	once.Do(func() { reg, err = schema.MergeRequired(map[schema.Source]schema.Requirement{schema.SourceAWS: awsschema.Required}, Sources()...) })
	return reg, err
}
