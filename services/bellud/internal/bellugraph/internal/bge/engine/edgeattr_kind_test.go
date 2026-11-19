package engine

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
)

func TestRelationUpdatedIsRelationChange(t *testing.T) {
	k, s, ok := changeKindSubject(codec.RelationUpdated)
	if !ok || k != ChangeChanged || s != SubjectRelation {
		t.Fatalf("got %v %v %v", k, s, ok)
	}
}
