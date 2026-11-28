package scanners

import (
	"context"
	"errors"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// ErrNoGraphIngest is returned by Batch when the sink was built without a
// graph ingest function.
var ErrNoGraphIngest = errors.New("scanners: sink has no graph ingest")

// FindingsSink adapts a findings.JobSink to JobSink. The findings package does
// not import scanners, so its ResolveMissing takes the asset id and source
// name as strings; this maps (Target, Kind) to them.
//
// Ingest applies a graph batch, for example through the engine's Ingest().Apply.
// It is passed at construction so that scanners does not import the engine.
type FindingsSink struct {
	*findings.JobSink
	Ingest func(batch.Batch) error
}

var _ JobSink = FindingsSink{}

// ResolveMissing implements JobSink.
func (s FindingsSink) ResolveMissing(ctx context.Context, t Target, k Kind) (int, error) {
	return s.JobSink.ResolveMissing(ctx, t.ID, string(k))
}

// Batch implements Sink by calling Ingest.
func (s FindingsSink) Batch(b batch.Batch) error {
	if s.Ingest == nil {
		return ErrNoGraphIngest
	}
	return s.Ingest(b)
}
