package findings

import (
	"context"
	"sync"
)

// JobSink is the per-scan-job writer for scanners. It has the method set of
// scanners.Sink and scanners.JobSink except ResolveMissing, which takes the
// asset id and source name as strings so that findings need not import
// scanners. The orchestrator maps (Target, Kind) to those strings.
type JobSink struct {
	store *Store
	ctx   context.Context
	scan  ScanRef

	mu              sync.Mutex
	seen            map[string]struct{}
	created, update int
}

// JobSink returns a sink for one scan job. ctx bounds its writes.
func (s *Store) JobSink(ctx context.Context, scan ScanRef) *JobSink {
	return &JobSink{store: s, ctx: ctx, scan: scan, seen: map[string]struct{}{}}
}

// Findings reports fs and marks each id as seen, including ids of a batch
// that failed later, which keeps a failed report from resolving them.
func (j *JobSink) Findings(fs []Finding) error {
	j.mu.Lock()
	for _, f := range fs {
		j.seen[f.ID] = struct{}{}
	}
	j.mu.Unlock()
	res, err := j.store.Report(j.ctx, j.scan, fs)
	j.mu.Lock()
	j.created += res.Created
	j.update += res.Updated + res.Reopened
	j.mu.Unlock()
	return err
}

// ScannerError records a Scanner_Error_Row for the job.
func (j *JobSink) ScannerError(input, cause string) error {
	return j.store.ScannerError(j.ctx, j.scan, input, cause)
}

// Seen marks a finding id as observed without reporting it.
func (j *JobSink) Seen(id string) {
	j.mu.Lock()
	j.seen[id] = struct{}{}
	j.mu.Unlock()
}

// ResolveMissing resolves open and in_progress findings of (asset, source)
// that this job did not report or mark seen.
func (j *JobSink) ResolveMissing(ctx context.Context, asset, source string) (int, error) {
	j.mu.Lock()
	seen := make(map[string]struct{}, len(j.seen))
	for id := range j.seen {
		seen[id] = struct{}{}
	}
	j.mu.Unlock()
	return j.store.ResolveMissing(ctx, j.scan, asset, source, seen)
}

// Counts returns findings created and updated (including reopened) so far.
func (j *JobSink) Counts() (created, updated int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.created, j.update
}
