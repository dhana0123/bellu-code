// Package scanners orchestrates scan jobs: a FIFO queue on the scan_job table,
// a bounded worker pool, per-job timeouts and admission checks
// (Requirements 18.1 and 18.3 to 18.7, 18.13, 18.14, 22.9).
package scanners

import (
	"context"
	"errors"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Kind is a scan kind.
type Kind string

const (
	KindSBOM               Kind = "sbom"
	KindVulnerability      Kind = "vulnerability"
	KindMisconfiguration   Kind = "misconfiguration"
	KindSecret             Kind = "secret"
	KindPosture            Kind = "posture"
	KindDataClassification Kind = "data_classification"
	KindAIInventory        Kind = "ai_inventory"
)

// TargetType is the kind of thing a scan runs against.
type TargetType string

const (
	TargetRepository   TargetType = "repository"
	TargetImage        TargetType = "image"
	TargetHost         TargetType = "host"
	TargetCloudAccount TargetType = "cloud_account"
	TargetCluster      TargetType = "cluster"
)

// Target identifies what to scan. Path and Ref are filled in by
// Config.Resolve; they are not stored on the job.
type Target struct {
	Type TargetType
	ID   string
	Path string
	Ref  string
}

// Info describes a scanner adapter.
type Info struct {
	Name      string
	Version   string
	License   string
	Libraries map[string]string // pinned library versions
}

// Sink is what adapters write to. It is the only route to the findings store.
type Sink interface {
	// Findings reports findings produced by the scan.
	Findings(fs []findings.Finding) error
	// ScannerError records a Scanner_Error_Row for an input that could not be scanned.
	ScannerError(input, cause string) error
	// Seen marks a finding id as observed again, feeding ResolveMissing.
	Seen(findingID string)
	// Batch applies graph entities and relations (for example the packages of
	// an SBOM) in one batch. It returns an error when the sink has no graph
	// ingest, or when the graph rejects the batch, in which case nothing of it
	// is applied.
	Batch(b batch.Batch) error
}

// JobSink is the per-job Sink the orchestrator owns. It adds what the
// orchestrator needs on top of what adapters see.
type JobSink interface {
	Sink
	// ResolveMissing resolves open findings of this asset and scanner that the
	// job did not see. It returns the number resolved.
	ResolveMissing(ctx context.Context, t Target, scanner Kind) (resolved int, err error)
	// Counts returns the findings created and updated so far.
	Counts() (created, updated int)
}

// Adapter is a scanner implementation.
type Adapter interface {
	Kind() Kind
	Info() Info
	Applies(TargetType) bool
	// Digest returns a content digest of the target for skip-unchanged (18.8).
	// An error or an empty digest means the content cannot be compared, so the
	// job runs.
	Digest(ctx context.Context, t Target) (string, error)
	Run(ctx context.Context, t Target, out Sink) error
}

// Status is a scan job status.
type Status string

const (
	StatusQueued           Status = "queued"
	StatusRunning          Status = "running"
	StatusSucceeded        Status = "succeeded"
	StatusFailed           Status = "failed"
	StatusCancelled        Status = "cancelled"
	StatusSkippedUnchanged Status = "skipped_unchanged"
)

// Job reasons.
const (
	ReasonTimeout             = "timeout"
	ReasonUnsafeInput         = "unsafe_input"
	ReasonRestarted           = "restarted"
	ReasonShutdown            = "shutdown"
	ReasonTargetNotFound      = "target_not_found"
	ReasonTargetUnreachable   = "target_unreachable"
	ReasonCredentialsRejected = "credentials_rejected"
	ReasonScannerError        = "scanner_error"
	ReasonPanic               = "scanner_panic"
	ReasonResolveFailed       = "resolve_failed"
)

// Job is a row of scan_job.
type Job struct {
	ID              string
	Kind            Kind
	Target          Target
	Status          Status
	Reason          string
	QueuedAt        time.Time
	StartedAt       *time.Time
	EndedAt         *time.Time
	Created         int
	Updated         int
	Resolved        int
	ContentDigest   string
	ScannerVersions map[string]string
	Duration        *time.Duration // recorded for every job that ran, even past a time target (22.9)
}

// JobQuery filters List. Zero values mean no filter; Limit 0 means 100.
type JobQuery struct {
	Status Status
	Kind   Kind
	Limit  int
}

// Orchestrator is the scan queue API.
type Orchestrator interface {
	// Enqueue admits a job and returns it with status queued (18.1, 18.13).
	Enqueue(ctx context.Context, k Kind, t Target) (Job, error)
	// Cancel stops a queued or running job (18.7).
	Cancel(ctx context.Context, jobID string) error
	Get(ctx context.Context, id string) (Job, error)
	List(ctx context.Context, q JobQuery) ([]Job, error)
	// Schedule creates or replaces the recurring scan for (Kind, Target). The
	// interval must be 15 minutes to 30 days (18.12). The first run is one
	// interval from now.
	Schedule(ctx context.Context, s Schedule) error
}

// Schedule interval bounds (18.12).
const (
	MinScheduleInterval = 15 * time.Minute
	MaxScheduleInterval = 30 * 24 * time.Hour
)

// Schedule is a recurring scan. Enabled false stores the schedule paused.
type Schedule struct {
	Kind     Kind
	Target   Target
	Interval time.Duration
	Enabled  bool
}

// ErrInvalidInterval means a schedule interval is outside 15 minutes to 30 days.
var ErrInvalidInterval = errors.New("scanners: schedule interval must be 15 minutes to 30 days")

// Adapter errors that map to a specific failure reason (18.14).
var (
	ErrTargetUnreachable   = errors.New("scanners: target unreachable")
	ErrCredentialsRejected = errors.New("scanners: credentials rejected")
)

// Admission errors (18.13). Each Enqueue rejection wraps exactly one.
var (
	ErrKindNotApplicable = &AdmissionError{Code: "kind_not_applicable"}
	ErrTargetNotFound    = &AdmissionError{Code: "target_not_found"}
	ErrQueueFull         = &AdmissionError{Code: "queue_full"}
	// ErrJobNotFound means no job has the id.
	ErrJobNotFound = errors.New("scanners: job not found")
	// ErrNotCancellable means the job already finished.
	ErrNotCancellable = errors.New("scanners: job is not queued or running")
)

// MaxQueuedPerTarget is the admission limit of queued jobs per target (18.13).
const MaxQueuedPerTarget = 1000

// AdmissionError names which admission condition rejected a request.
type AdmissionError struct{ Code string }

func (e *AdmissionError) Error() string { return "scanners: request rejected: " + e.Code }

// Is matches on Code so errors.Is(err, ErrQueueFull) works.
func (e *AdmissionError) Is(target error) bool {
	t, ok := target.(*AdmissionError)
	return ok && t.Code == e.Code
}
