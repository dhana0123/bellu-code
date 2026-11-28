package collectors

import (
	"context"
	"errors"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors/retry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Gap is one resource type or scope a collector could not read (missing_data).
type Gap = store.Gap

// Gap reasons, the values allowed by collector_gap.reason.
const (
	GapMissingPermission = "missing_permission"
	GapRateLimited       = "rate_limited"
	GapFailedCall        = "failed_call"
)

// ClassifyGap maps a failed call to a gap reason: exhausted retries are
// rate_limited, HTTP 401 and 403 are missing_permission, the rest failed_call.
func ClassifyGap(err error) string {
	var hs interface{ HTTPStatus() int }
	switch {
	case errors.Is(err, retry.ErrRateLimited):
		return GapRateLimited
	case errors.As(err, &hs) && (hs.HTTPStatus() == 401 || hs.HTTPStatus() == 403):
		return GapMissingPermission
	}
	return GapFailedCall
}

// FailType records a gap for one resource type that failed. scope is the project, subscription or
// cluster the type was read in. The reason comes from ClassifyGap. A missing
// permission also lands in DeniedScopes. Detail must not carry secrets.
func (r *StatusRecorder) FailType(resourceType, scope string, err error) {
	reason := ClassifyGap(err)
	r.Gap(Gap{ResourceType: resourceType, Scope: scope, Reason: reason, Detail: err.Error()})
	if reason == GapMissingPermission {
		r.Deny(scope)
	}
}

// Gap records a gap once per (resource type, scope); the first one wins.
func (r *StatusRecorder) Gap(g Gap) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.st.Gaps {
		if x.ResourceType == g.ResourceType && x.Scope == g.Scope {
			return
		}
	}
	r.st.Gaps = append(r.st.Gaps, g)
}

// GapSink persists the gaps of one run. The runner replaces all stored gaps of
// the collector with gaps (an empty slice clears them).
type GapSink func(ctx context.Context, collector string, gaps []Gap, runAt time.Time) error

// WithGapSink sets where the runner persists RunStatus.Gaps after each run
// (see sqlite.Store.ReplaceCollectorGaps). It is called for every collector
// that implements StatusReporter, also when the run failed.
func WithGapSink(f GapSink) Option { return func(r *Runner) { r.gapSink = f } }
