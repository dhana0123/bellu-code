package collectors_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
)

type statusErr int

func (e statusErr) Error() string   { return "status" }
func (e statusErr) HTTPStatus() int { return int(e) }

func noSleep() collectors.ProbeOption {
	return collectors.WithProbeSleep(func(context.Context, time.Duration) error { return nil })
}

func TestProbeKindsAfterThreeFailures(t *testing.T) {
	for _, c := range []struct {
		err  error
		kind string
	}{{statusErr(401), collectors.ProbeCredentialsRejected}, {errors.New("dial"), collectors.ProbeEndpointUnreachable}} {
		calls := 0
		err := collectors.Probe(context.Background(), func(context.Context) error { calls++; return c.err }, noSleep())
		var pe *collectors.ProbeError
		if !errors.As(err, &pe) || pe.Kind != c.kind || calls != 3 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	}
}

func TestProbeSucceedsAfterTransientFailure(t *testing.T) {
	calls := 0
	err := collectors.Probe(context.Background(), func(context.Context) error {
		if calls++; calls < 3 {
			return errors.New("flaky")
		}
		return nil
	}, noSleep())
	if err != nil {
		t.Fatal(err)
	}
}

func TestStatusRecorderFailTypeClassifiesAndDedupes(t *testing.T) {
	var r collectors.StatusRecorder
	r.FailType("buckets", "proj-a", statusErr(403))
	r.FailType("buckets", "proj-a", errors.New("x"))
	r.FailType("disks", "proj-a", errors.New("x"))
	st := r.Status()
	if len(st.Gaps) != 2 || st.Gaps[0].Reason != collectors.GapMissingPermission || st.Gaps[1].Reason != collectors.GapFailedCall || len(st.DeniedScopes) != 1 {
		t.Fatalf("%+v", st)
	}
}
