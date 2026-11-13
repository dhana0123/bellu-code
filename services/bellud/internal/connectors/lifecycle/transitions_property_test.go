package lifecycle

import (
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// auditEntry is one audit record appended by the harness per requested change.
type auditEntry struct {
	prev, next Status
	at         time.Time
	rejected   bool
}

// harness applies requested changes through Next and audits each one, the
// same way the Manager must. The connection holds exactly one status field.
type harness struct {
	status Status
	audit  []auditEntry
}

func (h *harness) request(to Status, now time.Time) error {
	prev := h.status
	err := Next(prev, to)
	if err != nil {
		h.audit = append(h.audit, auditEntry{prev: prev, next: to, at: now, rejected: true})
		return err
	}
	h.status = to
	h.audit = append(h.audit, auditEntry{prev: prev, next: to, at: now})
	return nil
}

// Feature: cloud-connectors, Property 10: Lifecycle transitions
// Validates: Requirements 2.3, 14.1, 14.8, 14.9
func TestPropertyLifecycleTransitions(t *testing.T) {
	// Independent oracle: the Req 14.9 list written out as pairs.
	allowed := map[[2]Status]bool{
		{StatusInitiated, StatusVerifying}: true,
		{StatusVerifying, StatusActive}:    true,
		{StatusVerifying, StatusError}:     true,
		{StatusActive, StatusExpired}:      true,
		{StatusActive, StatusPaused}:       true,
		{StatusActive, StatusError}:        true,
		{StatusPaused, StatusActive}:       true,
		{StatusPaused, StatusError}:        true,
		{StatusExpired, StatusVerifying}:   true,
		{StatusError, StatusVerifying}:     true,
	}
	statusGen := rapid.SampledFrom(Statuses)
	rapid.Check(t, func(t *rapid.T) {
		h := &harness{status: statusGen.Draw(t, "start")}
		reqs := rapid.SliceOfN(statusGen, 0, 40).Draw(t, "requests")
		clock := time.Unix(1_700_000_000, 0)
		for i, to := range reqs {
			clock = clock.Add(time.Second)
			prev := h.status
			before := len(h.audit)
			err := h.request(to, clock)

			ok := allowed[[2]Status{prev, to}]
			if ok != (err == nil) {
				t.Fatalf("step %d %s->%s: allowed=%v err=%v", i, prev, to, ok, err)
			}
			if !ok && !errors.Is(err, ErrTransition) {
				t.Fatalf("step %d: rejection not ErrTransition: %v", i, err)
			}
			if ok && h.status != to {
				t.Fatalf("step %d: accepted but status=%s want %s", i, h.status, to)
			}
			if !ok && h.status != prev {
				t.Fatalf("step %d: rejected but status changed %s -> %s", i, prev, h.status)
			}
			if len(h.audit) != before+1 {
				t.Fatalf("step %d: want exactly one audit entry, got %d new", i, len(h.audit)-before)
			}
			e := h.audit[len(h.audit)-1]
			if e.prev != prev || e.next != to || !e.at.Equal(clock) || e.rejected == ok {
				t.Fatalf("step %d: bad audit entry %+v", i, e)
			}
			// Exactly one status, and it is a known one.
			n := 0
			for _, s := range Statuses {
				if h.status == s {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("step %d: status %q is not exactly one known status", i, h.status)
			}
		}
		if len(h.audit) != len(reqs) {
			t.Fatalf("audit entries %d != requests %d", len(h.audit), len(reqs))
		}
	})
}
