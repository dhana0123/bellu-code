package broker

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"pgregory.net/rapid"
)

// denyAudit records how many requests had reached the transport when each
// entry was appended, proving the audit is written before any send.
type denyAudit struct {
	rt     *countingRT
	mu     sync.Mutex
	es     []audit.Entry
	sentAt []int32
}

func (a *denyAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e)
	a.sentAt = append(a.sentAt, a.rt.n.Load())
	return nil
}
func (a *denyAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (a *denyAudit) Prune(time.Time, int) error                   { return nil }

func newDenyBroker() (*Broker, *countingRT, *denyAudit) {
	rt := &countingRT{fn: respond(200, `{}`)}
	a := &denyAudit{rt: rt}
	return New(Config{Opener: fakeOpener{secret: token}, Audit: a, Redactor: redactor.New(), Inner: rt, RatePerSecond: 10000, AgentGate: allowAgents{}}), rt, a
}

// Feature: cloud-connectors, Property 7: Policy decision equals allowlist
// membership (broker part).
// **Validates: Requirements 5.2, 12.4, 16.6**
func TestPropertyBrokerDenyMatchesAllowlist(t *testing.T) {
	ref := newRef(t, AuthGitHubToken)
	rapid.Check(t, func(t *rapid.T) {
		owner := rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "owner")
		repo := rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "repo")
		scheme := rapid.SampledFrom([]string{"https", "http"}).Draw(t, "scheme")
		method := rapid.SampledFrom([]string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}).Draw(t, "method")
		host := rapid.SampledFrom([]string{"api.github.com", "evil.example.com", "github.com", "sts.us-east-1.amazonaws.com", "api.github.com.evil.io"}).Draw(t, "host")
		path := rapid.SampledFrom([]string{"/repos/" + owner + "/" + repo, "/big", "/user/keys", "/repos/" + owner, "/repos/" + owner + "/" + repo + "/x", "/"}).Draw(t, "path")
		caller := rapid.SampledFrom([]string{policy.CallerCollector, policy.CallerLifecycle, "agent:p"}).Draw(t, "caller")

		wantAllow := scheme == "https" && method == "GET" && host == "api.github.com" &&
			(path == "/big" || path == "/repos/"+owner+"/"+repo)

		b, rt, a := newDenyBroker()
		req, err := http.NewRequest(method, scheme+"://"+host+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := b.HTTPClient(ref, caller).Do(req)
		if wantAllow {
			if err != nil {
				t.Fatalf("allowed request failed: %v", err)
			}
			resp.Body.Close()
			if rt.n.Load() != 1 || len(a.es) != 0 {
				t.Fatalf("allowed: n=%d audit=%d", rt.n.Load(), len(a.es))
			}
			return
		}
		var be *BlockedError
		if !errors.As(unwrapClientError(err), &be) {
			t.Fatalf("want BlockedError, got %v", err)
		}
		if rt.n.Load() != 0 {
			t.Fatalf("denied request reached transport: %d", rt.n.Load())
		}
		if len(a.es) != 1 || a.sentAt[0] != 0 {
			t.Fatalf("audit entries: %+v", a.es)
		}
		e := a.es[0]
		if e.Event != audit.EventBlockedOperation || e.Outcome != audit.OutcomeBlocked || e.ConnectionID != "c1" ||
			e.Detail["caller"] != caller || e.Detail["violated"] == "" {
			t.Fatalf("audit entry: %+v", e)
		}
	})
}

// Unresolved or unlisted operations, and auth-class operations for non-lifecycle
// callers, are denied by Do with zero outbound requests.
// **Validates: Requirements 5.2, 12.4, 16.6**
func TestPropertyDoDeniesUnresolvedOperations(t *testing.T) {
	ref := newRef(t, AuthGitHubToken)
	rapid.Check(t, func(t *rapid.T) {
		op := rapid.OneOf(
			rapid.Just("sts:GetCallerIdentity"),
			rapid.Just(""),
			rapid.StringMatching(`[A-Za-z:/{} ]{0,24}`),
		).Draw(t, "operation")
		if op == "GET /repos/{o}/{r}" || op == "GET /big" {
			return
		}
		caller := rapid.SampledFrom([]string{policy.CallerCollector, "agent:p"}).Draw(t, "caller")
		b, rt, a := newDenyBroker()
		_, err := b.Do(context.Background(), Call{Connection: ref, Caller: caller, Operation: op,
			Params: map[string]any{"o": "a", "r": "b"}})
		var be *BlockedError
		if !errors.As(err, &be) {
			t.Fatalf("op %q: want BlockedError, got %v", op, err)
		}
		if rt.n.Load() != 0 || len(a.es) != 1 || a.sentAt[0] != 0 || !strings.Contains(a.es[0].Detail["caller"], caller) {
			t.Fatalf("op %q: n=%d audit=%+v", op, rt.n.Load(), a.es)
		}
	})
}
