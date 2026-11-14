package connectors

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Feature: github-app-signin, Property 29: Startup reconcile expires exactly the credential-less Connections
//
// **Validates: Requirements 14.3**
func TestPropertyStartupReconcileExpiresExactlyCredentialLess(t *testing.T) {
	ctx := context.Background()
	eng := testEngine(t)
	root := t.TempDir()
	run := 0

	rapid.Check(t, func(rt *rapid.T) {
		run++
		dir := fmt.Sprintf("%s/run-%d", root, run)
		s := newSvc(t, dir, &memSource{slots: map[string][]byte{}}, eng, ghTransport{})
		defer s.Close(ctx)

		type spec struct {
			connector, method, status string
			removed, hasCred          bool
		}
		draw := rapid.Custom(func(rt *rapid.T) spec {
			sp := spec{
				status:  rapid.SampledFrom([]string{"ACTIVE", "PAUSED", "ERROR", "EXPIRED"}).Draw(rt, "status"),
				removed: rapid.Bool().Draw(rt, "removed"),
				hasCred: rapid.Bool().Draw(rt, "hasCred"),
			}
			if rapid.Bool().Draw(rt, "github") {
				sp.connector = "github"
				sp.method = rapid.SampledFrom([]string{"pat", "device", "pat", "device", "app", ""}).Draw(rt, "ghMethod")
			} else {
				sp.connector = "aws"
				sp.method = rapid.SampledFrom([]string{"assume_role", "static_keys"}).Draw(rt, "awsMethod")
			}
			return sp
		})
		specs := rapid.SliceOfN(draw, 0, 12).Draw(rt, "connections")

		now := time.Now()
		for i, sp := range specs {
			id := fmt.Sprintf("conn-%d", i)
			c := store.NewConnection(id, sp.connector, fmt.Sprintf("alias-%d", i), s.store.Snapshot().Settings, now)
			c.Method, c.Status, c.Removed = sp.method, sp.status, sp.removed
			if err := s.store.AddConnection(c); err != nil {
				rt.Fatal(err)
			}
			if sp.hasCred {
				if err := s.vault.Put(ctx, slotRef(id, "credential"), sp.connector, []byte("secret"), time.Time{}); err != nil {
					rt.Fatal(err)
				}
			}
		}
		before := s.store.Snapshot().Connections

		s.reconcileMissingCredentials()

		after := s.store.Snapshot().Connections
		if len(after) != len(before) {
			rt.Fatalf("connection count changed: %d -> %d", len(before), len(after))
		}
		for i, sp := range specs {
			want := before[i]
			if sp.connector == "github" && (sp.method == "pat" || sp.method == "device") &&
				!sp.removed && !sp.hasCred && sp.status != "EXPIRED" {
				want.Status = "EXPIRED"
				want.StatusReason = after[i].StatusReason
				if want.StatusReason == "" {
					rt.Fatalf("conn-%d: expired without a reason", i)
				}
			}
			if !reflect.DeepEqual(after[i], want) {
				rt.Fatalf("conn-%d (%+v): got %+v want %+v", i, sp, after[i], want)
			}
		}
	})
}
