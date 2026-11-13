package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
)

const badPrefix = "bad_"

// Feature: cloud-connectors, Property 11: Audit completeness and fail-closed
// **Validates: Requirements 9.1, 9.2, 9.3**
func TestPropertyAuditCompletenessAndFailClosed(t *testing.T) {
	ops := []string{"create", "test", "rotate", "reconnect", "disconnect"}
	primary := map[string]string{
		"create": audit.EventConnect, "test": audit.EventTest, "rotate": audit.EventRotate,
		"reconnect": audit.EventConnect, "disconnect": audit.EventDisconnect,
	}
	secretGen := rapid.StringMatching(`[a-z0-9]{16,40}`)

	rapid.Check(t, func(rt *rapid.T) {
		op := rapid.SampledFrom(ops).Draw(rt, "op")
		auditFails := rapid.Bool().Draw(rt, "auditFails")
		oldSecret := "tok_" + secretGen.Draw(rt, "oldSecret")
		newSecret := "tok_" + secretGen.Draw(rt, "newSecret")
		if oldSecret == newSecret {
			newSecret += "x"
		}
		// A failing verification yields failure outcomes, never skipped audit.
		badNew := (op == "create" || op == "rotate") && rapid.Bool().Draw(rt, "badNew")
		if badNew {
			newSecret = badPrefix + newSecret
		}

		f := newMgrFix(t)
		f.p.verify = func(s string) (Identity, error) {
			if strings.HasPrefix(s, badPrefix) {
				return Identity{}, errors.New("rejected")
			}
			return Identity{AccountLabel: "acct-1"}, nil
		}
		ctx := context.Background()
		cred := credRef("c1")

		// Setup (audit healthy): an existing connection where the op needs one.
		switch op {
		case "test", "rotate", "disconnect":
			f.create(t, "prod", oldSecret)
		case "reconnect":
			// Stored credential fails verification, leaving the connection in ERROR.
			_, err := f.m.Create(ctx, CreateInput{
				ConnectorID: "ex", Alias: "prod", Method: "token",
				Credential: CredentialInput{Secret: []byte(badPrefix + oldSecret)},
			})
			if err == nil {
				rt.Fatal("setup: expected verification failure")
			}
			oldSecret = badPrefix + oldSecret
		}
		before := f.a.count(primary[op])
		total := len(f.a.entries)
		storedBefore, hadBefore := f.v.get(cred)

		f.a.fail = auditFails && op != "disconnect" // disconnect audit is best effort after revocation
		var err error
		switch op {
		case "create":
			_, err = f.m.Create(ctx, CreateInput{
				ConnectorID: "ex", Alias: "prod", Method: "token",
				Credential: CredentialInput{Secret: []byte(newSecret)},
			})
		case "test":
			_, err = f.m.Test(ctx, "c1")
		case "rotate":
			err = f.m.Rotate(ctx, "c1", CredentialInput{Secret: []byte(newSecret)})
		case "reconnect":
			err = f.m.Reconnect(ctx, "c1", CredentialInput{Secret: []byte(newSecret)})
		case "disconnect":
			err = f.m.Disconnect(ctx, "c1")
		}
		f.a.fail = false

		if auditFails && op != "disconnect" {
			// Fail-closed: error, no entries, stored credential unchanged.
			if err == nil {
				rt.Fatalf("%s succeeded although the audit append failed", op)
			}
			var e *Error
			if !errors.As(err, &e) {
				rt.Fatalf("want *Error, got %T", err)
			}
			if !badNew && e.Code != CodeAuditFailed {
				rt.Fatalf("%s: want %s, got %s", op, CodeAuditFailed, e.Code)
			}
			if got := len(f.a.entries); got != total {
				rt.Fatalf("entries appended despite failing log: %d -> %d", total, got)
			}
			after, has := f.v.get(cred)
			if has != hadBefore || after != storedBefore {
				rt.Fatalf("stored credential changed on audit failure: %q/%v -> %q/%v", storedBefore, hadBefore, after, has)
			}
			if op == "create" && len(f.v.data) != 0 {
				rt.Fatalf("credential stored for a connection whose connect was not audited")
			}
			if _, has := f.v.get(candRef("c1")); has {
				rt.Fatalf("candidate credential left behind")
			}
			return
		}

		// Completeness: exactly one entry of the operation's event.
		if got := f.a.count(primary[op]) - before; got != 1 {
			rt.Fatalf("%s (err=%v): want exactly 1 %s entry, got %d", op, err, primary[op], got)
		}
		for _, e := range f.a.entries[total:] {
			checkEntry(rt, e, oldSecret, newSecret)
		}
		for _, e := range f.a.entries[:total] {
			checkEntry(rt, e, oldSecret, newSecret)
		}
		// The entry of the operation carries the right outcome.
		last := entryOf(f.a.entries[total:], primary[op])
		switch {
		case op == "disconnect", op == "reconnect", op == "create":
			if last.Outcome != audit.OutcomeSuccess {
				rt.Fatalf("%s: outcome %s", op, last.Outcome)
			}
		case badNew && last.Outcome != audit.OutcomeFailure:
			rt.Fatalf("%s with failing verification: outcome %s", op, last.Outcome)
		case !badNew && last.Outcome != audit.OutcomeSuccess:
			rt.Fatalf("%s: outcome %s", op, last.Outcome)
		}
	})
}

func entryOf(es []audit.Entry, event string) audit.Entry {
	for _, e := range es {
		if e.Event == event {
			return e
		}
	}
	return audit.Entry{}
}

func checkEntry(rt *rapid.T, e audit.Entry, secrets ...string) {
	rt.Helper()
	if e.TS.IsZero() || e.TS.Location() != time.UTC {
		rt.Fatalf("entry %s: timestamp must be set and UTC: %v", e.Event, e.TS)
	}
	if e.ConnectionID == "" || e.ConnectorID == "" || e.Event == "" || e.Actor == "" {
		rt.Fatalf("entry missing field: %+v", e)
	}
	switch e.Outcome {
	case audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeBlocked:
	default:
		rt.Fatalf("entry %s: invalid outcome %q", e.Event, e.Outcome)
	}
	text := e.ConnectionID + e.ConnectorID + e.Event + e.Outcome + e.Actor
	for k, v := range e.Detail {
		text += k + v
	}
	for _, s := range secrets {
		if strings.Contains(text, strings.TrimPrefix(s, badPrefix)) {
			rt.Fatalf("entry %s contains a credential value", e.Event)
		}
	}
}
