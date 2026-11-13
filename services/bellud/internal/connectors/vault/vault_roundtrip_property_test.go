package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// Feature: cloud-connectors, Property 1: Vault round trip
//
// For any credential of 1 to 65,536 bytes (including non-ASCII and control
// bytes), any connector id, connection id, slot and version, sealing it in the
// vault and opening it with the same identifiers returns identical bytes.
//
// **Validates: Requirements 6.1, 12.1**
func TestPropertyVaultRoundTrip(t *testing.T) {
	log := newLog(t)
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.OneOf(
			rapid.IntRange(1, 64),
			rapid.IntRange(1, 4096),
			rapid.SampledFrom([]int{1, 2, 255, 256, MaxSecretLen - 1, MaxSecretLen}),
		).Draw(rt, "size")
		secret := rapid.SliceOfN(rapid.Byte(), size, size).Draw(rt, "secret")
		kind := rapid.SampledFrom([]OwnerKind{OwnerConnection, OwnerAuthConfig}).Draw(rt, "kind")
		ref := Ref{
			Owner:   kind,
			OwnerID: rapid.StringN(1, 64, -1).Draw(rt, "ownerID"),
			Slot:    rapid.StringN(1, 64, -1).Draw(rt, "slot"),
		}
		connectorID := rapid.StringN(1, 64, -1).Draw(rt, "connectorID")
		puts := rapid.IntRange(1, 4).Draw(rt, "puts") // final version == puts

		dir, err := os.MkdirTemp("", "vault-rt")
		if err != nil {
			rt.Fatal(err)
		}
		defer os.RemoveAll(dir)
		dir = filepath.Join(dir, "v")
		src := newMemSource()
		s, err := Open(ctx, Options{Dir: dir, Audit: log, Order: []keysource.Source{src}})
		if err != nil {
			rt.Fatal(err)
		}

		// Earlier versions use different bytes; only the last one must round trip.
		for i := 1; i < puts; i++ {
			old := append([]byte{byte(i)}, secret...)
			if len(old) > MaxSecretLen {
				old = old[:MaxSecretLen]
			}
			if err := s.Put(ctx, ref, connectorID, old, time.Time{}); err != nil {
				rt.Fatal(err)
			}
		}
		want := append([]byte(nil), secret...)
		if err := s.Put(ctx, ref, connectorID, secret, time.Time{}); err != nil {
			rt.Fatal(err)
		}

		check := func(st *Store, label string) {
			got, err := read(t, st, ref)
			if err != nil {
				rt.Fatalf("%s: open: %v", label, err)
			}
			if !bytes.Equal(got, want) {
				rt.Fatalf("%s: round trip mismatch (len got=%d want=%d)", label, len(got), len(want))
			}
			m, ok := st.Meta(ref)
			if !ok || m.Version != uint64(puts) {
				rt.Fatalf("%s: meta %+v ok=%v, want version %d", label, m, ok, puts)
			}
		}
		check(s, "same store")

		// Persisted form also round trips after a reopen with the same key.
		s2, err := Open(ctx, Options{Dir: dir, Audit: log, Order: []keysource.Source{src}})
		if err != nil {
			rt.Fatal(err)
		}
		check(s2, "reopened")
	})
}
