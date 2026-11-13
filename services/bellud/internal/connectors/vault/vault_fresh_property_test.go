package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

func openFreshStore(rt *rapid.T, t *testing.T) *Store {
	dir, err := os.MkdirTemp("", "vault-fresh")
	if err != nil {
		rt.Fatal(err)
	}
	rt.Cleanup(func() { os.RemoveAll(dir) })
	s, err := Open(context.Background(), Options{
		Dir: filepath.Join(dir, "v"), Audit: newLog(t), Order: []keysource.Source{newMemSource()},
	})
	if err != nil {
		rt.Fatal(err)
	}
	return s
}

// Feature: cloud-connectors, Property 3: Fresh data key and nonce per seal
//
// For any credential sealed N times, all N wrapped data keys, all N nonces and
// all N ciphertexts are pairwise distinct.
//
// **Validates: Requirements 6.1**
func TestPropertyFreshDEKAndNonce(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		s := openFreshStore(rt, t)
		n := rapid.IntRange(2, 12).Draw(rt, "n")
		secret := rapid.SliceOfN(rapid.Byte(), 1, 256).Draw(rt, "secret")
		sameRef := rapid.Bool().Draw(rt, "sameRef")
		connectorID := rapid.StringN(1, 16, -1).Draw(rt, "connectorID")

		wrapped, nonces, cts := map[string]int{}, map[string]int{}, map[string]int{}
		for i := range n {
			ref := Ref{OwnerConnection, "cn_1", "primary"}
			if !sameRef {
				ref.OwnerID = "cn_" + string(rune('a'+i))
			}
			if err := s.Put(ctx, ref, connectorID, append([]byte(nil), secret...), time.Time{}); err != nil {
				rt.Fatal(err)
			}
			r := s.records[ref]
			for name, m := range map[string]map[string]int{"wrapped": wrapped, "nonce": nonces, "ciphertext": cts} {
				v := map[string][]byte{"wrapped": r.WrappedDEK, "nonce": r.Nonce, "ciphertext": r.Ciphertext}[name]
				if prev, dup := m[string(v)]; dup {
					rt.Fatalf("%s of seal %d equals seal %d", name, i, prev)
				}
				m[string(v)] = i
			}
		}
	})
}

// Feature: cloud-connectors, Property 4: Plaintext buffer is zeroed after use
//
// The byte slice handed to the Use callback contains only zero bytes once Use
// returns, whether the callback succeeded or failed.
//
// **Validates: Requirements 6.11**
func TestPropertyPlaintextZeroedAfterUse(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		s := openFreshStore(rt, t)
		secret := rapid.SliceOfN(rapid.Byte(), 1, 4096).Draw(rt, "secret")
		fail := rapid.Bool().Draw(rt, "fail")
		ref := Ref{OwnerConnection, "cn_1", "primary"}
		want := append([]byte(nil), secret...)
		if err := s.Put(ctx, ref, "aws", secret, time.Time{}); err != nil {
			rt.Fatal(err)
		}

		var held, seen []byte
		cbErr := errors.New("callback failed")
		err := s.Use(ctx, ref, func(b []byte) error {
			held = b
			seen = append([]byte(nil), b...)
			if fail {
				return cbErr
			}
			return nil
		})
		if fail != errors.Is(err, cbErr) {
			rt.Fatalf("unexpected Use error %v (fail=%v)", err, fail)
		}
		if string(seen) != string(want) {
			rt.Fatal("callback did not receive the stored plaintext")
		}
		if len(held) != len(want) {
			rt.Fatalf("held length %d, want %d", len(held), len(want))
		}
		for i, c := range held {
			if c != 0 {
				rt.Fatalf("byte %d not zeroed after Use (fail=%v)", i, fail)
			}
		}
	})
}
