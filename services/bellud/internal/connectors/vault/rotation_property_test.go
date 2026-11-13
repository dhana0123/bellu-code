package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// Feature: cloud-connectors, Property 26: Master key rotation atomicity
//
// For any set of stored credentials and any failure injected at any step of
// master key rotation, every credential is decryptable afterwards, under the
// new key if rotation completed and under the previous key otherwise, no
// plaintext credential is written to disk during rotation, and a failed
// rotation reports an error.
//
// **Validates: Requirements 6.17, 6.18**
func TestPropertyRotationAtomicity(t *testing.T) {
	log := newLog(t)
	ctx := context.Background()
	// "" injects no failure. Failing at "promote" happens after the rename, so
	// rotation has completed on disk and in memory but still reports an error.
	steps := []string{"", "store-next", "rewrap", "write-new", "audit", "rename", "promote"}
	rapid.Check(t, func(rt *rapid.T) {
		failAt := rapid.SampledFrom(steps).Draw(rt, "failAt")
		n := rapid.IntRange(0, 5).Draw(rt, "count")
		secrets := map[Ref][]byte{}
		for i := 0; i < n; i++ {
			kind := rapid.SampledFrom([]OwnerKind{OwnerConnection, OwnerAuthConfig}).Draw(rt, "kind")
			r := Ref{Owner: kind, OwnerID: "id" + strconv.Itoa(i), Slot: rapid.SampledFrom([]string{"primary", "secondary"}).Draw(rt, "slot")}
			// At least 16 random bytes so an accidental match in the file is negligible.
			secrets[r] = rapid.SliceOfN(rapid.Byte(), 16, 256).Draw(rt, "secret")
		}

		root, err := os.MkdirTemp("", "vault-rot")
		if err != nil {
			rt.Fatal(err)
		}
		defer os.RemoveAll(root)
		dir := filepath.Join(root, "v")
		src := newMemSource()
		s, err := Open(ctx, Options{Dir: dir, Audit: log, Order: []keysource.Source{src}})
		if err != nil {
			rt.Fatal(err)
		}
		for r, sec := range secrets {
			if err := s.Put(ctx, r, "aws", append([]byte(nil), sec...), time.Time{}); err != nil {
				rt.Fatal(err)
			}
		}
		oldKid := s.kid

		noPlaintext := func(label string) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				rt.Fatal(err)
			}
			for _, e := range entries {
				raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					rt.Fatal(err)
				}
				for _, sec := range secrets {
					if bytes.Contains(raw, sec) {
						rt.Fatalf("%s: plaintext credential found in %s", label, e.Name())
					}
				}
			}
		}
		s.opt.StepHook = func(step string) error {
			noPlaintext("before " + step)
			if step == failAt {
				return errors.New("injected")
			}
			return nil
		}

		rotErr := s.RotateMasterKey(ctx)
		noPlaintext("after rotation")

		completed := failAt == "" || failAt == "promote"
		if failAt != "" && rotErr == nil {
			rt.Fatalf("failure at %q was not reported", failAt)
		}
		if failAt == "" && rotErr != nil {
			rt.Fatalf("unexpected error: %v", rotErr)
		}
		if completed == (s.kid == oldKid) {
			rt.Fatalf("failAt=%q: kid changed=%v, want %v", failAt, s.kid != oldKid, completed)
		}

		all := func(st *Store, label string) {
			for r, want := range secrets {
				got, err := read(t, st, r)
				if err != nil || !bytes.Equal(got, want) {
					rt.Fatalf("%s: failAt=%q ref=%+v: err=%v match=%v", label, failAt, r, err, bytes.Equal(got, want))
				}
			}
		}
		all(s, "same store")

		// A fresh process sees the same state: recovery promotes the staged
		// key after a crash at "promote", and ignores it before the rename.
		s2, err := Open(ctx, Options{Dir: dir, Audit: log, Order: []keysource.Source{src}})
		if err != nil {
			rt.Fatalf("failAt=%q: reopen: %v", failAt, err)
		}
		// With no records the file carries no key binding, so a reopen simply
		// uses whatever the current slot holds.
		if n > 0 && completed == (s2.kid == oldKid) {
			rt.Fatalf("failAt=%q: reopened kid changed=%v, want %v", failAt, s2.kid != oldKid, completed)
		}
		all(s2, "reopened")
		noPlaintext("after reopen")
	})
}
