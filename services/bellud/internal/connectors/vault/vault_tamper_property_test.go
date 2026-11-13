package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
)

// Feature: cloud-connectors, Property 2: Tamper and AAD binding
//
// For any stored credential, a single-bit flip, truncation or appended byte in
// the ciphertext, nonce or wrapped DEK, or any change of connector id,
// connection id, slot or version, makes opening fail with ErrDecrypt, yields no
// plaintext bytes, and appends one audit entry holding no key material,
// ciphertext or plaintext.
//
// **Validates: Requirements 6.2, 10.5, 12.2**
func TestPropertyVaultTamperAndAADBinding(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		secret := rapid.SliceOfN(rapid.Byte(), 16, 512).Draw(rt, "secret")
		r := Ref{
			Owner:   rapid.SampledFrom([]OwnerKind{OwnerConnection, OwnerAuthConfig}).Draw(rt, "kind"),
			OwnerID: rapid.StringMatching(`[a-z0-9_]{1,24}`).Draw(rt, "ownerID"),
			Slot:    rapid.StringMatching(`[a-z0-9_]{1,24}`).Draw(rt, "slot"),
		}
		connectorID := rapid.StringMatching(`[a-z0-9_]{1,24}`).Draw(rt, "connectorID")

		dir, err := os.MkdirTemp("", "vault-tamper")
		if err != nil {
			rt.Fatal(err)
		}
		defer os.RemoveAll(dir)
		log, err := audit.Open(filepath.Join(dir, "audit"), audit.Options{})
		if err != nil {
			rt.Fatal(err)
		}
		s, err := Open(ctx, Options{Dir: filepath.Join(dir, "v"), Audit: log, Order: nil})
		if err != nil {
			rt.Fatal(err)
		}
		if err := s.Put(ctx, r, connectorID, bytes.Clone(secret), time.Time{}); err != nil {
			rt.Fatal(err)
		}
		orig := s.records[r]

		field := rapid.SampledFrom([]string{"ciphertext", "nonce", "wrapped", "connector", "owner", "slot", "version"}).Draw(rt, "field")
		rec := *orig
		rec.Ciphertext, rec.Nonce, rec.WrappedDEK = bytes.Clone(orig.Ciphertext), bytes.Clone(orig.Nonce), bytes.Clone(orig.WrappedDEK)

		switch field {
		case "ciphertext":
			rec.Ciphertext = tamperBytes(rt, rec.Ciphertext)
		case "nonce":
			rec.Nonce = tamperBytes(rt, rec.Nonce)
		case "wrapped":
			rec.WrappedDEK = tamperBytes(rt, rec.WrappedDEK)
		case "connector":
			rec.ConnectorID = changedString(rt, rec.ConnectorID)
		case "owner":
			rec.OwnerID = changedString(rt, rec.OwnerID)
		case "slot":
			rec.Slot = changedString(rt, rec.Slot)
		case "version":
			rec.Version = rapid.Uint64().Filter(func(v uint64) bool { return v != orig.Version }).Draw(rt, "version")
		}

		s.records[r] = &rec
		var got []byte
		called := false
		err = s.Use(ctx, r, func(b []byte) error { called = true; got = bytes.Clone(b); return nil })
		s.records[r] = orig

		if !errors.Is(err, ErrDecrypt) {
			rt.Fatalf("%s: err = %v, want ErrDecrypt", field, err)
		}
		if called || len(got) != 0 {
			rt.Fatalf("%s: plaintext released (%d bytes)", field, len(got))
		}

		// The untampered record still opens: the failure was caused by the mutation.
		var ok []byte
		if err := s.Use(ctx, r, func(b []byte) error { ok = bytes.Clone(b); return nil }); err != nil || !bytes.Equal(ok, secret) {
			rt.Fatalf("original record no longer opens: %v", err)
		}

		page, err := log.List(r.OwnerID, "", audit.PageSize)
		if err != nil {
			rt.Fatal(err)
		}
		failures := 0
		for _, e := range page.Entries {
			if e.Event == audit.EventDecryptFailed {
				failures++
			}
		}
		if failures != 1 {
			rt.Fatalf("%s: %d decrypt_failed entries, want 1", field, failures)
		}
		raw, err := json.Marshal(page.Entries)
		if err != nil {
			rt.Fatal(err)
		}
		for name, v := range map[string][]byte{
			"secret": secret, "key": s.key, "ciphertext": orig.Ciphertext,
			"nonce": orig.Nonce, "wrapped dek": orig.WrappedDEK,
		} {
			for _, form := range [][]byte{
				v, []byte(hex.EncodeToString(v)),
				[]byte(base64.StdEncoding.EncodeToString(v)), []byte(base64.RawStdEncoding.EncodeToString(v)),
				[]byte(base64.URLEncoding.EncodeToString(v)), []byte(base64.RawURLEncoding.EncodeToString(v)),
			} {
				if len(form) >= 8 && bytes.Contains(raw, form) {
					rt.Fatalf("audit entries contain %s", name)
				}
			}
		}
	})
}

// tamperBytes applies one of: single-bit flip, truncation, appended byte.
func tamperBytes(rt *rapid.T, b []byte) []byte {
	switch rapid.SampledFrom([]string{"flip", "truncate", "append"}).Draw(rt, "op") {
	case "flip":
		i := rapid.IntRange(0, len(b)-1).Draw(rt, "idx")
		b[i] ^= 1 << rapid.IntRange(0, 7).Draw(rt, "bit")
		return b
	case "truncate":
		return b[:rapid.IntRange(0, len(b)-1).Draw(rt, "keep")]
	}
	return append(b, rapid.Byte().Draw(rt, "extra"))
}

func changedString(rt *rapid.T, old string) string {
	return rapid.StringMatching(`[a-z0-9_]{1,24}`).Filter(func(s string) bool { return s != old }).Draw(rt, "changed")
}
