package cveupdate

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/sign"
)

func fixture(t *testing.T) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier([]ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	return v, priv
}

func TestNoKeysRejected(t *testing.T) {
	if _, err := NewVerifier(nil); !errors.Is(err, ErrNoPinnedKeys) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewPinnedVerifier(); !errors.Is(err, ErrNoPinnedKeys) {
		t.Fatalf("embedded keys: got %v", err)
	}
}

func TestVerifyIndex(t *testing.T) {
	v, priv := fixture(t)
	raw, _ := json.Marshal(Index{Product: "p", Latest: Snapshot{ID: "s1"}})
	idx, err := v.VerifyIndex(raw, sign.Sign(priv, raw))
	if err != nil || idx.Latest.ID != "s1" {
		t.Fatalf("good index: %v", err)
	}
	bad := append([]byte{}, raw...)
	bad[3] ^= 1
	if _, err := v.VerifyIndex(bad, sign.Sign(priv, raw)); !errors.Is(err, ErrIndexSignature) {
		t.Fatalf("flipped index: %v", err)
	}
	_, other, _ := sign.GenerateKey()
	if _, err := v.VerifyIndex(raw, sign.Sign(other, raw)); !errors.Is(err, ErrIndexSignature) {
		t.Fatalf("unpinned key: %v", err)
	}
}

func TestVerifyPackFileDeletesAndNamesPack(t *testing.T) {
	v, priv := fixture(t)
	data := []byte("pack bytes")
	sig := sign.Sign(priv, data)
	sum := SHA256Hex(data)
	dir := t.TempDir()
	write := func(b []byte) string {
		p := filepath.Join(dir, "a.tar.gz")
		os.WriteFile(p, b, 0o600)
		return p
	}

	p := write(data)
	if err := v.VerifyPackFile("a.tar.gz", p, sum, int64(len(data)), sig); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("good pack must be kept")
	}

	flipped := append([]byte{}, data...)
	flipped[0] ^= 1
	cases := map[string]struct {
		body []byte
		sum  string
		sig  []byte
		want error
	}{
		"checksum":  {flipped, sum, sig, sign.ErrChecksum},
		"signature": {data, sum, sign.Sign(priv, flipped), sign.ErrInvalidSignature},
	}
	for name, c := range cases {
		p := write(c.body)
		err := v.VerifyPackFile("a.tar.gz", p, c.sum, 0, c.sig)
		var pe *PackError
		if !errors.As(err, &pe) || pe.Pack != "a.tar.gz" || !errors.Is(err, c.want) {
			t.Fatalf("%s: got %v", name, err)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s: rejected pack not deleted", name)
		}
	}

	p = write(data)
	if err := v.VerifyPackFile("a.tar.gz", p, sum, 1, sig); err == nil {
		t.Fatal("size mismatch accepted")
	}
}

func TestCheckDowngrade(t *testing.T) {
	now := time.Now()
	if err := CheckDowngrade(now, now.Add(-time.Hour), false); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("got %v", err)
	}
	for _, c := range []struct {
		inst, cand time.Time
		allow      bool
	}{{now, now.Add(-time.Hour), true}, {now, now, false}, {now, now.Add(time.Hour), false}, {time.Time{}, now, false}} {
		if err := CheckDowngrade(c.inst, c.cand, c.allow); err != nil {
			t.Fatal(err)
		}
	}
}
