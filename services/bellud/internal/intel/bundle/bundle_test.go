package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	in := []model.Vuln{{ID: "CVE-2"}, {ID: "CVE-1", Aliases: []string{"GHSA-x"}}}
	b, err := Build(in, priv, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(bytes.NewReader(b), pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Vulns()
	if err != nil || len(got) != 2 || got[0].ID != "CVE-1" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	good, _ := Build([]model.Vuln{{ID: "CVE-1"}}, priv, time.Unix(0, 0))
	if _, err := Verify(bytes.NewReader(good), otherPub); !errors.Is(err, ErrVerification) {
		t.Fatalf("wrong key: %v", err)
	}
	extra, _ := writeTarZst([]member{{"evil.txt", []byte("x")}})
	dup, _ := writeTarZst([]member{{DataFileName, nil}, {DataFileName, nil}})
	var many []member
	for i := 0; i < MaxMembers+1; i++ {
		many = append(many, member{DataFileName, nil})
	}
	manyB, _ := writeTarZst(many)
	for name, b := range map[string][]byte{"extra": extra, "dup": dup, "many": manyB} {
		if _, err := Verify(bytes.NewReader(b), pub); !errors.Is(err, ErrVerification) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyUnlistedAndTamperedData(t *testing.T) {
	pub, priv := keys(t)
	good, _ := Build([]model.Vuln{{ID: "CVE-1"}}, priv, time.Unix(0, 0))
	v, _ := Verify(bytes.NewReader(good), pub)
	manifest, sig := mustMembers(t, good)
	for name, ms := range map[string][]member{
		"tampered": {{DataFileName, append(v.JSONL, '\n')}, {ManifestFileName, manifest}, {SignatureFileName, sig}},
		"unlisted": {{ManifestFileName, manifest}, {SignatureFileName, sig}, {DataFileName, v.JSONL}, {"x", nil}},
		"nodata":   {{ManifestFileName, manifest}, {SignatureFileName, sig}},
	} {
		b, _ := writeTarZst(ms)
		if _, err := Verify(bytes.NewReader(b), pub); !errors.Is(err, ErrVerification) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mustMembers(t *testing.T, b []byte) (manifest, sig []byte) {
	t.Helper()
	m, err := readTarZst(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return m[ManifestFileName], m[SignatureFileName]
}

const validPointer = `{"schema":1,"version":"v1","created_at":"2026-11-15T03:00:00Z","bundle_url":"https://x.example/a.tar.zst","bundle_sha256":"` +
	"0000000000000000000000000000000000000000000000000000000000000000" + `","bundle_size":10,"extra":1}`

func TestParsePointer(t *testing.T) {
	if _, err := ParsePointer([]byte(validPointer)); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"", "[]", `{"schema":2}`,
		strings.Replace(validPointer, "https://x.example/a", "http://x.example/a", 1),
		strings.Replace(validPointer, `"bundle_size":10`, `"bundle_size":0`, 1),
		strings.Replace(validPointer, `"v1"`, `""`, 1),
	}
	for _, s := range bad {
		if _, err := ParsePointer([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := ParsePointer([]byte(strings.Replace(validPointer, "https://x.example/a", "http://127.0.0.1:1/a", 1))); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

func TestLoadPinnedKey(t *testing.T) {
	t.Setenv("BELLU_INTEL_PUBKEY", "")
	if _, err := LoadPinnedKey(); !errors.Is(err, ErrNoPinnedKey) {
		t.Fatalf("want ErrNoPinnedKey, got %v", err)
	}
	pub, _ := keys(t)
	t.Setenv("BELLU_INTEL_PUBKEY", base64Std(pub))
	got, err := LoadPinnedKey()
	if err != nil || !got.Equal(pub) {
		t.Fatalf("got %v, %v", got, err)
	}
	t.Setenv("BELLU_INTEL_PUBKEY", "AAAA")
	if _, err := LoadPinnedKey(); err == nil {
		t.Fatal("short key accepted")
	}
}
