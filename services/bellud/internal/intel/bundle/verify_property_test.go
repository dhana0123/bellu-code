package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
)

func genCorpus(minLen int) *rapid.Generator[[]model.Vuln] {
	return rapid.Custom(func(t *rapid.T) []model.Vuln {
		ids := rapid.SliceOfNDistinct(rapid.StringMatching(`CVE-20[0-9]{2}-[0-9]{4,6}`), minLen, 6, func(s string) string { return s }).Draw(t, "ids")
		out := make([]model.Vuln, 0, len(ids))
		for _, id := range ids {
			out = append(out, model.Vuln{
				ID:       id,
				Summary:  rapid.StringMatching(`[a-z ]{0,24}`).Draw(t, "summary"),
				Affected: []model.AffectedPackage{{Purl: "pkg:npm/" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "pkg")}},
			})
		}
		return out
	})
}

// importBundle mirrors the syncer: verify first, and import only on success.
func importBundle(t *rapid.T, s *store.Store, b []byte, pub ed25519.PublicKey) error {
	v, err := Verify(bytes.NewReader(b), pub)
	if err != nil {
		return err
	}
	return s.Replace(context.Background(), store.ImportInfo{Version: "new", CreatedAt: time.Unix(2, 0)}, bytes.NewReader(v.JSONL))
}

func snapshot(t *rapid.T, s *store.Store, ids []string) (store.Meta, map[string]model.Vuln) {
	m, err := s.Meta()
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	recs := map[string]model.Vuln{}
	for _, id := range ids {
		v, ok, err := s.Get(id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if ok {
			recs[id] = v
		}
	}
	return m, recs
}

func memberBodies(t *rapid.T, b []byte, pub ed25519.PublicKey) []member {
	v, err := Verify(bytes.NewReader(b), pub)
	if err != nil {
		t.Fatalf("untouched bundle must verify: %v", err)
	}
	manifest, sig := mustMember(t, b, ManifestFileName), mustMember(t, b, SignatureFileName)
	return []member{{DataFileName, v.JSONL}, {ManifestFileName, manifest}, {SignatureFileName, sig}}
}

func mustMember(t *rapid.T, b []byte, name string) []byte {
	m, err := readTarZst(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return m[name]
}

func flip(body []byte, i int) []byte {
	out := append([]byte(nil), body...)
	out[i%len(out)] ^= 0x01 << uint(i%8)
	return out
}

// Feature: unified-security-graph, Property 6: Verification rejects any tampered bundle and leaves the corpus unchanged
//
// For any generated corpus and any single-byte modification of the bundle, a
// swapped, removed, or added member, or a signature by another key, Verify
// returns an error, and importing the result into a store that already holds a
// corpus leaves its version, record count, and every record unchanged. The
// untouched bundle verifies.
//
// **Validates: Requirements 4.2, 4.6, 4.7**
func TestProperty6TamperedBundleRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.TempDir() + "/intel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	old := []model.Vuln{{ID: "OLD-1", Affected: []model.AffectedPackage{{Purl: "pkg:npm/old"}}}, {ID: "OLD-2"}}
	oldJSONL, err := ExportJSONL(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(context.Background(), store.ImportInfo{Version: "old", CreatedAt: time.Unix(1, 0)}, bytes.NewReader(oldJSONL)); err != nil {
		t.Fatal(err)
	}

	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus(1).Draw(t, "corpus")
		good, err := Build(corpus, priv, time.Unix(100, 0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(bytes.NewReader(good), pub); err != nil {
			t.Fatalf("untouched bundle: %v", err)
		}

		members := memberBodies(t, good, pub)
		var tampered []byte
		kind := rapid.IntRange(0, 6).Draw(t, "kind")
		switch kind {
		case 0: // single-byte change in the compressed archive
			tampered = flip(good, rapid.IntRange(0, len(good)-1).Draw(t, "pos"))
		case 1: // single-byte change inside one member
			i := rapid.IntRange(0, len(members)-1).Draw(t, "member")
			members[i].body = flip(members[i].body, rapid.IntRange(0, 1<<20).Draw(t, "pos"))
			tampered, err = writeTarZst(members)
		case 2: // swapped data member from another corpus
			other := genCorpus(1).Draw(t, "other")
			otherJSONL, _ := ExportJSONL(other)
			if bytes.Equal(otherJSONL, members[0].body) {
				otherJSONL = append(otherJSONL, '\n')
			}
			members[0].body = otherJSONL
			tampered, err = writeTarZst(members)
		case 3: // removed member
			i := rapid.IntRange(0, len(members)-1).Draw(t, "removed")
			tampered, err = writeTarZst(append(append([]member(nil), members[:i]...), members[i+1:]...))
		case 4: // added member
			name := rapid.SampledFrom([]string{"extra.txt", "../evil", DataFileName, ManifestFileName}).Draw(t, "name")
			tampered, err = writeTarZst(append(members, member{name, []byte("x")}))
		case 5: // signature by another key
			tampered, err = Build(corpus, otherPriv, time.Unix(100, 0))
		case 6: // truncated archive
			tampered = good[:rapid.IntRange(0, len(good)-1).Draw(t, "len")]
		}
		if err != nil {
			t.Fatalf("build tampered: %v", err)
		}

		ids := []string{"OLD-1", "OLD-2"}
		for _, v := range corpus {
			ids = append(ids, v.ID)
		}
		beforeMeta, beforeRecs := snapshot(t, s, ids)

		if v, err := Verify(bytes.NewReader(tampered), pub); err == nil {
			// A flip in a zstd frame header field that does not affect the
			// decoded content (e.g. the window descriptor) changes no verified
			// byte. Accept it only when the verified content is identical.
			if kind != 0 || !bytes.Equal(v.JSONL, members[0].body) {
				t.Fatalf("tampered bundle (kind %d) verified", kind)
			}
			return
		} else if !errors.Is(err, ErrVerification) {
			t.Fatalf("Verify of tampered bundle: got %v, want ErrVerification", err)
		}
		if err := importBundle(t, s, tampered, pub); err == nil {
			t.Fatal("tampered bundle was imported")
		}

		afterMeta, afterRecs := snapshot(t, s, ids)
		if afterMeta.Gen != beforeMeta.Gen || afterMeta.Version != beforeMeta.Version || afterMeta.Records != beforeMeta.Records {
			t.Fatalf("meta changed: %+v -> %+v", beforeMeta, afterMeta)
		}
		if !reflect.DeepEqual(beforeRecs, afterRecs) {
			t.Fatalf("records changed: %v -> %v", beforeRecs, afterRecs)
		}
		if beforeMeta.Version != "old" || beforeMeta.Records != len(old) || len(afterRecs) != len(old) {
			t.Fatalf("unexpected corpus state: %+v %v", afterMeta, afterRecs)
		}
	})
}
