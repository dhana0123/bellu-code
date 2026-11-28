package bundle

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

func genPointer() *rapid.Generator[Pointer] {
	return rapid.Custom(func(t *rapid.T) Pointer {
		var url string
		switch rapid.IntRange(0, 3).Draw(t, "urlKind") {
		case 0:
			url = "https://" + rapid.StringMatching(`[a-z0-9]{1,12}(\.[a-z]{2,6}){1,2}`).Draw(t, "host") +
				rapid.StringMatching(`(/[A-Za-z0-9._-]{1,12}){0,3}`).Draw(t, "path")
		case 1:
			url = "http://" + rapid.SampledFrom([]string{"localhost", "127.0.0.1", "[::1]"}).Draw(t, "loop") +
				rapid.StringMatching(`(:[0-9]{2,5})?(/[a-z0-9.]{1,8}){0,2}`).Draw(t, "rest")
		default:
			url = rapid.StringMatching(`[A-Za-z0-9._-]{1,16}(/[A-Za-z0-9._-]{1,16}){0,2}`).Draw(t, "rel")
		}
		return Pointer{
			Schema:       1,
			Version:      rapid.StringMatching(`[A-Za-z0-9._-]{1,64}`).Draw(t, "version"),
			CreatedAt:    time.Unix(rapid.Int64Range(1, 253402300799).Draw(t, "sec"), int64(rapid.IntRange(0, 999999999).Draw(t, "nsec"))).UTC(),
			BundleURL:    url,
			BundleSHA256: rapid.StringMatching(`[0-9a-f]{64}`).Draw(t, "sha"),
			BundleSize:   rapid.Int64Range(1, MaxBundleSize).Draw(t, "size"),
		}
	})
}

// Feature: unified-security-graph, Property 8: Pointer parsing round trips and never panics
//
// For any valid pointer, ParsePointer(MarshalPointer(p)) equals p. For any byte
// string, ParsePointer returns either a valid pointer or an error, and never
// panics.
//
// **Validates: Requirements 4.8**
func TestProperty8PointerRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genPointer().Draw(t, "pointer")
		data, err := MarshalPointer(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, err := ParsePointer(data)
		if err != nil {
			t.Fatalf("ParsePointer(%s): %v", data, err)
		}
		if !got.CreatedAt.Equal(p.CreatedAt) {
			t.Fatalf("created_at %v, want %v", got.CreatedAt, p.CreatedAt)
		}
		got.CreatedAt, p.CreatedAt = time.Time{}, time.Time{}
		if got != p {
			t.Fatalf("round trip %+v, want %+v", got, p)
		}
	})
}

func TestProperty8PointerNeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(t, "bytes")
		checkParse(t, data)
	})
	// Mutated valid documents reach deeper validation branches than random bytes.
	rapid.Check(t, func(t *rapid.T) {
		data, err := MarshalPointer(genPointer().Draw(t, "pointer"))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(data) > 0 {
			i := rapid.IntRange(0, len(data)-1).Draw(t, "index")
			data[i] = rapid.Byte().Draw(t, "byte")
			if rapid.Bool().Draw(t, "truncate") {
				data = data[:i]
			}
		}
		checkParse(t, data)
	})
}

// checkParse asserts ParsePointer yields an error or a pointer that passes the
// documented validity rules. A panic fails the test.
func checkParse(t *rapid.T, data []byte) {
	p, err := ParsePointer(data)
	if err != nil {
		return
	}
	if p.Schema != 1 || p.Version == "" || len(p.Version) > 64 || p.CreatedAt.IsZero() ||
		!validBundleURL(p.BundleURL) || !sha256Hex.MatchString(p.BundleSHA256) ||
		p.BundleSize <= 0 || p.BundleSize > MaxBundleSize {
		t.Fatalf("ParsePointer(%q) accepted invalid pointer %+v", data, p)
	}
}
