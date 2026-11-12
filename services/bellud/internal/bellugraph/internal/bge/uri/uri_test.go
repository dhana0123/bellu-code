package uri

import (
	"errors"
	"testing"
	"testing/quick"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	h1   = "0123456789abcdef0123456789abcdef"
	h2   = "fedcba9876543210fedcba9876543210"
	ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func TestFormatParseExamples(t *testing.T) {
	cases := []struct {
		ref  Ref
		want string
	}{
		{Entity{"host", h1}, "bellugraph://host/" + h1},
		{Relation{"depends_on", "process", h1, "listening_port", h2},
			"bellugraph://relation/depends_on/process/" + h1 + "/listening_port/" + h2},
		{Event{ulid}, "bellugraph://event/" + ulid},
	}
	for _, c := range cases {
		got, err := Format(c.ref)
		if err != nil || got != c.want {
			t.Fatalf("Format(%v) = %q, %v; want %q", c.ref, got, err, c.want)
		}
		back, err := Parse(got)
		if err != nil || back != c.ref {
			t.Fatalf("Parse(%q) = %v, %v; want %v", got, back, err, c.ref)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	bad := []string{
		"", "host/" + h1, "http://host/" + h1, "BELLUGRAPH://host/" + h1,
		"bellugraph://", "bellugraph://host", "bellugraph://host/", "bellugraph://host/" + h1 + "/x",
		"bellugraph://host/" + h1[:31], "bellugraph://host/" + "ABCDEF0123456789abcdef0123456789",
		"bellugraph://Host/" + h1, "bellugraph://schema", "bellugraph://1x/" + h1,
		"bellugraph://event/" + ulid[:25], "bellugraph://event/" + "81ARZ3NDEKTSV4RRFFQ69G5FAV",
		"bellugraph://event/01ARZ3NDEKTSV4RRFFQ69G5FAU", "bellugraph://event/" + ulid + "/x",
		"bellugraph://relation/depends_on/process/" + h1 + "/host",
		"bellugraph://relation/Bad/process/" + h1 + "/host/" + h2,
		"bellugraph://relation/depends_on/process/" + h1 + "/host/zz",
	}
	for _, s := range bad {
		if r, err := Parse(s); err == nil || !errors.Is(err, errs.Validation) {
			t.Errorf("Parse(%q) = %v, %v; want Validation error", s, r, err)
		}
	}
}

func TestFormatRejectsInvalid(t *testing.T) {
	for _, r := range []Ref{nil, Entity{"event", h1}, Entity{"host", "x"}, Event{"nope"}, Relation{"", "a", h1, "b", h2}} {
		if s, err := Format(r); err == nil || !errors.Is(err, errs.Validation) {
			t.Errorf("Format(%v) = %q, %v; want Validation error", r, s, err)
		}
	}
}

// Property 26: Parse(Format(r)) == r for valid references.
func TestRoundTripProperty(t *testing.T) {
	const hexd, crock = "0123456789abcdef", "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	pick := func(alpha string, n int, seed []byte) string {
		b := make([]byte, n)
		for i := range b {
			var s byte
			if len(seed) > 0 {
				s = seed[i%len(seed)] + byte(i)
			}
			b[i] = alpha[int(s)%len(alpha)]
		}
		return string(b)
	}
	f := func(a, b, c []byte, kn, tn uint8) bool {
		kinds := []string{"host", "process", "k8s_object", "endpoint"}
		types := []string{"depends_on", "runs_on", "connects_to"}
		e := Entity{kinds[int(kn)%len(kinds)], pick(hexd, hexLen, a)}
		r := Relation{types[int(tn)%len(types)], e.Kind, e.Hex, kinds[int(tn)%len(kinds)], pick(hexd, hexLen, b)}
		ev := Event{"0" + pick(crock, ulidLen-1, c)}
		for _, ref := range []Ref{e, r, ev} {
			s, err := Format(ref)
			if err != nil {
				return false
			}
			back, err := Parse(s)
			if err != nil || back != ref {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}
