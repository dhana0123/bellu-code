package seek

import (
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Signals are the per-candidate ranking inputs, each in 0..1.
// A signal the BSKG does not provide is 0.
type Signals struct {
	IdentMatch float64 // 1 or 0
	Overlap    float64 // Jaccard of token sets
	KEV        float64 // 1 or 0
	EPSS       float64
	CVSS       float64 // v3 base score / 10
	Fix        float64 // 1 when a fix commit exists
}

// Score is the weighted sum of the signals, clamped to [0,1].
func Score(s Signals) float64 {
	v := WIdent*s.IdentMatch + WOverlap*s.Overlap + WKEV*s.KEV +
		WEPSS*s.EPSS + WCVSS*s.CVSS + WFix*s.Fix
	return math.Min(1, math.Max(0, v))
}

// Tokens lowercases s, splits it on non-alphanumerics and returns the
// distinct tokens of at least 3 characters.
func Tokens(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, t := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if utf8.RuneCountInString(t) >= 3 {
			out[t] = struct{}{}
		}
	}
	return out
}

// Jaccard is |a∩b| / |a∪b|, or 0 when both sets are empty.
func Jaccard(a, b map[string]struct{}) float64 {
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// IdentMatch is 1 when a token of the CVE description also appears in the
// unit's snippet or root cause, otherwise 0.
func IdentMatch(desc, snippet, rootCause string) float64 {
	d := Tokens(desc)
	for _, text := range []string{snippet, rootCause} {
		for t := range Tokens(text) {
			if _, ok := d[t]; ok {
				return 1
			}
		}
	}
	return 0
}

// SignalsFor computes the ranking signals of one CVE for one unit.
func SignalsFor(u Unit, v VulnDetail) Signals {
	s := Signals{
		IdentMatch: IdentMatch(v.Description, u.Snippet, u.RootCause),
		Overlap:    Jaccard(Tokens(u.RootCause), Tokens(v.Description)),
	}
	if v.KEV {
		s.KEV = 1
	}
	if v.EPSS != nil {
		s.EPSS = *v.EPSS
	}
	if v.CVSS != nil {
		s.CVSS = *v.CVSS / 10
	}
	if v.FixCommit != "" {
		s.Fix = 1
	}
	return s
}

func rounded(score float64) int64 { return int64(math.Round(score * 1e6)) }

// Rank returns a copy of cs ordered by rounded (6 dp) score descending, then
// CVE id ascending.
func Rank(cs []Candidate) []Candidate {
	out := append([]Candidate(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rounded(out[i].Score), rounded(out[j].Score)
		if ri != rj {
			return ri > rj
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

// Cutoff drops candidates with Score < min. A score equal to min is kept.
func Cutoff(cs []Candidate, min float64) []Candidate {
	out := make([]Candidate, 0, len(cs))
	for _, c := range cs {
		if c.Score >= min {
			out = append(out, c)
		}
	}
	return out
}
