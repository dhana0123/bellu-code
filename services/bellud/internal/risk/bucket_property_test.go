package risk

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 12: Severity buckets are monotone
// and KEV floors at high.
//
// **Validates: Requirements 6.6, 6.7**

var severityRank = map[Severity]int{
	SevInfo:     0,
	SevLow:      1,
	SevMedium:   2,
	SevHigh:     3,
	SevCritical: 4,
}

func TestBucketThresholdsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		score := rapid.Float64Range(0, 100).Draw(t, "score")
		var want Severity
		switch {
		case score >= 90:
			want = SevCritical
		case score >= 70:
			want = SevHigh
		case score >= 40:
			want = SevMedium
		case score >= 10:
			want = SevLow
		default:
			want = SevInfo
		}
		if got := Bucket(score, false); got != want {
			t.Fatalf("Bucket(%v,false)=%v, want %v", score, got, want)
		}
	})
}

func TestBucketMonotoneProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Float64Range(0, 100).Draw(t, "a")
		b := rapid.Float64Range(0, 100).Draw(t, "b")
		if a > b {
			a, b = b, a
		}
		kev := rapid.Bool().Draw(t, "kev")
		lo, hi := Bucket(a, kev), Bucket(b, kev)
		if severityRank[hi] < severityRank[lo] {
			t.Fatalf("Bucket(%v,%v)=%v ranks above Bucket(%v,%v)=%v", a, kev, lo, b, kev, hi)
		}
	})
}

func TestBucketKEVFloorsAtHighProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		score := rapid.Float64Range(0, 100).Draw(t, "score")
		got := Bucket(score, true)
		if got != SevHigh && got != SevCritical {
			t.Fatalf("Bucket(%v,true)=%v, want high or critical", score, got)
		}
		if severityRank[got] < severityRank[Bucket(score, false)] {
			t.Fatalf("KEV lowered severity at score %v: %v", score, got)
		}
	})
}

func TestBucketKEVInputsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := anyInputs().Draw(t, "in")
		in.KEV = true
		got := Bucket(Compute(in), in.KEV)
		if got != SevHigh && got != SevCritical {
			t.Fatalf("KEV inputs %+v bucketed %v, want high or critical", in, got)
		}
	})
}
