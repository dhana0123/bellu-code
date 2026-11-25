package risk

import "testing"

func TestExposureMonotonic(t *testing.T) {
	for _, base := range goldenCases()[:2000] {
		u, i, n := base, base, base
		i.Exposure, n.Exposure = ExposureInternal, ExposureInternet
		if !(Compute(n) >= Compute(i) && Compute(i) >= Compute(u)) {
			t.Fatalf("not monotone for %+v", base)
		}
	}
	base := Inputs{CVSS: 5, Reachable: true}
	if Compute(Inputs{CVSS: 5, Reachable: true, Exposure: ExposureInternet}) <= Compute(base) {
		t.Fatal("internet should raise the score")
	}
}

func TestAssetCriticalityMonotonic(t *testing.T) {
	prev := -1.0
	for _, c := range []float64{0, 0.25, 0.5, 0.75, 1} {
		s := Compute(Inputs{CVSS: 5, EPSS: 0.3, Reachable: true, AssetCriticality: c})
		if s < prev {
			t.Fatalf("criticality %v lowered the score", c)
		}
		prev = s
	}
}

func TestNewInputsClampAt100(t *testing.T) {
	in := Inputs{CVSS: 10, EPSS: 1, KEV: true, Reachable: true, AICriticality: 1, Exposure: ExposureInternet, AssetCriticality: 1}
	if got := Compute(in); got != 100 {
		t.Fatalf("got %v want 100", got)
	}
}

func TestUnknownEqualsOldScore(t *testing.T) {
	for _, in := range goldenCases()[:2000] {
		want := Compute(in)
		for _, e := range []Exposure{ExposureUnknown, "bogus"} {
			in.Exposure = e
			in.AssetCriticality = 0
			if got := Compute(in); got != want {
				t.Fatalf("%+v: got %v want %v", in, got, want)
			}
		}
	}
}
