package risk

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/compute_golden.txt")

const goldenPath = "testdata/compute_golden.txt"

// goldenCases enumerates a grid of the original five inputs. The golden file
// was generated from Compute before Exposure and AssetCriticality existed, so
// it pins today's scores for every input where the new fields are zero.
func goldenCases() []Inputs {
	cvss := []float64{math.NaN(), -1, 11}
	for i := 0; i <= 20; i++ {
		cvss = append(cvss, float64(i)/2)
	}
	epss := []float64{math.NaN(), -0.5, 1.5}
	for i := 0; i <= 10; i++ {
		epss = append(epss, float64(i)/10)
	}
	ai := []float64{math.NaN(), -1, 2, 0, 0.25, 0.5, 0.75, 1}
	var out []Inputs
	for _, c := range cvss {
		for _, e := range epss {
			for _, k := range []bool{false, true} {
				for _, r := range []bool{false, true} {
					for _, a := range ai {
						out = append(out, Inputs{CVSS: c, EPSS: e, KEV: k, Reachable: r, AICriticality: a})
					}
				}
			}
		}
	}
	return out
}

func goldenLine(in Inputs) string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
	return fmt.Sprintf("%s %s %t %t %s => %s", f(in.CVSS), f(in.EPSS), in.KEV, in.Reachable, f(in.AICriticality), f(Compute(in)))
}

func TestComputeGolden(t *testing.T) {
	cases := goldenCases()
	if *updateGolden {
		var b strings.Builder
		for _, in := range cases {
			b.WriteString(goldenLine(in) + "\n")
		}
		if err := os.WriteFile(goldenPath, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	i := 0
	for sc.Scan() {
		if i >= len(cases) {
			t.Fatalf("golden has more lines than cases")
		}
		if got := goldenLine(cases[i]); got != sc.Text() {
			t.Fatalf("line %d: got %q want %q", i, got, sc.Text())
		}
		i++
	}
	if i != len(cases) {
		t.Fatalf("golden has %d lines, want %d", i, len(cases))
	}
}
