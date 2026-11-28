package bom

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Requirement 5.11: exports larger than 50 MB must not use more than 256 MB.
const (
	largeMinOutput = 50 << 20
	largeMemBound  = 256 << 20
	largePackages  = 70_000
)

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// largeSBOM builds an SBOM whose export exceeds 50 MB in both formats.
func largeSBOM(n int) SBOM {
	pkgs := make([]Package, n)
	for i := range pkgs {
		name := fmt.Sprintf("module-%06d", i)
		ver := fmt.Sprintf("1.%d.%d", i%50, i%7)
		purl := fmt.Sprintf("pkg:npm/%%40scope/%s@%s", name, ver)
		sup := "Example Supplier Inc."
		pkgs[i] = Package{
			Name: name, Version: &ver, Purl: &purl, Ecosystem: "npm",
			Licenses: []string{"MIT", "Apache-2.0"},
			Supplier: &sup,
			Locations: []string{
				fmt.Sprintf("/srv/app/node_modules/%s/package.json", name),
				fmt.Sprintf("/srv/app/node_modules/.cache/%s/package-lock.json", name),
			},
			Hashes: []Hash{
				{Algorithm: "SHA-256", Value: fmt.Sprintf("%064x", i)},
				{Algorithm: "SHA-512", Value: fmt.Sprintf("%0128x", i)},
			},
			Properties: map[string]string{"scope": "runtime", "direct": "false", "layer": fmt.Sprintf("sha256:%064x", i)},
		}
	}
	return SBOM{Subject: "repo/large", Packages: pkgs}
}

type memResult struct {
	output int64
	peak   uint64 // peak HeapAlloc above the baseline that holds the input SBOM
	took   time.Duration
}

// measureWrite exports s and returns the output size and the peak heap growth
// during the write. The input SBOM is already allocated and live when the
// baseline is read, so it is excluded from the budget: the requirement covers
// the export's own memory.
func measureWrite(tb testing.TB, s SBOM, format Format) memResult {
	tb.Helper()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()

	cw := &countingWriter{}
	start := time.Now()
	err := Write(context.Background(), cw, s, Options{Format: format})
	took := time.Since(start)
	close(stop)
	<-done
	if err != nil {
		tb.Fatalf("Write(%s): %v", format, err)
	}
	var grown uint64
	if p := peak.Load(); p > base.HeapAlloc {
		grown = p - base.HeapAlloc
	}
	return memResult{output: cw.n, peak: grown, took: took}
}

var largeFormats = []Format{FormatCycloneDXJSON, FormatSPDXJSON}

func TestWriteLargeMemoryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("large export memory test skipped under -short")
	}
	s := largeSBOM(largePackages)
	for _, f := range largeFormats {
		t.Run(string(f), func(t *testing.T) {
			r := measureWrite(t, s, f)
			t.Logf("format=%s packages=%d output=%.1f MB peak_extra_heap=%.1f MB time=%s",
				f, largePackages, float64(r.output)/(1<<20), float64(r.peak)/(1<<20), r.took)
			if r.output <= largeMinOutput {
				t.Fatalf("output %d bytes does not exceed 50 MB; increase package count", r.output)
			}
			if r.peak >= largeMemBound {
				t.Fatalf("peak extra heap %.1f MB >= 256 MB for %.1f MB output",
					float64(r.peak)/(1<<20), float64(r.output)/(1<<20))
			}
		})
	}
}

func BenchmarkWriteLarge(b *testing.B) {
	s := largeSBOM(largePackages)
	for _, f := range largeFormats {
		b.Run(string(f), func(b *testing.B) {
			b.ReportAllocs()
			var r memResult
			for i := 0; i < b.N; i++ {
				r = measureWrite(b, s, f)
			}
			b.SetBytes(r.output)
			b.ReportMetric(float64(r.peak)/(1<<20), "peakMB")
			b.ReportMetric(float64(r.output)/(1<<20), "outMB")
		})
	}
}
