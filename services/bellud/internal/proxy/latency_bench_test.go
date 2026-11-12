package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// Req 22.10: median latency added by the proxy must stay under 1 ms for bodies <= 4 KiB.
const (
	latencySamples   = 1000
	latencyBodyBytes = 4 << 10
	latencyBudget    = time.Millisecond
)

type latencyRig struct {
	directURL, proxiedURL string
	direct, proxied       *http.Client
	body                  []byte
	close                 func()
}

func newLatencyRig(tb testing.TB) *latencyRig {
	tb.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	u, err := url.Parse(upstream.URL)
	if err != nil {
		tb.Fatal(err)
	}
	child := &tschild.Child{URL: u, Password: "internal-pw"}
	front := httptest.NewServer(New(func() *tschild.Child { return child }))
	newClient := func() *http.Client {
		return &http.Client{Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 4}}
	}
	body := bytes.Repeat([]byte("a"), latencyBodyBytes)
	return &latencyRig{
		directURL: upstream.URL + "/session", proxiedURL: front.URL + "/session",
		direct: newClient(), proxied: newClient(), body: body,
		close: func() { front.Close(); upstream.Close() },
	}
}

func (r *latencyRig) do(tb testing.TB, c *http.Client, target string) time.Duration {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(r.body))
	if err != nil {
		tb.Fatal(err)
	}
	start := time.Now()
	res, err := c.Do(req)
	if err != nil {
		tb.Fatal(err)
	}
	n, err := io.Copy(io.Discard, res.Body)
	res.Body.Close()
	d := time.Since(start)
	if err != nil || n != int64(len(r.body)) || res.StatusCode != http.StatusOK {
		tb.Fatalf("bad response: status=%d n=%d err=%v", res.StatusCode, n, err)
	}
	return d
}

func median(d []time.Duration) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func TestProxyAddedLatencyMedian(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement skipped in -short mode")
	}
	r := newLatencyRig(t)
	defer r.close()
	for i := 0; i < 50; i++ { // warm up keep-alive connections
		r.do(t, r.direct, r.directURL)
		r.do(t, r.proxied, r.proxiedURL)
	}
	direct := make([]time.Duration, 0, latencySamples)
	proxied := make([]time.Duration, 0, latencySamples)
	for i := 0; i < latencySamples; i++ { // interleaved to cancel drift
		direct = append(direct, r.do(t, r.direct, r.directURL))
		proxied = append(proxied, r.do(t, r.proxied, r.proxiedURL))
	}
	md, mp := median(direct), median(proxied)
	added := mp - md
	t.Logf("samples=%d body=%dB median direct=%v proxied=%v added=%v (budget %v)",
		latencySamples, latencyBodyBytes, md, mp, added, latencyBudget)
	if added >= latencyBudget {
		t.Fatalf("median added latency %v >= %v", added, latencyBudget)
	}
}

func BenchmarkProxyLatency(b *testing.B) {
	r := newLatencyRig(b)
	defer r.close()
	r.do(b, r.proxied, r.proxiedURL)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.do(b, r.proxied, r.proxiedURL)
	}
}

func BenchmarkDirectLatency(b *testing.B) {
	r := newLatencyRig(b)
	defer r.close()
	r.do(b, r.direct, r.directURL)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.do(b, r.direct, r.directURL)
	}
}
