package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// Feature: go-server-bellu-graph, Property 6: Proxy transparency
// **Validates: Requirements 5.1, 5.3, 5.4, 5.5, 5.7**

// tcase is the scripted exchange the shared upstream plays for one iteration.
type tcase struct {
	status     int
	respHdr    map[string][]string
	respChunks [][]byte
}

type observed struct {
	method string
	hdr    http.Header
	body   []byte
}

func TestPropProxyTransparency(t *testing.T) {
	var mu sync.Mutex
	var cur tcase
	var seen observed

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = observed{method: r.Method, hdr: r.Header.Clone(), body: b}
		c := cur
		mu.Unlock()
		for k, vs := range c.respHdr {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(c.status)
		for _, ch := range c.respChunks {
			_, _ = w.Write(ch)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	child := &tschild.Child{URL: u, Password: "internal-pw"}

	front := httptest.NewServer(New(func() *tschild.Child { return child }))
	defer front.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	defer client.CloseIdleConnections()

	hdrs := func(prefix string) *rapid.Generator[map[string][]string] {
		return rapid.Custom(func(t *rapid.T) map[string][]string {
			n := rapid.IntRange(0, 5).Draw(t, "n")
			m := map[string][]string{}
			for i := 0; i < n; i++ {
				name := prefix + string(rune('A'+i))
				m[name] = rapid.SliceOfN(rapid.StringMatching(`[!-~]([ -~]{0,20}[!-~])?`), 1, 3).Draw(t, "vals")
			}
			return m
		})
	}

	rapid.Check(t, func(rt *rapid.T) {
		method := rapid.SampledFrom([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}).Draw(rt, "method")
		reqHdr := hdrs("X-Req-").Draw(rt, "reqHdr")
		reqBody := rapid.SliceOfN(rapid.Byte(), 0, 2048).Draw(rt, "reqBody")
		streamReq := rapid.Bool().Draw(rt, "streamReq")
		status := rapid.SampledFrom([]int{200, 201, 202, 400, 404, 409, 500, 503}).Draw(rt, "status")
		respHdr := hdrs("X-Resp-").Draw(rt, "respHdr")
		chunks := rapid.SliceOfN(rapid.SliceOfN(rapid.Byte(), 1, 512), 0, 8).Draw(rt, "chunks")

		mu.Lock()
		cur = tcase{status: status, respHdr: respHdr, respChunks: chunks}
		seen = observed{}
		mu.Unlock()

		var body io.Reader
		if len(reqBody) > 0 {
			body = bytes.NewReader(reqBody)
			if streamReq {
				// Hide the length so the client uses chunked transfer encoding.
				body = io.MultiReader(body)
			}
		}
		req, err := http.NewRequest(method, front.URL+"/p/q?x=1", body)
		if err != nil {
			rt.Fatal(err)
		}
		for k, vs := range reqHdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set("Authorization", "Basic ZXh0ZXJuYWw6c2VjcmV0") // credential: replaced, not compared
		res, err := client.Do(req)
		if err != nil {
			rt.Fatal(err)
		}
		got, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			rt.Fatal(err)
		}

		mu.Lock()
		s := seen
		mu.Unlock()

		// Request direction (5.1, 5.3, 5.4).
		if s.method != method {
			rt.Fatalf("method %q != %q", s.method, method)
		}
		if !bytes.Equal(s.body, reqBody) {
			rt.Fatalf("request body differs: %d vs %d bytes", len(s.body), len(reqBody))
		}
		for k, vs := range reqHdr {
			if !reflect.DeepEqual(s.hdr.Values(k), vs) {
				rt.Fatalf("request header %s: %q != %q", k, s.hdr.Values(k), vs)
			}
		}

		// Response direction (5.5, 5.7).
		if res.StatusCode != status {
			rt.Fatalf("status %d != %d", res.StatusCode, status)
		}
		for k, vs := range respHdr {
			if !reflect.DeepEqual(res.Header.Values(k), vs) {
				rt.Fatalf("response header %s: %q != %q", k, res.Header.Values(k), vs)
			}
		}
		if want := bytes.Join(chunks, nil); !bytes.Equal(got, want) {
			rt.Fatalf("response body differs: %d vs %d bytes", len(got), len(want))
		}
	})
}
