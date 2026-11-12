// Package proxy forwards TS-owned requests to the loopback TS child.
//
// Bodies are never read or re-encoded. The transport has compression disabled so
// Content-Encoding and Content-Length pass through untouched. FlushInterval is -1, which
// flushes after every write, so SSE (and any Stream route) is never buffered.
package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// ResponseHeaderTimeout bounds the wait for upstream response headers (Req 5.8).
const ResponseHeaderTimeout = 30 * time.Second

// UpgradeFunc handles a WebSocket upgrade for an authorized request. The request carries
// the original headers; the implementation must apply Prepare to build the upstream request.
// Task 6.2 plugs the hijack-and-splice implementation in here.
type UpgradeFunc func(w http.ResponseWriter, r *http.Request, child *tschild.Child)

// Options configures the proxy.
type Options struct {
	// Upgrade handles WebSocket upgrades. When nil, the standard library's built-in
	// upgrade handling in ReverseProxy is used.
	Upgrade UpgradeFunc
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
}

type proxy struct {
	child   func() *tschild.Child
	rp      *httputil.ReverseProxy
	upgrade UpgradeFunc
}

// New returns a handler that forwards requests to the current child.
func New(child func() *tschild.Child, opts ...Options) http.Handler {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	tr := o.Transport
	if tr == nil {
		tr = &http.Transport{
			DisableCompression:    true,
			ResponseHeaderTimeout: ResponseHeaderTimeout,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			// Not proxy-aware: the child is always loopback.
		}
	}
	if o.Upgrade == nil {
		o.Upgrade = Splice
	}
	p := &proxy{child: child, upgrade: o.Upgrade}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      tr,
		FlushInterval:  -1,
		ModifyResponse: modifyResponse,
		ErrorHandler:   errorHandler,
	}
	return p
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := p.child()
	if c == nil {
		unavailable(w)
		return
	}
	if isUpgrade(r) && p.upgrade != nil {
		p.upgrade(w, r, c)
		return
	}
	// Carry the resolved child through the context so Rewrite uses the same one
	// that passed the nil check.
	p.rp.ServeHTTP(w, r.WithContext(withChild(r.Context(), c)))
}

// Prepare applies the credential, Host and X-Forwarded-* rules to an outbound request
// whose URL is already set. It is shared with the WebSocket splice (task 6.2).
func Prepare(in, out *http.Request, c *tschild.Child) {
	out.Header.Del("Authorization")
	out.Header.Del("Cookie")
	out.SetBasicAuth(tschild.Username, c.Password)
	out.Host = in.Host
	host, _, err := net.SplitHostPort(in.RemoteAddr)
	if err != nil {
		host = in.RemoteAddr
	}
	out.Header.Del("X-Forwarded-For")
	out.Header.Del("X-Forwarded-Host")
	out.Header.Del("X-Forwarded-Proto")
	out.Header.Del("Forwarded")
	if host != "" {
		out.Header.Set("X-Forwarded-For", host)
	}
	out.Header.Set("X-Forwarded-Host", in.Host)
	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}
	out.Header.Set("X-Forwarded-Proto", proto)
}

func (p *proxy) rewrite(pr *httputil.ProxyRequest) {
	c := childFrom(pr.In.Context())
	pr.SetURL(c.URL) // joins target path with request path; keeps the query
	pr.Out.URL.RawPath = pr.In.URL.RawPath
	if c.URL.Path == "" || c.URL.Path == "/" {
		pr.Out.URL.Path = pr.In.URL.Path
	}
	Prepare(pr.In, pr.Out, c)
	// Rewrite drops hop-by-hop headers before calling us, including Upgrade. Restore it
	// for the built-in upgrade fallback.
	if isUpgrade(pr.In) {
		pr.Out.Header.Set("Connection", "Upgrade")
		pr.Out.Header.Set("Upgrade", pr.In.Header.Get("Upgrade"))
	}
}

func modifyResponse(res *http.Response) error {
	if strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "text/event-stream") {
		// Child exit mid-stream surfaces as a read error. Convert it to a normal EOF so the
		// client sees a clean end of stream instead of an aborted connection (Req 6.6).
		res.Body = &sseBody{ReadCloser: res.Body}
	}
	return nil
}

type sseBody struct{ io.ReadCloser }

func (b *sseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		return n, io.EOF
	}
	return n, err
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, r.Context().Err()) && r.Context().Err() != nil {
		return // client went away; upstream request already cancelled
	}
	writeError(w, http.StatusBadGateway, "UnknownError", "upstream unavailable", "")
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "2")
	writeError(w, http.StatusServiceUnavailable, "ServiceUnavailableError", "upstream is starting", "tschild")
}

// writeError emits the packages/protocol error shape: {_tag, message, ...}.
func writeError(w http.ResponseWriter, status int, tag, message, service string) {
	body := map[string]string{"_tag": tag, "message": message}
	if service != "" {
		body["service"] = service
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func isUpgrade(r *http.Request) bool {
	for _, v := range r.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return r.Header.Get("Upgrade") != ""
			}
		}
	}
	return false
}
