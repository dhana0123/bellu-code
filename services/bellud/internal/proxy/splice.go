package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// CloseTimeout bounds how long a spliced WebSocket may stay open after one side finished
// (Req 6.5, 6.7).
const CloseTimeout = 5 * time.Second

const dialTimeout = 5 * time.Second

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// close frame: FIN|opcode 8, payload length 2, status 1011 (internal error). Server to
// client frames are unmasked.
var close1011 = []byte{0x88, 0x02, 0x03, 0xF3}

// Splice is the default UpgradeFunc: it dials the child, replays the prepared upgrade
// request, relays the 101 response, then copies raw bytes in both directions so frame
// order and payloads are untouched.
func Splice(w http.ResponseWriter, r *http.Request, c *tschild.Child) {
	up, err := net.DialTimeout("tcp", c.URL.Host, dialTimeout)
	if err != nil {
		writeError(w, http.StatusBadGateway, "UnknownError", "upstream unavailable", "")
		return
	}
	defer up.Close() // no-op after the splice closes it

	out := r.Clone(r.Context())
	out.Body = nil
	out.RequestURI = ""
	out.URL = upstreamURL(c, r)
	out.Header = r.Header.Clone()
	Prepare(r, out, c)

	_ = up.SetDeadline(time.Now().Add(ResponseHeaderTimeout))
	upr := bufio.NewReader(up)
	if err := out.Write(up); err != nil {
		writeError(w, http.StatusBadGateway, "UnknownError", "upstream unavailable", "")
		return
	}
	res, err := http.ReadResponse(upr, out)
	if err != nil {
		writeError(w, http.StatusBadGateway, "UnknownError", "upstream unavailable", "")
		return
	}
	_ = up.SetDeadline(time.Time{})

	if res.StatusCode != http.StatusSwitchingProtocols {
		// Upgrade refused by the child: relay as a plain response, no WebSocket opens.
		defer res.Body.Close()
		for k, v := range res.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "UnknownError", "upgrade unsupported", "")
		return
	}
	cli, crw, err := hj.Hijack()
	if err != nil {
		return
	}
	var head strings.Builder
	head.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = res.Header.Write(&head)
	head.WriteString("\r\n")
	if _, err := io.WriteString(cli, head.String()); err != nil {
		cli.Close()
		return
	}

	var s scanner
	done := make(chan struct{}, 2)
	// client -> child. Bytes the HTTP server already buffered come first.
	go func() {
		pump(up, crw.Reader, nil)
		closeWrite(up)
		done <- struct{}{}
	}()
	// child -> client. Bytes buffered while reading the 101 come first.
	go func() {
		_ = pump(cli, upr, &s)
		if !s.closeSeen && s.atBoundary() {
			// Child died or the upstream ended without a close frame (Req 6.7).
			_, _ = cli.Write(close1011)
		}
		closeWrite(cli)
		done <- struct{}{}
	}()

	<-done
	timer := time.NewTimer(CloseTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
	cli.Close()
	up.Close()
}

// pump copies src to dst with a pooled buffer. It returns nil on clean EOF of src and the
// error otherwise (a failed write is reported as an error too).
func pump(dst net.Conn, src io.Reader, s *scanner) error {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if s != nil {
				s.feed(buf[:n])
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func upstreamURL(c *tschild.Child, r *http.Request) *url.URL {
	u := &url.URL{Scheme: "http", Host: c.URL.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	if p := c.URL.Path; p != "" && p != "/" {
		u.Path = strings.TrimSuffix(p, "/") + "/" + strings.TrimPrefix(r.URL.Path, "/")
		u.RawPath = ""
	}
	return u
}

// scanner tracks WebSocket frame boundaries in the child->client byte stream so the proxy
// knows whether a close frame went by and whether a 1011 frame can be injected cleanly.
type scanner struct {
	hdr       [14]byte
	hn        int
	remaining uint64
	closeSeen bool
}

func (s *scanner) atBoundary() bool { return s.hn == 0 && s.remaining == 0 }

func (s *scanner) feed(p []byte) {
	for len(p) > 0 {
		if s.remaining > 0 {
			n := uint64(len(p))
			if n > s.remaining {
				n = s.remaining
			}
			s.remaining -= n
			p = p[n:]
			continue
		}
		s.hdr[s.hn] = p[0]
		s.hn++
		p = p[1:]
		if s.hn < 2 {
			continue
		}
		need := 2
		switch s.hdr[1] & 0x7f {
		case 126:
			need += 2
		case 127:
			need += 8
		}
		if s.hdr[1]&0x80 != 0 {
			need += 4
		}
		if s.hn < need {
			continue
		}
		var l uint64
		switch s.hdr[1] & 0x7f {
		case 126:
			l = uint64(s.hdr[2])<<8 | uint64(s.hdr[3])
		case 127:
			for i := 0; i < 8; i++ {
				l = l<<8 | uint64(s.hdr[2+i])
			}
		default:
			l = uint64(s.hdr[1] & 0x7f)
		}
		if s.hdr[0]&0x0f == 8 {
			s.closeSeen = true
		}
		s.remaining = l
		s.hn = 0
	}
}
