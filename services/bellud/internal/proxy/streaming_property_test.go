package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// Feature: go-server-bellu-graph, Property 7: Streaming preserved
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

// TestPropSSEStreamingPreserved gates the upstream on a client ack after every chunk.
// If the proxy buffered the body, the client would never see chunk i before the
// upstream wrote chunk i+1, and the exchange would deadlock until the timeout.
func TestPropSSEStreamingPreserved(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunks := rapid.SliceOfN(rapid.SliceOfN(rapid.Byte(), 1, 600), 1, 6).Draw(rt, "chunks")

		ack := make(chan struct{})
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			for _, c := range chunks {
				_, _ = w.Write(c)
				w.(http.Flusher).Flush()
				select {
				case <-ack:
				case <-time.After(5 * time.Second):
					return // body is truncated, so the client check fails
				case <-r.Context().Done():
					return
				}
			}
		}))
		defer upstream.Close()
		u, _ := url.Parse(upstream.URL)
		child := &tschild.Child{URL: u, Password: "pw"}
		front := httptest.NewServer(New(func() *tschild.Child { return child }))
		defer front.Close()

		res, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Get(front.URL + "/event")
		if err != nil {
			rt.Fatal(err)
		}
		defer res.Body.Close()
		for i, want := range chunks {
			got := make([]byte, len(want))
			if _, err := io.ReadFull(res.Body, got); err != nil {
				rt.Fatalf("chunk %d not observable before stream end: %v", i, err)
			}
			if !bytes.Equal(got, want) {
				rt.Fatalf("chunk %d content mismatch", i)
			}
			ack <- struct{}{}
		}
		if rest, _ := io.ReadAll(res.Body); len(rest) != 0 {
			rt.Fatalf("unexpected trailing bytes: %d", len(rest))
		}
	})
}

type spMsg struct {
	op byte
	p  []byte
}

// spFrame builds a FIN frame with 7-bit, 16-bit or 64-bit length encoding as needed.
func spFrame(op byte, payload []byte, mask bool) []byte {
	var b []byte
	m := byte(0)
	if mask {
		m = 0x80
	}
	b = append(b, 0x80|op)
	switch n := len(payload); {
	case n < 126:
		b = append(b, m|byte(n))
	case n <= 0xffff:
		b = append(b, m|126, byte(n>>8), byte(n))
	default:
		b = append(b, m|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if !mask {
		return append(b, payload...)
	}
	key := []byte{9, 8, 7, 6}
	b = append(b, key...)
	for i, c := range payload {
		b = append(b, c^key[i%4])
	}
	return b
}

func spReadFrame(r io.Reader) (byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		e := make([]byte, 2)
		if _, err := io.ReadFull(r, e); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(e))
	case 127:
		e := make([]byte, 8)
		if _, err := io.ReadFull(r, e); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(e)
	}
	var key []byte
	if h[1]&0x80 != 0 {
		key = make([]byte, 4)
		if _, err := io.ReadFull(r, key); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if key != nil {
		for i := range p {
			p[i] ^= key[i%4]
		}
	}
	return h[0] & 0x0f, p, nil
}

// spEchoChild is a raw WebSocket echo server that understands extended lengths.
func spEchoChild(t *testing.T) *tschild.Child {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID))
				io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+
					base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
				for {
					op, p, err := spReadFrame(br)
					if err != nil {
						return
					}
					conn.Write(spFrame(op, p, false))
					if op == 8 {
						return
					}
				}
			}()
		}
	}()
	u, _ := url.Parse("http://" + ln.Addr().String())
	return &tschild.Child{URL: u, Password: "pw"}
}

func TestPropWebSocketStreamingPreserved(t *testing.T) {
	child := spEchoChild(t)
	front := httptest.NewServer(New(func() *tschild.Child { return child }))
	defer front.Close()

	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.SampledFrom([]int{0, 1, 125, 126, 127, 300, 65535, 65536}).
			Draw(rt, "size")
		msgGen := rapid.Custom(func(rt *rapid.T) spMsg {
			n := rapid.IntRange(0, 130).Draw(rt, "n")
			if rapid.IntRange(0, 4).Draw(rt, "big") == 0 {
				n = size
			}
			return spMsg{
				op: rapid.SampledFrom([]byte{1, 2}).Draw(rt, "op"),
				p:  rapid.SliceOfN(rapid.Byte(), n, n).Draw(rt, "p"),
			}
		})
		msgs := rapid.SliceOfN(msgGen, 1, 6).Draw(rt, "msgs")
		reason := rapid.StringMatching(`[a-z]{0,20}`).Draw(rt, "reason")
		pipelined := rapid.Bool().Draw(rt, "pipelined")

		conn, err := net.Dial("tcp", front.Listener.Addr().String())
		if err != nil {
			rt.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		br := bufio.NewReader(conn)
		res, err := http.ReadResponse(br, nil)
		if err != nil || res.StatusCode != 101 {
			rt.Fatalf("handshake: %v %v", res, err)
		}

		check := func(i int, m spMsg) {
			op, p, err := spReadFrame(br)
			if err != nil || op != m.op || !bytes.Equal(p, m.p) {
				rt.Fatalf("frame %d: op=%d len=%d err=%v want op=%d len=%d", i, op, len(p), err, m.op, len(m.p))
			}
		}
		if pipelined {
			// A writer goroutine keeps sending while we read, so a buffering splice would stall.
			go func() {
				for _, m := range msgs {
					conn.Write(spFrame(m.op, m.p, true))
				}
			}()
			for i, m := range msgs {
				check(i, m)
			}
		} else {
			// Each frame must come back before the next one is sent (stream still open).
			for i, m := range msgs {
				conn.Write(spFrame(m.op, m.p, true))
				check(i, m)
			}
		}

		closeBody := append([]byte{0x03, 0xE8}, reason...)
		conn.Write(spFrame(8, closeBody, true))
		op, p, err := spReadFrame(br)
		if err != nil || op != 8 || !bytes.Equal(p, closeBody) {
			rt.Fatalf("close frame: op=%d p=%q err=%v", op, p, err)
		}
		conn.SetDeadline(time.Now().Add(CloseTimeout + 2*time.Second))
		if _, err := br.ReadByte(); err != io.EOF {
			rt.Fatalf("expected EOF after close, got %v", err)
		}
	})
}
