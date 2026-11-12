package proxy

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// frame builds a WebSocket frame (masked when mask is true) with a payload < 126 bytes.
func frame(op byte, payload []byte, mask bool) []byte {
	b := []byte{0x80 | op, byte(len(payload))}
	if !mask {
		return append(b, payload...)
	}
	key := []byte{1, 2, 3, 4}
	b[1] |= 0x80
	b = append(b, key...)
	for i, c := range payload {
		b = append(b, c^key[i%4])
	}
	return b
}

// readFrame returns opcode and unmasked payload.
func readFrame(r io.Reader) (byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	n := int(h[1] & 0x7f)
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
	for i := range p {
		if key != nil {
			p[i] ^= key[i%4]
		}
	}
	return h[0] & 0x0f, p, nil
}

// echoChild is a minimal raw WebSocket echo server. Payload "die" makes it drop the
// connection without a close frame.
func echoChild(t *testing.T) *tschild.Child {
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
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID))
				io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+
					base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
				for {
					op, p, err := readFrame(br)
					if err != nil {
						return
					}
					if string(p) == "die" {
						return
					}
					conn.Write(frame(op, p, false))
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

func dialWS(t *testing.T, c *tschild.Child) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	srv := httptest.NewServer(New(func() *tschild.Child { return c }))
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, res
}

func TestSpliceEchoOrderAndClose(t *testing.T) {
	conn, br, res := dialWS(t, echoChild(t))
	if res.StatusCode != 101 {
		t.Fatalf("status %d", res.StatusCode)
	}
	msgs := []struct {
		op byte
		p  string
	}{{1, "one"}, {2, "\x00\x01bin"}, {1, "three"}}
	for _, m := range msgs {
		conn.Write(frame(m.op, []byte(m.p), true))
	}
	for _, m := range msgs {
		op, p, err := readFrame(br)
		if err != nil || op != m.op || string(p) != m.p {
			t.Fatalf("got op=%d p=%q err=%v want %d %q", op, p, err, m.op, m.p)
		}
	}
	// Close frame with status 1000 and reason passes through; both sides then close.
	conn.Write(frame(8, append([]byte{0x03, 0xE8}, "bye"...), true))
	op, p, err := readFrame(br)
	if err != nil || op != 8 || string(p) != "\x03\xe8bye" {
		t.Fatalf("close echo op=%d p=%q err=%v", op, p, err)
	}
	conn.SetDeadline(time.Now().Add(CloseTimeout + time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected EOF after close, got %v", err)
	}
}

func TestSpliceChildDeathSends1011(t *testing.T) {
	conn, br, res := dialWS(t, echoChild(t))
	if res.StatusCode != 101 {
		t.Fatalf("status %d", res.StatusCode)
	}
	conn.Write(frame(1, []byte("die"), true))
	op, p, err := readFrame(br)
	if err != nil || op != 8 || len(p) < 2 || p[0] != 0x03 || p[1] != 0xF3 {
		t.Fatalf("want 1011 close, got op=%d p=%x err=%v", op, p, err)
	}
}

func TestSpliceChildUnreachable(t *testing.T) {
	c := echoChild(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	u, _ := url.Parse("http://" + ln.Addr().String())
	ln.Close()
	c.URL = u
	_, _, res := dialWS(t, c)
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", res.StatusCode)
	}
}
