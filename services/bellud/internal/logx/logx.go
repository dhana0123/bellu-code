// Package logx provides prefixed logging for bellud and the TS child relay.
package logx

import (
	"bytes"
	"io"
	"log"
	"sync"
)

const (
	// Prefix is prepended to every bellud log line.
	Prefix = "[bellud]"
	// ChildPrefix is prepended to every line relayed from the TS child process.
	ChildPrefix = "[ts-child]"
)

// New returns a logger whose every line starts with "[bellud] ".
func New(w io.Writer) *log.Logger {
	return log.New(w, Prefix+" ", log.LstdFlags)
}

// Relay is a writer that prefixes each complete line with a fixed prefix.
type Relay struct {
	mu     sync.Mutex
	out    io.Writer
	prefix string
	buf    []byte
}

// NewRelay returns a line-prefixing writer using ChildPrefix.
func NewRelay(out io.Writer) *Relay {
	return &Relay{out: out, prefix: ChildPrefix + " "}
}

// Write buffers input and emits each complete line with the prefix.
func (r *Relay) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := append([]byte(r.prefix), r.buf[:i+1]...)
		r.buf = r.buf[i+1:]
		if _, err := r.out.Write(line); err != nil {
			return len(p), err
		}
	}
}

// Flush emits any trailing partial line.
func (r *Relay) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	line := append(append([]byte(r.prefix), r.buf...), '\n')
	r.buf = nil
	_, err := r.out.Write(line)
	return err
}
