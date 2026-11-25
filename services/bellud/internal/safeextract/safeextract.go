// Package safeextract bounds untrusted archive and directory input before a
// scanner reads it (Requirements 21.5, 21.6). It limits decompressed bytes,
// entry count, path depth and path length, and rejects absolute paths, ".."
// segments and links that leave the root.
//
// When a bound is violated the reader stops, any partial output is removed
// and the OnViolation callback runs once (the caller writes one
// scanner_error row from it).
package safeextract

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// Limits are the input bounds. A zero field takes its default.
type Limits struct {
	MaxBytes    int64 // decompressed bytes, default 1 GiB
	MaxEntries  int   // default 50,000
	MaxSegments int   // path segments, default 32
	MaxPathLen  int   // characters per path, default 4,096
}

// DefaultLimits are the bounds of Requirement 21.5.
var DefaultLimits = Limits{MaxBytes: 1 << 30, MaxEntries: 50000, MaxSegments: 32, MaxPathLen: 4096}

func (l Limits) norm() Limits {
	d := DefaultLimits
	if l.MaxBytes > 0 {
		d.MaxBytes = l.MaxBytes
	}
	if l.MaxEntries > 0 {
		d.MaxEntries = l.MaxEntries
	}
	if l.MaxSegments > 0 {
		d.MaxSegments = l.MaxSegments
	}
	if l.MaxPathLen > 0 {
		d.MaxPathLen = l.MaxPathLen
	}
	return d
}

// ErrViolation matches every bound or escape error.
var ErrViolation = errors.New("safeextract: input rejected")

// Violation describes the first rule the input broke.
type Violation struct{ Reason string }

func (v *Violation) Error() string   { return "safeextract: input rejected: " + v.Reason }
func (v *Violation) Is(t error) bool { return t == ErrViolation }

func violation(format string, a ...any) error { return &Violation{Reason: fmt.Sprintf(format, a...)} }

// CheckPath applies the path rules to an archive entry name.
func CheckPath(name string, l Limits) error {
	l = l.norm()
	if len(name) > l.MaxPathLen {
		return violation("path longer than %d characters", l.MaxPathLen)
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || filepath.IsAbs(name) || (len(name) > 1 && name[1] == ':') {
		return violation("absolute path %q", name)
	}
	segs := strings.Split(strings.ReplaceAll(name, `\`, "/"), "/")
	n := 0
	for _, s := range segs {
		if s == ".." {
			return violation("path %q has a .. segment", name)
		}
		if s != "" && s != "." {
			n++
		}
	}
	if n > l.MaxSegments {
		return violation("path has more than %d segments", l.MaxSegments)
	}
	return nil
}

// checkLink rejects a link whose target resolves outside the root. entry is
// the link's own root-relative path; hard links are relative to the root.
func checkLink(entry, target string, hard bool, l Limits) error {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, `\`) || filepath.IsAbs(target) {
		return violation("link %q has absolute target %q", entry, target)
	}
	if len(target) > l.MaxPathLen {
		return violation("link %q target longer than %d characters", entry, l.MaxPathLen)
	}
	base := path.Dir(path.Clean(entry))
	if hard {
		base = "."
	}
	joined := path.Join(base, strings.ReplaceAll(target, `\`, "/"))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return violation("link %q target %q is outside the root", entry, target)
	}
	return nil
}

type counter struct {
	l       Limits
	entries int
	bytes   int64
}

func (c *counter) entry() error {
	c.entries++
	if c.entries > c.l.MaxEntries {
		return violation("more than %d entries", c.l.MaxEntries)
	}
	return nil
}

func (c *counter) add(n int64) error {
	c.bytes += n
	if c.bytes > c.l.MaxBytes {
		return violation("decompressed size exceeds %d bytes", c.l.MaxBytes)
	}
	return nil
}

// open wraps r in a gzip reader when it starts with the gzip magic.
func open(r io.Reader) (io.Reader, func(), error) {
	br := bufio.NewReader(r)
	if m, _ := br.Peek(2); len(m) == 2 && m[0] == 0x1f && m[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		return zr, func() { zr.Close() }, nil
	}
	return br, func() {}, nil
}

// walkTar visits every entry; sink, when non-nil, receives regular file data.
func walkTar(r io.Reader, c *counter, depth int, sink func(h *tar.Header, r io.Reader) error) error {
	rd, closer, err := open(r)
	if err != nil {
		return err
	}
	defer closer()
	tr := tar.NewReader(rd)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := c.entry(); err != nil {
			return err
		}
		if err := CheckPath(h.Name, c.l); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeSymlink:
			if err := checkLink(h.Name, h.Linkname, false, c.l); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := checkLink(h.Name, h.Linkname, true, c.l); err != nil {
				return err
			}
		case tar.TypeReg:
			var body io.Reader = io.LimitReader(tr, c.l.MaxBytes-c.bytes+1)
			nested := depth < 3 && sink == nil && isTarName(h.Name)
			if nested {
				pr := &countReader{r: body, c: c}
				if err := walkTar(pr, c, depth+1, nil); err != nil {
					return err
				}
				if _, err := io.Copy(io.Discard, pr); err != nil {
					return err
				}
				continue
			}
			pr := &countReader{r: body, c: c}
			if sink != nil {
				if err := sink(h, pr); err != nil {
					return err
				}
			}
			if _, err := io.Copy(io.Discard, pr); err != nil {
				return err
			}
		}
	}
}

func isTarName(n string) bool {
	return strings.HasSuffix(n, ".tar") || strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz")
}

type countReader struct {
	r io.Reader
	c *counter
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		if e := cr.c.add(int64(n)); e != nil {
			return n, e
		}
	}
	return n, err
}

// ValidateTar walks every header of a (optionally gzip-compressed) tar and
// applies the bounds and escape rules, descending into nested layer tars.
// It reads the data once and stops at the first violation. onViolation, when
// non-nil, is called once with the error.
func ValidateTar(r io.Reader, l Limits, onViolation func(error)) error {
	c := &counter{l: l.norm()}
	err := walkTar(r, c, 0, nil)
	if err != nil && onViolation != nil && errors.Is(err, ErrViolation) {
		onViolation(err)
	}
	return err
}

// ValidateTarFile validates the tar at p.
func ValidateTarFile(p string, l Limits, onViolation func(error)) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return ValidateTar(f, l, onViolation)
}

// ExtractTar writes the tar under dst. On any error (violation or I/O) it
// removes everything it wrote under dst, and for a violation it calls
// onViolation once.
func ExtractTar(r io.Reader, dst string, l Limits, onViolation func(error)) (err error) {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	var written []string
	defer func() {
		if err == nil {
			return
		}
		for i := len(written) - 1; i >= 0; i-- {
			os.RemoveAll(written[i])
		}
		if onViolation != nil && errors.Is(err, ErrViolation) {
			onViolation(err)
		}
	}()
	c := &counter{l: l.norm()}
	return walkTar(r, c, 0, func(h *tar.Header, body io.Reader) error {
		target := filepath.Join(dst, filepath.FromSlash(path.Clean(h.Name)))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		written = append(written, target)
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

// FS is a bounded, read-only fs.FS over a directory root. Every Open checks
// the path rules and that symlinks resolve inside the root. Reads count bytes
// and directory listings count entries; once a bound is hit every later call
// fails with the same error.
type FS struct {
	root string
	c    *counter
	mu   sync.Mutex
	err  error
	once sync.Once
	cb   func(error)
}

var _ fs.FS = (*FS)(nil)

// DirFS returns a bounded view of root. onViolation runs once, on the first
// violation.
func DirFS(root string, l Limits, onViolation func(error)) (*FS, error) {
	abs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	return &FS{root: abs, c: &counter{l: l.norm()}, cb: onViolation}, nil
}

// Err returns the violation that stopped the FS, if any.
func (f *FS) Err() error { f.mu.Lock(); defer f.mu.Unlock(); return f.err }

func (f *FS) fail(err error) error {
	f.mu.Lock()
	if f.err == nil {
		f.err = err
	}
	err = f.err
	f.mu.Unlock()
	if f.cb != nil {
		f.once.Do(func() { f.cb(err) })
	}
	return err
}

// Open implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	if err := f.Err(); err != nil {
		return nil, err
	}
	if err := CheckPath(name, f.c.l); err != nil {
		return nil, f.fail(err)
	}
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	full := filepath.Join(f.root, filepath.FromSlash(name))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: unwrapErr(err)}
	}
	if real != f.root && !strings.HasPrefix(real, f.root+string(filepath.Separator)) {
		return nil, f.fail(violation("symlink %q resolves outside the root", name))
	}
	file, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	return &boundedFile{File: file, fs: f}, nil
}

func unwrapErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

type boundedFile struct {
	*os.File
	fs *FS
}

func (b *boundedFile) Read(p []byte) (int, error) {
	if err := b.fs.Err(); err != nil {
		return 0, err
	}
	n, err := b.File.Read(p)
	if n > 0 {
		b.fs.mu.Lock()
		e := b.fs.c.add(int64(n))
		b.fs.mu.Unlock()
		if e != nil {
			return 0, b.fs.fail(e)
		}
	}
	return n, err
}

// ReadDir counts each returned entry against the entry bound.
func (b *boundedFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if err := b.fs.Err(); err != nil {
		return nil, err
	}
	es, err := b.File.ReadDir(n)
	for range es {
		b.fs.mu.Lock()
		e := b.fs.c.entry()
		b.fs.mu.Unlock()
		if e != nil {
			return nil, b.fs.fail(e)
		}
	}
	return es, err
}
