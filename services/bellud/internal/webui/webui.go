// Package webui serves the web app shell and static assets, mirroring
// packages/cli/src/services/web-ui.ts.
//
// Asset source: Options.Dir (from BELLUCODE_WEB_DIST) when set, otherwise the
// assets embedded at build time. Embedding needs the `embedweb` build tag and
// a populated internal/webui/dist directory (copy packages/app/dist there;
// the directory is gitignored). Without the tag the embedded FS is empty, so
// `go build ./...` works. Precompressed variants are sibling files named
// "<path>.br".
package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Options configures New.
type Options struct {
	// Dir, when non-empty, is served instead of the embedded assets. New fails
	// if it is unreadable; there is no fallback.
	Dir string
	// FS overrides the asset source (tests). Ignored when Dir is set.
	FS fs.FS
}

type handler struct{ fsys fs.FS }

// New builds the web UI handler.
func New(o Options) (http.Handler, error) {
	switch {
	case o.Dir != "":
		if _, err := os.ReadDir(o.Dir); err != nil {
			return nil, fmt.Errorf("BELLUCODE_WEB_DIST %q is not a readable directory: %w", o.Dir, err)
		}
		return &handler{fsys: os.DirFS(o.Dir)}, nil
	case o.FS != nil:
		return &handler{fsys: o.FS}, nil
	default:
		return &handler{fsys: embeddedFS()}, nil
	}
}

func (h *handler) read(key string) ([]byte, bool) {
	if key == "" || !fs.ValidPath(key) {
		return nil, false
	}
	info, err := fs.Stat(h.fsys, key)
	if err != nil || info.IsDir() {
		return nil, false
	}
	b, err := fs.ReadFile(h.fsys, key)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	hdr := w.Header()

	var body []byte
	encoded := false
	found := false
	if key != "index.html" && acceptsBrotli(r.Header.Values("Accept-Encoding")) {
		if b, ok := h.read(key + ".br"); ok {
			body, encoded, found = b, true, true
		}
	}
	if !found {
		body, found = h.read(key)
	}
	if !found && (strings.HasPrefix(key, "_assets/") || strings.HasPrefix(key, "icons/")) {
		hdr.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	name := key
	if !found {
		name = "index.html"
		b, ok := h.read(name)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body = b
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	html := name == "index.html"
	if html {
		hdr.Set("Content-Security-Policy", csp(themeHash(body)))
	} else {
		hdr.Set("Content-Security-Policy", csp(""))
	}
	hdr.Set("Content-Type", mimeType(name))
	// Only content-hashed build output is immutable. Favicons, icons and the manifest keep
	// their URL across releases, so they must revalidate or browsers show stale branding.
	if strings.HasPrefix(name, "_assets/") {
		hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		hdr.Set("Cache-Control", "no-cache")
	}
	hdr.Set("X-Content-Type-Options", "nosniff")
	if !html {
		if _, ok := h.read(name + ".br"); ok {
			hdr.Set("Vary", "Accept-Encoding")
		}
	}
	if encoded {
		hdr.Set("Content-Encoding", "br")
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

func acceptsBrotli(values []string) bool {
	for _, v := range values {
		for _, entry := range strings.Split(v, ",") {
			parts := strings.Split(entry, ";")
			if strings.ToLower(strings.TrimSpace(parts[0])) != "br" {
				continue
			}
			ok := true
			for _, p := range parts[1:] {
				if q0.MatchString(strings.ToLower(strings.TrimSpace(p))) {
					ok = false
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

var q0 = regexp.MustCompile(`^q=0(?:\.0*)?$`)

var themeRe = regexp.MustCompile(`(?is)<script\b[^>]*\bid=(?:"oc-theme-preload-script"|'oc-theme-preload-script')[^>]*>(.*?)</script>`)
var srcRe = regexp.MustCompile(`(?i)\bsrc\s*=`)

func themeHash(html []byte) string {
	for _, m := range themeRe.FindAllSubmatchIndex(html, -1) {
		open := string(html[m[0]:m[2]]) // opening tag, up to the content group
		if srcRe.MatchString(open) {
			continue
		}
		sum := sha256.Sum256(html[m[2]:m[3]])
		return base64.StdEncoding.EncodeToString(sum[:])
	}
	return ""
}

func csp(hash string) string {
	h := ""
	if hash != "" {
		h = " 'sha256-" + hash + "'"
	}
	return "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'" + h +
		"; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: blob:; font-src 'self' data:; media-src 'self' data:; connect-src * data: blob:; worker-src 'self' blob:; frame-src 'self' blob:; object-src 'self' blob:"
}

func mimeType(name string) string {
	switch path.Ext(name) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json"
	case ".webmanifest":
		return "application/manifest+json"
	case ".svg":
		return "image/svg+xml"
	case ".wasm":
		return "application/wasm"
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
