//go:build !embedweb

package webui

import (
	"io/fs"
	"testing/fstest"
)

// embeddedFS is empty unless built with -tags embedweb.
func embeddedFS() fs.FS { return fstest.MapFS{} }
