//go:build embedweb

package webui

import (
	"embed"
	"io/fs"
)

// dist is populated at build time (copy packages/app/dist to internal/webui/dist).
//
//go:embed all:dist
var dist embed.FS

func embeddedFS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
