// Command sync-bellu-graph vendors a pinned upstream Toise commit into
// internal/bellugraph, renaming it to the Bellu Graph Engine.
//
// Usage (from services/bellud, normally via script/sync-bellu-graph):
//
//	sync-bellu-graph [flags] <40-hex-commit>
//
// Checksums: the sha256 of the fetched tarball must match the entry for the
// commit in the sum file (script/bellu-graph.sum). On the first sync of a new
// commit there is no entry; pass -record to trust the tarball on first use and
// record its sum after a successful sync. Review the diff before committing.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bellu/bellucode/services/bellud/internal/syncgraph"
)

func main() {
	var o syncgraph.Options
	flag.StringVar(&o.Out, "out", "internal/bellugraph", "vendored tree to replace")
	flag.StringVar(&o.MapPath, "map", "script/rename.map.yaml", "rename map")
	flag.StringVar(&o.SumPath, "sum", "script/bellu-graph.sum", "tarball checksum file")
	flag.BoolVar(&o.Record, "record", false, "trust on first use: record the tarball checksum if absent")
	flag.StringVar(&o.SrcDir, "src", "", "use a local upstream tree instead of fetching (no checksum)")
	flag.StringVar(&o.BaseURL, "url", "", "tarball URL prefix (default codeload.github.com/toise-dev/toise/tar.gz/)")
	flag.StringVar(&o.Regen, "regen", syncgraph.RegenAuto, "proto/GraphQL regeneration: auto|skip|required")
	flag.BoolVar(&o.KeepStaging, "keep-staging", false, "keep the staging dir on failure (debugging)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sync-bellu-graph [flags] <40-hex-commit>")
		os.Exit(2)
	}
	o.Commit = flag.Arg(0)
	o.Stderr = os.Stderr
	if err := syncgraph.Sync(o); err != nil {
		fmt.Fprintln(os.Stderr, "sync-bellu-graph: error:", err)
		os.Exit(1)
	}
	fmt.Println("synced", o.Commit, "->", o.Out)
}
