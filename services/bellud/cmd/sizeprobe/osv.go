//go:build sizeprobe && !sizebase && osvmatch

package main

import "github.com/google/osv-scanner/v2/pkg/osvscanner"

func osvCount() int {
	fns := []any{osvscanner.DoScan}
	return len(fns)
}
