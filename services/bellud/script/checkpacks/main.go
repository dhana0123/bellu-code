// Command checkpacks validates every Rule_Pack (Requirement 23.12) with the
// posture loader, so the build check and the engine share one validator.
//
// It checks the bundled packs, or the pack directories under the directory given
// as the first argument. It reports "<pack>/<rule id>: <check>: <detail>" where
// check is "schema" or "compile", and exits 1 on any failure.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/posture"
)

func run(root fs.FS) (failures []string, packs, rules int, err error) {
	ps, errs, err := posture.LoadAll(root)
	if err != nil {
		return nil, 0, 0, err
	}
	for _, p := range ps {
		rules += len(p.Rules)
	}
	for _, e := range errs {
		failures = append(failures, e.Error())
	}
	sort.Strings(failures)
	return failures, len(ps), rules + len(failures), nil
}

func main() {
	root := posture.Bundled()
	if len(os.Args) > 1 {
		root = os.DirFS(os.Args[1])
	}
	failures, packs, rules, err := run(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, f := range failures {
		fmt.Println("FAIL", f)
	}
	if len(failures) > 0 {
		os.Exit(1)
	}
	fmt.Printf("rule packs OK (%d packs, %d rules)\n", packs, rules)
}
