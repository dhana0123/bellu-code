//go:build sizeprobe && sizebase

package main

// imports is the baseline: no scanner libraries linked.
func imports() int { return 0 }
