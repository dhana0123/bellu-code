//go:build sizeprobe

// Command sizeprobe is a build-tagged spike used only to measure the linked
// binary size of the scanner libraries (Requirement 19.8). It is not shipped.
// Build with script/check-binary-size.sh.
package main

import "fmt"

func main() {
	fmt.Println("sizeprobe", imports())
}
