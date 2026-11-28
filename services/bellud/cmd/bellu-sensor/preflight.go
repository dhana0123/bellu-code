//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// Status values reported to bellud (Requirement 15.2).
const (
	StatusOK          = "ok"
	StatusUnsupported = "unsupported"

	ReasonKernelTooOld = "kernel_too_old"
	ReasonBTFMissing   = "btf_missing"
)

const btfPath = "/sys/kernel/btf/vmlinux"

// Preflight reports whether probes may be attached.
type Preflight struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// CheckKernel returns unsupported when release is older than 5.8 or btfExists is false.
// The kernel version is checked first.
func CheckKernel(release string, btfExists bool) Preflight {
	if !kernelAtLeast(release, 5, 8) {
		return Preflight{Status: StatusUnsupported, Reason: ReasonKernelTooOld}
	}
	if !btfExists {
		return Preflight{Status: StatusUnsupported, Reason: ReasonBTFMissing}
	}
	return Preflight{Status: StatusOK}
}

// RunPreflight reads the running kernel release and BTF availability.
func RunPreflight() (Preflight, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return Preflight{}, fmt.Errorf("read kernel release: %w", err)
	}
	_, statErr := os.Stat(btfPath)
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return Preflight{}, fmt.Errorf("stat %s: %w", btfPath, statErr)
	}
	return CheckKernel(strings.TrimSpace(string(raw)), statErr == nil), nil
}

// kernelAtLeast parses "5.15.0-91-generic" style releases. Unparseable releases count as too old.
func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minStr := parts[1]
	if i := strings.IndexFunc(minStr, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minStr = minStr[:i]
	}
	mnr, err := strconv.Atoi(minStr)
	if err != nil {
		return false
	}
	return maj > major || (maj == major && mnr >= minor)
}
