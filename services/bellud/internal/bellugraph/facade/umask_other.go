//go:build windows

package facade

// setUmask is a no-op where umask does not exist.
func setUmask(m int) int { return m }
