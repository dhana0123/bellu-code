//go:build !unix

package runtimeevents

func setUmask(m int) int { return m }
