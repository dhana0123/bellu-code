package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Defaults and bounds for the scanners.* keys (Requirements 18.2, 18.4, 18.5).
const (
	DefaultScannersParallel   = 2
	MinScannersParallel       = 1
	MaxScannersParallel       = 16
	DefaultScannersJobTimeout = time.Hour
	MinScannersJobTimeout     = 30 * time.Second
	MaxScannersJobTimeout     = 24 * time.Hour
)

// Scanners holds the scanners.* configuration keys. Each key is read from
// BELLUCODE_ plus the key in upper case with "." replaced by "_", for example
// BELLUCODE_SCANNERS_PARALLEL.
type Scanners struct {
	Parallel   int           // scanners.parallel: 1 to 16, default 2
	JobTimeout time.Duration // scanners.job_timeout: 30 s to 24 h, default 1 h
	AutoScan   bool          // scanners.auto_scan: default false
}

// DefaultScanners returns the defaults.
func DefaultScanners() Scanners {
	return Scanners{Parallel: DefaultScannersParallel, JobTimeout: DefaultScannersJobTimeout}
}

// Validate checks the bounds of Parallel and JobTimeout.
func (c Scanners) Validate() error {
	if c.Parallel < MinScannersParallel || c.Parallel > MaxScannersParallel {
		return fmt.Errorf("invalid scanners.parallel %d: want an integer from 1 to 16", c.Parallel)
	}
	if c.JobTimeout < MinScannersJobTimeout || c.JobTimeout > MaxScannersJobTimeout {
		return fmt.Errorf("invalid scanners.job_timeout %s: want 30s to 24h", c.JobTimeout)
	}
	return nil
}

// LoadScanners reads and validates the scanners.* keys through env. An empty
// value counts as unset.
func LoadScanners(env func(string) (string, bool)) (Scanners, error) {
	c := DefaultScanners()
	lookup := func(key string) (string, bool) {
		v, _ := env(envName(key))
		v = strings.TrimSpace(v)
		return v, v != ""
	}
	if v, ok := lookup("scanners.parallel"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("invalid scanners.parallel %q: want an integer from 1 to 16", v)
		}
		c.Parallel = n
	}
	if v, ok := lookup("scanners.job_timeout"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("invalid scanners.job_timeout %q: want a duration from 30s to 24h", v)
		}
		c.JobTimeout = d
	}
	if v, ok := lookup("scanners.auto_scan"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid scanners.auto_scan %q: want true or false", v)
		}
		c.AutoScan = b
	}
	return c, c.Validate()
}
