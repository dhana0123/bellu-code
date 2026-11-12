// Package host is the host collector: processes, listening sockets and the
// hostname, read from /proc on Linux. On other platforms it observes nothing.
package host

import (
	"time"
)

// Name is the collector name.
const Name = "host"

// MinInterval is the smallest allowed tick interval.
const MinInterval = 5 * time.Second

// Collector implements collectors.Collector for the local host.
type Collector struct {
	procRoot hostRoot
	interval time.Duration
	hostname string // overrides os.Hostname when non-empty
}

type hostRoot string

// Option customizes a Collector.
type Option func(*Collector)

// WithProcRoot sets the proc filesystem root (default /proc).
func WithProcRoot(p string) Option { return func(c *Collector) { c.procRoot = hostRoot(p) } }

// WithHostname overrides the hostname (default os.Hostname).
func WithHostname(h string) Option { return func(c *Collector) { c.hostname = h } }

// New builds a host collector; interval is clamped to at least MinInterval.
func New(interval time.Duration, opts ...Option) *Collector {
	c := &Collector{procRoot: "/proc", interval: interval}
	for _, o := range opts {
		o(c)
	}
	if c.interval < MinInterval {
		c.interval = MinInterval
	}
	return c
}

// Name returns "host".
func (c *Collector) Name() string { return Name }

// Interval returns the tick interval (>= 5s).
func (c *Collector) Interval() time.Duration { return c.interval }
