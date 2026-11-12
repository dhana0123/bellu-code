package engine

import (
	"log/slog"
	"time"
)

// Options configure Open. Zero values select the design defaults; tests
// override them.
type Options struct {
	Logger *slog.Logger     // nil: slog.Default()
	Clock  func() time.Time // nil: time.Now

	Retention        time.Duration // 0: keep everything
	SnapshotInterval time.Duration // default 5m
	SnapshotEvery    int           // events between Snapshots, default 10000
	SnapshotKeep     int           // Snapshots kept besides the base, default 8
	RetentionCheck   time.Duration // default 1h

	LocalIDIdle      time.Duration // default 15m
	LocalIDTombstone time.Duration // default 24h
	LocalIDSweep     time.Duration // default 1m

	SubscriberBuffer int // default 256
}

func (o Options) withDefaults() Options {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.SnapshotInterval <= 0 {
		o.SnapshotInterval = 5 * time.Minute
	}
	if o.SnapshotEvery <= 0 {
		o.SnapshotEvery = 10000
	}
	if o.SnapshotKeep <= 0 {
		o.SnapshotKeep = 8
	}
	if o.RetentionCheck <= 0 {
		o.RetentionCheck = time.Hour
	}
	if o.LocalIDIdle <= 0 {
		o.LocalIDIdle = 15 * time.Minute
	}
	if o.LocalIDTombstone <= 0 {
		o.LocalIDTombstone = 24 * time.Hour
	}
	if o.LocalIDSweep <= 0 {
		o.LocalIDSweep = time.Minute
	}
	if o.SubscriberBuffer <= 0 {
		o.SubscriberBuffer = 256
	}
	return o
}
