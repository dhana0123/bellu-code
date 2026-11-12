package engine

import (
	"context"
	"fmt"
)

// Close stops new writes, waits for in-flight ones (or ctx), stops background
// work, writes a final Snapshot and closes the store. It is idempotent. If ctx
// ends while waiting, Close returns its error and may be called again.
func (c *Core) Close(ctx context.Context) error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closing.Store(true)
	if c.State() == StateReady {
		c.setState(StateClosing, "close requested")
	}

	got := make(chan struct{})
	abandon := make(chan struct{})
	go func() {
		c.applyMu.Lock()
		select {
		case got <- struct{}{}:
		case <-abandon:
			c.applyMu.Unlock()
		}
	}()
	select {
	case <-got:
	case <-ctx.Done():
		close(abandon)
		return fmt.Errorf("closing graph engine: waiting for in-flight writes: %w", ctx.Err())
	}
	defer c.applyMu.Unlock()

	c.bgCancel()
	c.wg.Wait()
	for _, f := range c.onClose {
		f()
	}
	var firstErr error
	if c.State() != StateFailed {
		if err := c.writeSnapshot(); err != nil {
			firstErr = err
			c.log.Error("final snapshot failed", "error", err.Error())
		}
	}
	if err := c.st.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("closing store: %w", err)
	}
	c.closed = true
	c.setState(StateClosed, "closed")
	return firstErr
}
