package keysource

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "bellucode-bellud"
	keyringProbe   = "availability-probe"
	// keyringTimeout bounds every OS key store call: go-keyring can block on D-Bus
	// when no Secret Service is running.
	keyringTimeout = 3 * time.Second
)

var errKeyringTimeout = errors.New("keysource: os key store timed out")

type osKeyring struct {
	once      sync.Once
	available bool
}

// NewOSKeyring returns the OS key store source (Keychain, Credential Manager, Secret Service).
func NewOSKeyring() Rotatable { return &osKeyring{} }

func (k *osKeyring) Name() string { return NameOSKeyring }

// Available probes the store once with a bounded read. A missing probe entry
// proves the store works; any other error or a timeout means unavailable.
func (k *osKeyring) Available(ctx context.Context) bool {
	k.once.Do(func() {
		_, err := withTimeout(ctx, func() (string, error) { return keyring.Get(keyringService, keyringProbe) })
		k.available = err == nil || errors.Is(err, keyring.ErrNotFound)
	})
	return k.available
}

func (k *osKeyring) Load(ctx context.Context) ([]byte, error) {
	return k.LoadSlot(ctx, SlotCurrent)
}

func (k *osKeyring) LoadSlot(ctx context.Context, slot string) ([]byte, error) {
	v, err := withTimeout(ctx, func() (string, error) { return keyring.Get(keyringService, entryName(slot)) })
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	return parseKey([]byte(v))
}

func (k *osKeyring) Store(ctx context.Context, key []byte, slot string) error {
	if len(key) != KeyLen {
		return errors.New("keysource: master key must be 32 bytes")
	}
	enc := base64.StdEncoding.EncodeToString(key)
	_, err := withTimeout(ctx, func() (struct{}, error) {
		return struct{}{}, keyring.Set(keyringService, entryName(slot), enc)
	})
	return err
}

func (k *osKeyring) Promote(ctx context.Context) error {
	next, err := k.LoadSlot(ctx, SlotNext)
	if err != nil {
		return err
	}
	defer zero(next)
	if err := k.Store(ctx, next, SlotCurrent); err != nil {
		return err
	}
	_, err = withTimeout(ctx, func() (struct{}, error) {
		err := keyring.Delete(keyringService, entryName(SlotNext))
		if errors.Is(err, keyring.ErrNotFound) {
			err = nil
		}
		return struct{}{}, err
	})
	return err
}

func entryName(slot string) string { return "master-key/" + slot }

// withTimeout runs fn in a goroutine and gives up after keyringTimeout.
// A hung call leaks its goroutine, which is acceptable for a one-shot probe.
func withTimeout[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	timer := time.NewTimer(keyringTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-timer.C:
		var zeroV T
		return zeroV, errKeyringTimeout
	case <-ctx.Done():
		var zeroV T
		return zeroV, ctx.Err()
	}
}
