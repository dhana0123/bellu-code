package keysource

import (
	"context"
	"os"
	"path/filepath"
)

const (
	credentialsEnv  = "CREDENTIALS_DIRECTORY"
	systemdCredName = "bellucode-master-key"
)

type systemd struct{}

// NewSystemd returns the systemd credential source (LoadCredentialEncrypted).
// It is read-only: the key is provisioned with systemd-creds.
func NewSystemd() Source { return systemd{} }

func (systemd) Name() string { return NameSystemd }

func (systemd) path() string {
	dir := os.Getenv(credentialsEnv)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, systemdCredName)
}

func (s systemd) Available(context.Context) bool {
	p := s.path()
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Load reads the credential and then unsets CREDENTIALS_DIRECTORY so the
// location is not inherited by child processes.
func (s systemd) Load(context.Context) ([]byte, error) {
	p := s.path()
	if p == "" {
		return nil, ErrNoKey
	}
	raw, err := os.ReadFile(p)
	os.Unsetenv(credentialsEnv)
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	return parseKey(raw)
}

func (systemd) Store(context.Context, []byte, string) error { return ErrStoreUnsupported }
