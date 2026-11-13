package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
)

// verifyModes requires directory 0700 and vault.json 0600. It tries to fix a
// wrong mode once, then refuses to load without touching data.
func verifyModes(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if err := ensureMode(dir, fi, 0o700, "directory"); err != nil {
		return err
	}
	p := filepath.Join(dir, vaultFile)
	fi, err = os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return ensureMode(p, fi, 0o600, "store")
}

func ensureMode(path string, fi os.FileInfo, want os.FileMode, class string) error {
	if fi.Mode().Perm() == want {
		return nil
	}
	reason := "mode is not " + modeString(want)
	if err := os.Chmod(path, want); err != nil {
		return &keysource.PermissionError{Class: class, Reason: reason}
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
		return &keysource.PermissionError{Class: class, Reason: reason}
	}
	return nil
}

func modeString(m os.FileMode) string {
	if m == 0o700 {
		return "0700"
	}
	return "0600"
}

func readDoc(dir string) (fileDoc, error) {
	raw, err := os.ReadFile(filepath.Join(dir, vaultFile))
	if errors.Is(err, os.ErrNotExist) {
		return fileDoc{Version: fileFormat}, nil
	}
	if err != nil {
		return fileDoc{}, err
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != fileFormat {
		return fileDoc{}, ErrCorrupt
	}
	return doc, nil
}

// writeFile writes doc to path (0600) and fsyncs it.
func writeFile(path string, doc fileDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// commit renames dir/name over vault.json and fsyncs the directory.
func commit(dir, name string) error {
	if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, vaultFile)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
