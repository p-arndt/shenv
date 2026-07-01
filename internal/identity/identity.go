// Package identity manages the user's global age keypair — the private key that
// lives in ~/.shenv/key.txt and is created once, then reused across every repo
// (like an SSH key).
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Path returns the location of the user's private key file (~/.shenv/key.txt).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "key.txt"), nil
}

// Load reads the user's private key from disk.
func Load() (*age.X25519Identity, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no identity found — run `shenv init` first")
		}
		return nil, err
	}
	// The file may contain comment lines; take the first key line.
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return age.ParseX25519Identity(line)
	}
	return nil, fmt.Errorf("identity file %s contains no key", path)
}

// Create generates a fresh keypair and writes it to the global key file.
// It refuses to overwrite an existing key.
func Create() (*age.X25519Identity, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("identity already exists at %s — remove it manually to regenerate", path)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	content := fmt.Sprintf("# shenv identity — keep this file secret, never share or commit it\n# public key: %s\n%s\n",
		id.Recipient().String(), id.String())
	// 0o600: readable only by the owner.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
