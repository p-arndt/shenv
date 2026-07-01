// Package identity manages the user's global age keypair — the private key that
// lives in ~/.shenv/key.txt and is created once, then reused across every repo
// (like an SSH key). The key may optionally be encrypted with a passphrase.
package identity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"shenv/internal/crypto"
)

// armorMarker identifies a passphrase-encrypted key file.
const armorMarker = "-----BEGIN AGE ENCRYPTED FILE-----"

// pubKeyComment prefixes the plaintext public-key line kept in every key file,
// so `whoami` can work without unlocking an encrypted key.
const pubKeyComment = "# public key:"

// PassphraseFunc is called only when an encrypted key needs to be unlocked.
type PassphraseFunc func() (string, error)

// Path returns the location of the user's private key file (~/.shenv/key.txt).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "key.txt"), nil
}

// Load reads the user's private key. If it is passphrase-encrypted, ask is
// invoked to obtain the passphrase (and must not be nil in that case).
func Load(ask PassphraseFunc) (*age.X25519Identity, error) {
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

	if isEncrypted(data) {
		if ask == nil {
			return nil, fmt.Errorf("key is passphrase-protected but no passphrase was provided")
		}
		passphrase, err := ask()
		if err != nil {
			return nil, err
		}
		blob := data[bytes.Index(data, []byte(armorMarker)):]
		plain, err := crypto.DecryptWithPassphrase(blob, passphrase)
		if err != nil {
			return nil, err
		}
		return age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	}

	return parsePlaintextKey(data)
}

// PublicKey returns the user's public key without needing a passphrase: for an
// encrypted key it is read from the plaintext comment, otherwise derived directly.
func PublicKey() (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no identity found — run `shenv init` first")
		}
		return "", err
	}

	if isEncrypted(data) {
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if after, ok := strings.CutPrefix(line, pubKeyComment); ok {
				return strings.TrimSpace(after), nil
			}
		}
		return "", fmt.Errorf("encrypted key file is missing its public-key comment")
	}

	id, err := parsePlaintextKey(data)
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// Create generates a fresh keypair and writes it to the global key file. If
// passphrase is non-empty, the private key is encrypted at rest. It refuses to
// overwrite an existing key.
func Create(passphrase string) (*age.X25519Identity, error) {
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

	content, err := renderKeyFile(id, passphrase)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// 0o600 covers Unix; Windows ignores it, so secureKeyFile enforces the ACL.
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return nil, err
	}
	if err := secureKeyFile(path); err != nil {
		// Never leave a key on disk we couldn't lock down.
		os.Remove(path)
		return nil, fmt.Errorf("securing key file: %w", err)
	}
	return id, nil
}

// renderKeyFile builds the on-disk contents for a key, encrypting the secret when
// a passphrase is given. The public key is always kept as a plaintext comment.
func renderKeyFile(id *age.X25519Identity, passphrase string) ([]byte, error) {
	pub := id.Recipient().String()
	if passphrase == "" {
		return fmt.Appendf(nil,
			"# shenv identity — keep this file secret, never share or commit it\n%s %s\n%s\n",
			pubKeyComment, pub, id.String()), nil
	}

	blob, err := crypto.EncryptWithPassphrase([]byte(id.String()), passphrase)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(
		"# shenv identity (passphrase-encrypted) — keep secret; needs your passphrase to use\n%s %s\n",
		pubKeyComment, pub)
	return append([]byte(header), blob...), nil
}

// parsePlaintextKey extracts the age secret key from an unencrypted key file.
func parsePlaintextKey(data []byte) (*age.X25519Identity, error) {
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return age.ParseX25519Identity(line)
	}
	return nil, fmt.Errorf("key file contains no key")
}

// IsEncrypted reports whether the on-disk key is passphrase-protected.
func IsEncrypted() (bool, error) {
	path, err := Path()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Errorf("no identity found — run `shenv init` first")
		}
		return false, err
	}
	return isEncrypted(data), nil
}

// isEncrypted reports whether the key file is passphrase-protected.
func isEncrypted(data []byte) bool {
	return bytes.Contains(data, []byte(armorMarker))
}
