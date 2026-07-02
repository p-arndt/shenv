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

// signKeyComment prefixes the plaintext verify-key line, kept for the same
// reason: `whoami` must print it without a passphrase prompt.
const signKeyComment = "# signing key:"

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

// VerifyKey returns the user's public signing key. Like PublicKey it avoids the
// passphrase where possible: a plaintext key derives it directly, an encrypted
// key reads it from the comment. Key files written before signing existed lack
// that comment; then ask unlocks the key once and the comment is added so the
// next call is silent again.
func VerifyKey(ask PassphraseFunc) (string, error) {
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

	if !isEncrypted(data) {
		id, err := parsePlaintextKey(data)
		if err != nil {
			return "", err
		}
		return deriveVerifyKey(id)
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), signKeyComment); ok {
			return strings.TrimSpace(after), nil
		}
	}

	id, err := Load(ask)
	if err != nil {
		return "", err
	}
	verify, err := deriveVerifyKey(id)
	if err != nil {
		return "", err
	}
	// Best-effort self-heal: record the comment so future calls skip the unlock.
	// Failing to write it is not fatal — the derived key is already in hand.
	if healed, ok := insertSignComment(data, verify); ok {
		_ = os.WriteFile(path, healed, 0o600)
	}
	return verify, nil
}

// deriveVerifyKey computes the encoded public signing key for an identity.
func deriveVerifyKey(id *age.X25519Identity) (string, error) {
	key, err := crypto.DeriveSigningKey(id)
	if err != nil {
		return "", err
	}
	return crypto.VerifyKeyString(key), nil
}

// insertSignComment places the signing-key comment right after the public-key
// comment. ok is false if no public-key line was found to anchor on.
func insertSignComment(data []byte, verify string) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), pubKeyComment) {
			withComment := append(lines[:i+1:i+1], fmt.Sprintf("%s %s", signKeyComment, verify))
			return []byte(strings.Join(append(withComment, lines[i+1:]...), "\n")), true
		}
	}
	return nil, false
}

// Create generates a fresh keypair and writes it to the global key file. If
// passphrase is non-empty, the private key is encrypted at rest. It refuses to
// overwrite an existing key.
func Create(passphrase string) (*age.X25519Identity, error) {
	path, err := Path()
	if err != nil {
		return nil, err
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
	// O_EXCL makes create-if-absent atomic: no stat/write race, and it refuses to
	// follow a pre-planted symlink at the key path. 0o600 covers Unix; Windows
	// ignores it, so secureKeyFile enforces the ACL below.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("identity already exists at %s — remove it manually to regenerate", path)
		}
		return nil, err
	}
	// Lock the still-empty file down before the secret touches disk: on Windows
	// a fresh file starts with the directory's inherited ACL, so writing first
	// would briefly expose the key bytes to whoever that ACL admits.
	if err := secureKeyFile(path); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("securing key file: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return id, nil
}

// renderKeyFile builds the on-disk contents for a key, encrypting the secret when
// a passphrase is given. The public key and the public signing key are always
// kept as plaintext comments.
func renderKeyFile(id *age.X25519Identity, passphrase string) ([]byte, error) {
	pub := id.Recipient().String()
	verify, err := deriveVerifyKey(id)
	if err != nil {
		return nil, err
	}
	if passphrase == "" {
		return fmt.Appendf(nil,
			"# shenv identity — keep this file secret, never share or commit it\n%s %s\n%s %s\n%s\n",
			pubKeyComment, pub, signKeyComment, verify, id.String()), nil
	}

	blob, err := crypto.EncryptWithPassphrase([]byte(id.String()), passphrase)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(
		"# shenv identity (passphrase-encrypted) — keep secret; needs your passphrase to use\n%s %s\n%s %s\n",
		pubKeyComment, pub, signKeyComment, verify)
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
