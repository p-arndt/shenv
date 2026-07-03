//go:build !windows

package identity

import "os"

// SecureFile enforces owner-only permissions on a secret-holding file (the key
// file, edit's transient plaintext). On Unix the 0600 mode bits are honoured
// directly, so this just re-asserts them in case the umask interfered.
func SecureFile(path string) error {
	return os.Chmod(path, 0o600)
}
