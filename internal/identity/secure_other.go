//go:build !windows

package identity

import "os"

// secureKeyFile enforces owner-only permissions. On Unix the 0600 mode bits are
// honoured directly, so this just re-asserts them in case the umask interfered.
func secureKeyFile(path string) error {
	return os.Chmod(path, 0o600)
}
