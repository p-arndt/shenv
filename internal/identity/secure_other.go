//go:build !windows

package identity

import (
	"fmt"
	"os"
)

// SecureFile enforces owner-only permissions on a secret-holding file (the key
// file, edit's transient plaintext). On Unix the 0600 mode bits are honoured
// directly, so this just re-asserts them in case the umask interfered.
func SecureFile(path string) error {
	return os.Chmod(path, 0o600)
}

// checkKeyPermissions refuses to use a key that group or other can reach. A key
// without a passphrase is protected by nothing else, and a copied or restored
// file easily arrives with the source's looser mode — same stance as ssh.
func checkKeyPermissions(path string, fi os.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("key file %s is accessible by other users (permissions %04o) — run `chmod 600 %s`", path, perm, path)
	}
	return nil
}
