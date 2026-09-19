package command

import (
	"fmt"
	"os"
	"path/filepath"

	"shenv/internal/identity"
)

// writePlaintext replaces path with the decrypted secrets, making sure they are
// never readable by anyone but the owner — not even for the instant between the
// first byte landing and the permissions being tightened.
//
// Writing into the destination directly is what makes that window: an existing
// file keeps its old (possibly world-readable) mode while the secrets go in, and
// on Windows the Unix mode bits do nothing at all, so the plaintext simply
// inherits the directory's ACL. A reader that opens the file during the window
// keeps access through its descriptor no matter what happens afterwards.
//
// So the bytes go into a file created exclusively beside the destination —
// O_EXCL means it is ours and no pre-planted symlink is followed — which is
// locked down with identity.SecureFile while still empty, and only then takes
// the destination's name. Every step is checked; on any failure the temporary
// file is removed rather than left behind full of secrets.
func writePlaintext(path string, data []byte) error {
	// os.Rename replaces a symlink instead of following it, but a symlinked
	// destination still means the write was aimed somewhere the caller did not
	// choose — refuse it here too, independently of the caller's own checks.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to follow it", path)
	}

	// Same directory as the destination so the final rename is atomic — across
	// filesystems it would degrade to a copy, reintroducing the exposure window.
	f, err := os.CreateTemp(filepath.Dir(path), plaintextTempPrefix+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}

	if err := identity.SecureFile(tmp); err != nil {
		return fail(fmt.Errorf("securing %s before writing secrets to it: %w", tmp, err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	// Sync before the rename: a crash must not leave the destination's name
	// pointing at an empty or half-written .env.
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
