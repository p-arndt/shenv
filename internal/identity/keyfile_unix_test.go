//go:build !windows

package identity

import (
	"os"
	"strings"
	"testing"
)

// TestCreateProducesAcceptedPermissions: what Create writes must pass the check
// Load applies, or the tool would refuse its own key.
func TestCreateProducesAcceptedPermissions(t *testing.T) {
	tempHome(t)
	if _, err := Create(""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(nil); err != nil {
		t.Fatalf("freshly created key rejected: %v", err)
	}
}

// TestLoadRefusesGroupOrOtherAccess: a key restored from a backup or copied from
// another machine keeps the source's mode, and without a passphrase that mode is
// the only thing protecting it.
func TestLoadRefusesGroupOrOtherAccess(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o666} {
		tempHome(t)
		if _, err := Create(""); err != nil {
			t.Fatal(err)
		}
		path, err := Path()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}

		_, err = Load(nil)
		if err == nil {
			t.Fatalf("mode %04o: Load accepted a world/group-accessible key", mode)
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o: error should say how to fix it, got %v", mode, err)
		}
		for _, check := range []func() error{
			func() error { _, err := PublicKey(); return err },
			func() error { _, err := VerifyKey(nil); return err },
			func() error { _, err := IsEncrypted(); return err },
		} {
			if check() == nil {
				t.Errorf("mode %04o: a key reader accepted the exposed key", mode)
			}
		}
	}
}

// TestLoadRefusesSymlinkedKey: following the link would read a file whose own
// permissions were never checked, and could point anywhere.
func TestLoadRefusesSymlinkedKey(t *testing.T) {
	tempHome(t)
	if _, err := Create(""); err != nil {
		t.Fatal(err)
	}
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	real := path + ".real"
	if err := os.Rename(path, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink refusal, got %v", err)
	}
}

// TestLoadRefusesNonRegularKey: anything that is not a plain file at the key
// path (a directory here, a fifo in the hostile case) is refused rather than
// read.
func TestLoadRefusesNonRegularKey(t *testing.T) {
	tempHome(t)
	if _, err := Create(""); err != nil {
		t.Fatal(err)
	}
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected a non-regular-file refusal, got %v", err)
	}
}
