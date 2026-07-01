package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsEncrypted(t *testing.T) {
	t.Run("plaintext key", func(t *testing.T) {
		tempHome(t)
		if _, err := Create(""); err != nil {
			t.Fatal(err)
		}
		enc, err := IsEncrypted()
		if err != nil {
			t.Fatal(err)
		}
		if enc {
			t.Fatal("plaintext key reported as encrypted")
		}
	})

	t.Run("passphrase key", func(t *testing.T) {
		tempHome(t)
		if _, err := Create("hunter2"); err != nil {
			t.Fatal(err)
		}
		enc, err := IsEncrypted()
		if err != nil {
			t.Fatal(err)
		}
		if !enc {
			t.Fatal("passphrase key reported as plaintext")
		}
	})

	t.Run("no identity", func(t *testing.T) {
		tempHome(t)
		if _, err := IsEncrypted(); err == nil {
			t.Fatal("expected an error when no identity exists")
		}
	})
}

// TestCreateRefusesOverwrite: a second Create must never clobber an existing key,
// or a user would silently lose access to everything encrypted for the old one.
func TestCreateRefusesOverwrite(t *testing.T) {
	tempHome(t)
	first, err := Create("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(""); err == nil {
		t.Fatal("second Create should have refused to overwrite")
	}
	// The original key must survive untouched.
	got, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Recipient().String() != first.Recipient().String() {
		t.Fatal("existing key was modified by the refused Create")
	}
}

func TestPublicKeyNoIdentity(t *testing.T) {
	tempHome(t)
	if _, err := PublicKey(); err == nil {
		t.Fatal("expected an error when no identity exists")
	}
}

func TestLoadNoIdentity(t *testing.T) {
	tempHome(t)
	if _, err := Load(nil); err == nil {
		t.Fatal("expected an error when no identity exists")
	}
}

// TestLoadRejectsEmptyKeyFile: a key file with only comments/blank lines has no
// usable key and must error rather than return a nil identity.
func TestLoadRejectsEmptyKeyFile(t *testing.T) {
	tempHome(t)
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# just a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("expected a 'no key' error, got %v", err)
	}
}

// TestPublicKeyEncryptedMissingComment: an encrypted key file whose plaintext
// public-key comment was stripped can't answer `whoami` and must say so.
func TestPublicKeyEncryptedMissingComment(t *testing.T) {
	tempHome(t)
	if _, err := Create("hunter2"); err != nil {
		t.Fatal(err)
	}
	path, _ := Path()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the "# public key:" comment line, keeping the armored body.
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, pubKeyComment) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKey(); err == nil {
		t.Fatal("expected an error for an encrypted key missing its public-key comment")
	}
}
