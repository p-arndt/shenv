package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// TestEncryptDecryptRoundTrip verifies that a file encrypted for a recipient can
// be decrypted with the matching identity, and that a non-recipient cannot.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.txt")
	encPath := filepath.Join(dir, "blob.age")
	want := []byte("API_KEY=secret\nDB_PASS=hunter2\n")

	if err := os.WriteFile(plainPath, want, 0o600); err != nil {
		t.Fatal(err)
	}

	member, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(plainPath, encPath, []age.Recipient{member.Recipient()}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptFile(encPath, member)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("round trip mismatch: got %q want %q", got, want)
	}

	// A different identity must not be able to decrypt.
	stranger, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptFile(encPath, stranger); err == nil {
		t.Fatal("expected non-recipient decryption to fail, got nil error")
	}
}
