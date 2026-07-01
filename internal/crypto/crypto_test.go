package crypto

import (
	"testing"

	"filippo.io/age"
)

// TestEncryptDecryptRoundTrip verifies that a blob encrypted for a recipient can
// be decrypted with the matching identity, and that a non-recipient cannot.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	want := []byte("API_KEY=secret\nDB_PASS=hunter2\n")

	member, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	blob, err := EncryptBytes(want, []age.Recipient{member.Recipient()})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptBytes(blob, member)
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
	if _, err := DecryptBytes(blob, stranger); err == nil {
		t.Fatal("expected non-recipient decryption to fail, got nil error")
	}
}

// TestPassphraseRoundTrip verifies scrypt encrypt/decrypt of raw bytes and that a
// wrong passphrase is rejected.
func TestPassphraseRoundTrip(t *testing.T) {
	want := []byte("AGE-SECRET-KEY-1EXAMPLE")

	blob, err := EncryptWithPassphrase(want, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptWithPassphrase(blob, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("round trip mismatch: got %q want %q", got, want)
	}

	if _, err := DecryptWithPassphrase(blob, "wrong"); err == nil {
		t.Fatal("expected wrong passphrase to fail, got nil error")
	}
}
