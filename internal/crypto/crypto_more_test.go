package crypto

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// TestDecryptRejectsGarbage: feeding non-age bytes to DecryptBytes must fail with a
// clear error rather than panicking.
func TestDecryptRejectsGarbage(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBytes([]byte("this is not an age blob"), id); err == nil {
		t.Fatal("expected an error decrypting garbage")
	}
}

// TestEncryptEmptyPlaintext: an empty .env is still a valid round trip.
func TestEncryptEmptyPlaintext(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncryptBytes(nil, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBytes(blob, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

// TestDecryptRejectsOversized: a blob that decrypts to more than the cap is
// refused, so a hostile blob can't exhaust memory.
func TestDecryptRejectsOversized(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	huge := make([]byte, maxPlaintextSize+1)
	blob, err := EncryptBytes(huge, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBytes(blob, id); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

// TestDecryptWithPassphraseRejectsGarbage mirrors the recipient path for the
// scrypt-based key encryption.
func TestDecryptWithPassphraseRejectsGarbage(t *testing.T) {
	if _, err := DecryptWithPassphrase([]byte("nonsense"), "pw"); err == nil {
		t.Fatal("expected an error decrypting garbage with a passphrase")
	}
}
