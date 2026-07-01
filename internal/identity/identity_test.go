package identity

import "testing"

// tempHome points ~/.shenv at a throwaway directory for the duration of a test.
func tempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)        // Unix
	t.Setenv("USERPROFILE", dir) // Windows
}

func TestPlaintextRoundTrip(t *testing.T) {
	tempHome(t)

	id, err := Create("")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := Load(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Fatal("loaded identity does not match created one")
	}

	pub, err := PublicKey()
	if err != nil {
		t.Fatalf("publickey: %v", err)
	}
	if pub != id.Recipient().String() {
		t.Fatalf("public key mismatch: got %s", pub)
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	tempHome(t)
	const pass = "hunter2"

	id, err := Create(pass)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Public key must be readable WITHOUT the passphrase.
	pub, err := PublicKey()
	if err != nil {
		t.Fatalf("publickey: %v", err)
	}
	if pub != id.Recipient().String() {
		t.Fatalf("public key mismatch: got %s", pub)
	}

	// Correct passphrase unlocks the same identity.
	got, err := Load(func() (string, error) { return pass, nil })
	if err != nil {
		t.Fatalf("load with correct passphrase: %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Fatal("unlocked identity does not match created one")
	}

	// Wrong passphrase must fail.
	if _, err := Load(func() (string, error) { return "nope", nil }); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}

	// No passphrase provider for an encrypted key must fail, not panic.
	if _, err := Load(nil); err == nil {
		t.Fatal("expected nil passphrase func to fail on encrypted key")
	}
}
