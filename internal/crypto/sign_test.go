package crypto

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/age"
)

// TestDeriveSigningKeyDeterministic: the signing key is derived, not stored, so
// the same identity must always yield the same key — across machines and runs.
func TestDeriveSigningKeyDeterministic(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("derivation must be deterministic")
	}

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := DeriveSigningKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(c) {
		t.Fatal("different identities must derive different signing keys")
	}
}

func TestVerifyKeyStringRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	encoded := VerifyKeyString(key)
	parsed, err := ParseVerifyKey(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(key.Public().(ed25519.PublicKey)) {
		t.Fatal("round trip must recover the same verify key")
	}
}

func TestParseVerifyKeyRejectsGarbage(t *testing.T) {
	for _, s := range []string{
		"",
		"not base64 !!",
		"c2hvcnQ",                       // valid base64, wrong length
		"age1qqqqqqqqqqqqqqqqqqqqqqqqq", // an age key is not a verify key
	} {
		if _, err := ParseVerifyKey(s); err == nil {
			t.Errorf("%q should be rejected", s)
		}
	}
}
