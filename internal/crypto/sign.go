package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
)

// Signing gives pull/run sender authentication: age encryption alone hides the
// contents from outsiders, but since the recipient keys are public, anyone could
// craft a valid-looking env.shenv for the team. A signature made with a member's
// key proves the blob really came from that member.
//
// The Ed25519 signing key is derived deterministically from the age identity via
// HKDF, so there is only one secret to create, protect, and back up — the age key
// in ~/.shenv/key.txt. The X25519 scalar is never reused directly as a signing
// key; HKDF makes the two keys cryptographically independent.

// signKeyInfo domain-separates the derived signing key from any future derivation.
const signKeyInfo = "shenv signing key v1"

// DeriveSigningKey returns the Ed25519 signing key for an age identity.
func DeriveSigningKey(id *age.X25519Identity) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, []byte(id.String()), nil, signKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// VerifyKeyString encodes the public half of a signing key for recipients.shenv.
func VerifyKeyString(key ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

// ParseVerifyKey decodes a verify key as printed by `shenv whoami`.
func ParseVerifyKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signing key %q (expected the base64 key from `shenv whoami`)", s)
	}
	return ed25519.PublicKey(raw), nil
}
