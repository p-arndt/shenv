package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/recipients"
)

// These tests cover sender authentication: pull must only accept an env.shenv
// that was signed by a current member. The recipient keys in recipients.shenv
// are public, so without the signature anyone could encrypt a replacement blob
// "for the team".

// plantBlob encrypts a payload for the given age public key and writes it where
// pull will fetch it — simulating an attacker (or an old shenv) replacing the blob.
func plantBlob(t *testing.T, payload []byte, pub string) {
	t.Helper()
	rec, err := age.ParseX25519Recipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.EncryptBytes(payload, []age.Recipient{rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.DefaultBlobPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPullRejectsUnsignedBlob: a blob without a signer line (older shenv or a
// stripped payload) must be refused, not silently trusted.
func TestPullRejectsUnsignedBlob(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	members, _ := recipients.Load()
	plantBlob(t, recipients.EmbedManifest([]byte("X=1\n"), members), pub)

	feed(t, "")
	if err := Pull(nil); err == nil {
		t.Fatal("pulling an unsigned blob must fail")
	}
	if _, err := os.Stat(defaultEnvFile); err == nil {
		t.Fatal("a rejected blob must not produce a .env")
	}
}

// TestPullRejectsForgedSignature: an outsider knows every public key from the
// committed recipients.shenv, so they can encrypt a blob the team can decrypt —
// but they can only sign it with their own key. Claiming a member's name must
// not get that signature accepted.
func TestPullRejectsForgedSignature(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	members, _ := recipients.Load()

	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := recipients.SealPayload([]byte("EVIL=1\n"), members, "me", attackerKey)
	plantBlob(t, forged, pub)

	feed(t, "")
	if err := Pull(nil); err == nil {
		t.Fatal("a blob signed with a non-member key must be rejected")
	}
	if _, err := os.Stat(defaultEnvFile); err == nil {
		t.Fatal("a rejected blob must not produce a .env")
	}
}

// TestPullRejectsUnknownSigner: a signature by a name that is not in
// recipients.shenv (a removed member, or a made-up identity) must be refused.
func TestPullRejectsUnknownSigner(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	members, _ := recipients.Load()

	_, strangerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plantBlob(t, recipients.SealPayload([]byte("X=1\n"), members, "stranger", strangerKey), pub)

	feed(t, "")
	if err := Pull(nil); err == nil {
		t.Fatal("a signer missing from recipients.shenv must be rejected")
	}
}

// TestPullAcceptsTeammatesPush: multi-user — a blob pushed (and signed) by one
// member must verify for another member who only has the shared recipients file.
func TestPullAcceptsTeammatesPush(t *testing.T) {
	setup(t)
	mustInit(t) // "me", the puller

	// A teammate with their own identity, registered alongside "me".
	mate, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	mateSign, err := crypto.DeriveSigningKey(mate)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipients.Add("mate", mate.Recipient().String(), crypto.VerifyKeyString(mateSign)); err != nil {
		t.Fatal(err)
	}

	// The teammate pushes: seals with their key, encrypts for everyone.
	members, _ := recipients.Load()
	keys, err := recipients.Keys(members)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.EncryptBytes(recipients.SealPayload([]byte("SHARED=1\n"), members, "mate", mateSign), keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.DefaultBlobPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	feed(t, "")
	if err := Pull(nil); err != nil {
		t.Fatalf("a teammate's signed push must verify: %v", err)
	}
	got, err := os.ReadFile(defaultEnvFile)
	if err != nil || string(got) != "SHARED=1\n" {
		t.Fatalf("unexpected .env: %q, %v", got, err)
	}
}
