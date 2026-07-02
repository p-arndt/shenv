package command

import (
	"bytes"
	"os"
	"testing"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/identity"
	"shenv/internal/recipients"
)

// These tests cover the lockout guards: pushing without yourself in the list,
// pushing a recipient set that drops someone who can decrypt today, and
// overwriting a blob you cannot read.

// TestPushSelfMissingAborts: an identity exists but was never registered in this
// repo (init ran elsewhere) — push must warn and, on decline, write nothing.
func TestPushSelfMissingAborts(t *testing.T) {
	setup(t)
	if _, err := identity.Create(""); err != nil {
		t.Fatal(err)
	}
	// Only a teammate is registered — the classic "add-member but never init" trap.
	if err := recipients.Add("alice", testPubKey(t)); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")

	feed(t, "n\n") // decline the self-missing warning
	if err := Push(nil); err != nil {
		t.Fatalf("push should return nil (aborted), got %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err == nil {
		t.Fatal("aborted push must not write the blob")
	}
}

func TestPushSelfMissingProceedsWhenConfirmed(t *testing.T) {
	setup(t)
	if _, err := identity.Create(""); err != nil {
		t.Fatal(err)
	}
	if err := recipients.Add("alice", testPubKey(t)); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")

	// self-missing warning, then the first-push foreign-recipient confirmation
	feed(t, "y\ny\n")
	if err := Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err != nil {
		t.Fatalf("confirmed push should write the blob: %v", err)
	}
}

// TestPushDroppedMemberAborts: the current blob's manifest says alice can
// decrypt; a recipients file without her must trigger the lockout prompt, and
// declining leaves the old blob byte-for-byte intact.
func TestPushDroppedMemberAborts(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := AddMember([]string{"alice", testPubKey(t)}); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")
	feed(t, "y\n") // first-push foreign-recipient confirmation
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(backend.DefaultBlobPath)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the drift: alice vanishes from the recipients file.
	if err := recipients.Remove("alice"); err != nil {
		t.Fatal(err)
	}

	feed(t, "n\n") // decline "Lock them out?"
	if err := Push(nil); err != nil {
		t.Fatalf("push should return nil (aborted), got %v", err)
	}
	after, err := os.ReadFile(backend.DefaultBlobPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("declined lockout push must leave the existing blob untouched")
	}
}

func TestPushDroppedMemberProceedsWhenConfirmed(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	if err := AddMember([]string{"alice", testPubKey(t)}); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}

	if err := recipients.Remove("alice"); err != nil {
		t.Fatal(err)
	}

	// lockout confirmation, then the recipients-changed confirmation
	feed(t, "y\ny\n")
	if err := Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}

	// The new blob's manifest must now list only "me".
	blob, err := os.ReadFile(backend.DefaultBlobPath)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decryptBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	members, _ := recipients.ExtractManifest(payload)
	if len(members) != 1 || members[0].Key != pub {
		t.Fatalf("manifest should list only self, got %+v", members)
	}
}

// TestPushForeignBlobWarns: a blob this identity cannot decrypt (e.g. a fresh
// dev about to clobber the team's env.age) must trigger the overwrite warning.
func TestPushForeignBlobWarns(t *testing.T) {
	setup(t)

	// Someone else's blob, encrypted only for their key.
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	foreign := []recipients.Member{{Name: "someone", Key: other.Recipient().String()}}
	blob, err := crypto.EncryptBytes(
		recipients.EmbedManifest([]byte("THEIRS=1\n"), foreign),
		[]age.Recipient{other.Recipient()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.DefaultBlobPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	// A fresh dev inits themselves (only they are in recipients) and pushes.
	mustInit(t)
	writeEnv(t, "MINE=1\n")

	feed(t, "n\n") // decline the overwrite warning
	if err := Push(nil); err != nil {
		t.Fatalf("push should return nil (aborted), got %v", err)
	}
	after, err := os.ReadFile(backend.DefaultBlobPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, after) {
		t.Fatal("declined overwrite must leave the foreign blob untouched")
	}
}

// TestPushLegacyBlobSkipsLockoutCheck: blobs from older shenv versions carry no
// manifest — push must not prompt about lockout (nothing to compare against).
func TestPushLegacyBlobSkipsLockoutCheck(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	rec, err := age.ParseX25519Recipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := crypto.EncryptBytes([]byte("OLD=1\n"), []age.Recipient{rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.DefaultBlobPath, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "NEW=1\n")

	feed(t, "") // no prompts expected: self present, no manifest, set unchanged...
	if err := Push(nil); err != nil {
		t.Fatalf("push over a legacy blob should succeed without a lockout prompt: %v", err)
	}
}

func TestKeygenIsIdempotent(t *testing.T) {
	setup(t)
	feed(t, "\n") // empty passphrase
	if err := Keygen(nil); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, err := identity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	// keygen must not touch the repo — no recipients file.
	if _, err := os.Stat(recipients.Path); err == nil {
		t.Fatal("keygen must not create a recipients file")
	}

	feed(t, "") // second run must not prompt or error
	if err := Keygen(nil); err != nil {
		t.Fatalf("second keygen: %v", err)
	}
	if got, _ := identity.PublicKey(); got != pub {
		t.Fatalf("second keygen changed the key: %q → %q", pub, got)
	}
}

func TestRemoveMember(t *testing.T) {
	setup(t)
	if err := recipients.Add("alice", testPubKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := recipients.Add("bob", testPubKey(t)); err != nil {
		t.Fatal(err)
	}

	if err := RemoveMember([]string{"alice"}); err != nil {
		t.Fatalf("remove-member: %v", err)
	}
	members, err := recipients.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Name != "bob" {
		t.Fatalf("expected only bob to remain, got %+v", members)
	}

	if err := RemoveMember([]string{"nobody"}); err == nil {
		t.Fatal("removing an unknown member must error")
	}
	if err := RemoveMember(nil); err == nil {
		t.Fatal("remove-member without a name must error")
	}
}
