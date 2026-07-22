package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/identity"
	"shenv/internal/recipients"
)

func testPubKey(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

// testSignKey returns a freshly generated, valid base64 Ed25519 verify key.
func testSignKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(pub)
}

func TestInitPlaintext(t *testing.T) {
	setup(t)
	feed(t, "\n") // empty passphrase → plaintext key

	// Pin the default-name sources so the assertion below doesn't depend on the
	// git config or OS user of whoever runs the tests.
	stubNameSources(t, "me")

	if err := Init(nil); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Identity exists and is plaintext.
	enc, err := identity.IsEncrypted()
	if err != nil {
		t.Fatal(err)
	}
	if enc {
		t.Error("empty passphrase should leave the key plaintext")
	}
	// Registered as "me".
	members, err := recipients.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Name != "me" {
		t.Fatalf("expected to be registered as 'me', got %+v", members)
	}
	// .gitignore set up.
	gi, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gi), defaultEnvFile) || !strings.Contains(string(gi), "!"+backend.DefaultBlobPath) {
		t.Fatalf(".gitignore missing expected entries:\n%s", gi)
	}
}

func TestInitCustomName(t *testing.T) {
	setup(t)
	feed(t, "\n")
	if err := Init([]string{"patrick"}); err != nil {
		t.Fatal(err)
	}
	members, _ := recipients.Load()
	if len(members) != 1 || members[0].Name != "patrick" {
		t.Fatalf("expected name 'patrick', got %+v", members)
	}
}

func TestInitWithPassphraseDeclineRemember(t *testing.T) {
	setup(t)
	// passphrase, confirm, then decline the keychain offer.
	feed(t, "hunter2\nhunter2\nn\n")
	if err := Init(nil); err != nil {
		t.Fatalf("init: %v", err)
	}
	enc, err := identity.IsEncrypted()
	if err != nil {
		t.Fatal(err)
	}
	if !enc {
		t.Error("a passphrase should encrypt the key at rest")
	}
}

func TestInitMismatchedPassphrase(t *testing.T) {
	setup(t)
	feed(t, "hunter2\nDIFFERENT\n")
	if err := Init(nil); err == nil {
		t.Fatal("mismatched passphrase confirmation should error")
	}
	// No identity should have been created.
	if _, err := identity.PublicKey(); err == nil {
		t.Fatal("no key should exist after a failed init")
	}
}

func TestInitReusesExistingKey(t *testing.T) {
	setup(t)
	feed(t, "\n") // one empty passphrase — only the first Init creates a key
	if err := Init(nil); err != nil {
		t.Fatal(err)
	}
	pub, err := identity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	// A second init (e.g. joining another repo) must reuse the key, not error or
	// regenerate — that was the trap that let users lock themselves out.
	if err := Init([]string{"me2"}); err != nil {
		t.Fatalf("second init should reuse the existing key: %v", err)
	}
	if got, _ := identity.PublicKey(); got != pub {
		t.Fatalf("second init changed the key: %q → %q", pub, got)
	}
	members, err := recipients.Load()
	if err != nil {
		t.Fatal(err)
	}
	// Same key, new name = a rename, not a second entry: duplicate keys would
	// make signature attribution ambiguous, so Load rejects them.
	if len(members) != 1 || members[0].Name != "me2" {
		t.Fatalf("re-init under a new name should rename the single entry, got %+v", members)
	}
}

func TestWhoamiPrintsBothKeys(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	signPub, err := identity.VerifyKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := Whoami(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, pub) || !strings.Contains(out, signPub) {
		t.Fatalf("whoami must print both keys (%q, %q), got:\n%s", pub, signPub, out)
	}
}

// TestWhoamiHintUsesDefaultName: the add-member hint must be copy-pasteable,
// substituting the derived name (git user, then OS login) for the old
// <your-name> placeholder — the same source `shenv init` uses.
func TestWhoamiHintUsesDefaultName(t *testing.T) {
	setup(t)
	mustInit(t)
	stubNameSources(t, "Ada Lovelace")
	out := captureStdout(t, func() {
		if err := Whoami(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "shenv add-member Ada-Lovelace ") {
		t.Fatalf("whoami hint must include the derived name, got:\n%s", out)
	}
	if strings.Contains(out, "<your-name>") {
		t.Fatalf("whoami hint must not keep the placeholder, got:\n%s", out)
	}
}

func TestWhoamiNoIdentity(t *testing.T) {
	setup(t)
	if err := Whoami(nil); err == nil {
		t.Fatal("whoami without an identity should error")
	}
}

func TestAddMember(t *testing.T) {
	setup(t)
	key, signKey := testPubKey(t), testSignKey(t)
	if err := AddMember([]string{"alice", key, signKey}); err != nil {
		t.Fatalf("add-member: %v", err)
	}
	members, _ := recipients.Load()
	if len(members) != 1 || members[0].Name != "alice" || members[0].Key != key || members[0].SignKey != signKey {
		t.Fatalf("unexpected members: %+v", members)
	}
}

func TestAddMemberBadArgs(t *testing.T) {
	setup(t)
	for _, args := range [][]string{
		nil,
		{"only-one"},
		{"name", "key-but-no-signing-key"},
		{"a", "b", "c", "d"},
	} {
		if err := AddMember(args); err == nil {
			t.Errorf("args %v should be rejected", args)
		}
	}
}

func TestAddMemberInvalidKey(t *testing.T) {
	setup(t)
	if err := AddMember([]string{"alice", "not-a-key", testSignKey(t)}); err == nil {
		t.Fatal("an invalid public key should be rejected")
	}
	if err := AddMember([]string{"alice", testPubKey(t), "not-a-signing-key!"}); err == nil {
		t.Fatal("an invalid signing key should be rejected")
	}
}

func TestEnsureGitignoreIdempotent(t *testing.T) {
	setup(t)
	if err := ensureGitignore(); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(".gitignore")
	if err := ensureGitignore(); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(".gitignore")
	if string(first) != string(second) {
		t.Fatalf("ensureGitignore should be a no-op the second time:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// TestEnsureGitignorePreservesExisting appends only what's missing.
func TestEnsureGitignorePreservesExisting(t *testing.T) {
	setup(t)
	if err := os.WriteFile(".gitignore", []byte("node_modules/\n"+defaultEnvFile+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureGitignore(); err != nil {
		t.Fatal(err)
	}
	gi, _ := os.ReadFile(".gitignore")
	s := string(gi)
	if !strings.Contains(s, "node_modules/") {
		t.Error("existing entries must be preserved")
	}
	if strings.Count(s, defaultEnvFile) != 1 {
		t.Errorf(".env should not be duplicated:\n%s", s)
	}
	if !strings.Contains(s, "!"+backend.DefaultBlobPath) {
		t.Error("the un-ignore rule for the blob should have been added")
	}
}

func TestConfirm(t *testing.T) {
	cases := map[string]bool{
		"y\n":     true,
		"Y\n":     true,
		"yes\n":   true,
		"YES\n":   true,
		"n\n":     false,
		"no\n":    false,
		"\n":      false,
		"garbage": false,
		"":        false, // EOF
	}
	for input, want := range cases {
		feed(t, input)
		if got := confirm(); got != want {
			t.Errorf("confirm(%q) = %v, want %v", input, got, want)
		}
	}
}
