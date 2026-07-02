package command

import (
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

func TestInitPlaintext(t *testing.T) {
	setup(t)
	feed(t, "\n") // empty passphrase → plaintext key

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
	if len(members) != 2 {
		t.Fatalf("expected both registrations, got %+v", members)
	}
}

func TestWhoamiPrintsPublicKey(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	out := captureStdout(t, func() {
		if err := Whoami(nil); err != nil {
			t.Fatal(err)
		}
	})
	if strings.TrimSpace(out) != pub {
		t.Fatalf("whoami printed %q, want %q", strings.TrimSpace(out), pub)
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
	key := testPubKey(t)
	if err := AddMember([]string{"alice", key}); err != nil {
		t.Fatalf("add-member: %v", err)
	}
	members, _ := recipients.Load()
	if len(members) != 1 || members[0].Name != "alice" || members[0].Key != key {
		t.Fatalf("unexpected members: %+v", members)
	}
}

func TestAddMemberBadArgs(t *testing.T) {
	setup(t)
	for _, args := range [][]string{
		nil,
		{"only-one"},
		{"a", "b", "c"},
	} {
		if err := AddMember(args); err == nil {
			t.Errorf("args %v should be rejected", args)
		}
	}
}

func TestAddMemberInvalidKey(t *testing.T) {
	setup(t)
	if err := AddMember([]string{"alice", "not-a-key"}); err == nil {
		t.Fatal("an invalid key should be rejected")
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
