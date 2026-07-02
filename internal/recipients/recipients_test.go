package recipients

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// testKey returns a freshly generated, valid age public key.
func testKey(t *testing.T) string {
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

// inRepo switches into a throwaway working directory so the relative recipients
// path reads/writes are isolated.
func inRepo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestAddRoundTrip(t *testing.T) {
	inRepo(t)
	key, signKey := testKey(t), testSignKey(t)
	if err := Add("alice", key, signKey); err != nil {
		t.Fatalf("add: %v", err)
	}
	members, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(members) != 1 || members[0].Name != "alice" || members[0].Key != key || members[0].SignKey != signKey {
		t.Fatalf("unexpected members: %+v", members)
	}
}

// TestAddRejectsInjectableNames: a name with whitespace or control characters
// could smuggle an extra recipient line into the file (or corrupt it), and a
// leading '#' would silently comment the entry out.
func TestAddRejectsInjectableNames(t *testing.T) {
	inRepo(t)
	key, signKey := testKey(t), testSignKey(t)
	for _, name := range []string{
		"",
		"two words",
		"tab\tname",
		"evil\nmallory " + key,
		"#commented",
	} {
		if err := Add(name, key, signKey); err == nil {
			t.Errorf("name %q should be rejected", name)
		}
	}
	if _, err := os.Stat(Path); err == nil {
		t.Error("no recipients file should have been written for rejected names")
	}
}

func TestAddRejectsInvalidKey(t *testing.T) {
	inRepo(t)
	if err := Add("alice", "not-a-key", testSignKey(t)); err == nil || !strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("expected invalid-key error, got %v", err)
	}
}

func TestAddRejectsInvalidSignKey(t *testing.T) {
	inRepo(t)
	if err := Add("alice", testKey(t), "too-short!"); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("expected invalid-signing-key error, got %v", err)
	}
}
