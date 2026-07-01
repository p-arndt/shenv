package recipients

import (
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
	key := testKey(t)
	if err := Add("alice", key); err != nil {
		t.Fatalf("add: %v", err)
	}
	members, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(members) != 1 || members[0].Name != "alice" || members[0].Key != key {
		t.Fatalf("unexpected members: %+v", members)
	}
}

// TestAddRejectsInjectableNames: a name with whitespace or control characters
// could smuggle an extra recipient line into the file (or corrupt it), and a
// leading '#' would silently comment the entry out.
func TestAddRejectsInjectableNames(t *testing.T) {
	inRepo(t)
	key := testKey(t)
	for _, name := range []string{
		"",
		"two words",
		"tab\tname",
		"evil\nmallory " + key,
		"#commented",
	} {
		if err := Add(name, key); err == nil {
			t.Errorf("name %q should be rejected", name)
		}
	}
	if _, err := os.Stat(Path); err == nil {
		t.Error("no recipients file should have been written for rejected names")
	}
}

func TestAddRejectsInvalidKey(t *testing.T) {
	inRepo(t)
	if err := Add("alice", "not-a-key"); err == nil || !strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("expected invalid-key error, got %v", err)
	}
}
