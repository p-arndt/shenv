package recipients

import (
	"os"
	"strings"
	"testing"
)

func TestKeysParsesMembers(t *testing.T) {
	k1, k2 := testKey(t), testKey(t)
	got, err := Keys([]Member{{Name: "a", Key: k1}, {Name: "b", Key: k2}})
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d recipients, want 2", len(got))
	}
}

// TestKeysRejectsEmpty: encrypting for zero recipients would produce a blob nobody
// can read, so it must be a hard error.
func TestKeysRejectsEmpty(t *testing.T) {
	if _, err := Keys(nil); err == nil {
		t.Fatal("expected an error for an empty recipient set")
	}
}

// TestKeysRejectsInvalidKey: a corrupt key in the committed file must fail loudly
// and name the offending member rather than silently dropping them.
func TestKeysRejectsInvalidKey(t *testing.T) {
	_, err := Keys([]Member{{Name: "mallory", Key: "not-a-key"}})
	if err == nil || !strings.Contains(err.Error(), "mallory") {
		t.Fatalf("expected an error naming the bad member, got %v", err)
	}
}

// TestAddUpdatesExistingMember: re-adding a name rotates its key in place instead
// of appending a duplicate line.
func TestAddUpdatesExistingMember(t *testing.T) {
	inRepo(t)
	first, second := testKey(t), testKey(t)
	if err := Add("alice", first); err != nil {
		t.Fatal(err)
	}
	if err := Add("alice", second); err != nil {
		t.Fatal(err)
	}
	members, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the entry to be updated, got %d members", len(members))
	}
	if members[0].Key != second {
		t.Fatalf("key not rotated: got %q, want %q", members[0].Key, second)
	}
}

// TestLoadMissingFileIsEmpty: no recipients file (fresh repo) is an empty list,
// not an error.
func TestLoadMissingFileIsEmpty(t *testing.T) {
	inRepo(t)
	members, err := Load()
	if err != nil {
		t.Fatalf("missing file should load as empty: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected empty, got %v", members)
	}
}

// TestLoadSkipsCommentsAndBlanks and rejects malformed lines.
func TestLoadSkipsCommentsAndBlanks(t *testing.T) {
	inRepo(t)
	key := testKey(t)
	content := "# a comment\n\n   \nalice " + key + "\n"
	if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	members, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Name != "alice" {
		t.Fatalf("unexpected members: %+v", members)
	}
}

func TestLoadRejectsMalformedLine(t *testing.T) {
	inRepo(t)
	if err := os.WriteFile(Path, []byte("alice one two three\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a malformed recipients line")
	}
}

// TestSaveSortsByName keeps diffs stable regardless of insertion order.
func TestSaveSortsByName(t *testing.T) {
	inRepo(t)
	kb, ka := testKey(t), testKey(t)
	if err := Save([]Member{{Name: "bob", Key: kb}, {Name: "alice", Key: ka}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(Path)
	if err != nil {
		t.Fatal(err)
	}
	ai := strings.Index(string(data), "alice")
	bi := strings.Index(string(data), "bob")
	if ai == -1 || bi == -1 || ai > bi {
		t.Fatalf("expected alice before bob in:\n%s", data)
	}
}
