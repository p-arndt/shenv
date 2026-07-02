package command

import (
	"os"
	"testing"

	"shenv/internal/recipients"
)

// isolate points ~/.shenv/state at a throwaway home and runs in a throwaway repo,
// so recipient bookkeeping doesn't touch the real machine.
func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	repo := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(repo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestRecipientsRoundTrip(t *testing.T) {
	isolate(t)

	if _, have, err := loadPushedRecipients(); err != nil || have {
		t.Fatalf("expected no prior push, got have=%v err=%v", have, err)
	}

	members := []recipients.Member{
		{Name: "alice", Key: "age1alice"},
		{Name: "bob", Key: "age1bob"},
	}
	if err := rememberRecipients(members); err != nil {
		t.Fatalf("remember: %v", err)
	}

	prev, have, err := loadPushedRecipients()
	if err != nil || !have {
		t.Fatalf("expected recorded push, got have=%v err=%v", have, err)
	}
	want := recipientSet(members)
	if len(prev) != len(want) {
		t.Fatalf("round-trip size mismatch: got %d want %d", len(prev), len(want))
	}
	for k := range want {
		if !prev[k] {
			t.Fatalf("missing entry %q after round-trip", k)
		}
	}
}

func TestRecipientSetDetectsChanges(t *testing.T) {
	base := recipientSet([]recipients.Member{{Name: "alice", Key: "age1alice"}})

	// Same name, swapped key must register as different.
	swapped := recipientSet([]recipients.Member{{Name: "alice", Key: "age1EVIL"}})
	if setsEqual(base, swapped) {
		t.Fatal("a swapped key should be detected as a change")
	}

	// An added member must register as different.
	added := recipientSet([]recipients.Member{
		{Name: "alice", Key: "age1alice"},
		{Name: "eve", Key: "age1eve"},
	})
	if setsEqual(base, added) {
		t.Fatal("an added recipient should be detected as a change")
	}
}

// TestRecipientSetDetectsSignKeySwap: pull verifies signatures against the
// signing key in recipients.shenv, so replacing only that key — name and
// encryption key unchanged — would let an attacker forge blobs as an existing
// member. That edit must register as a change and hit the confirmation prompt.
func TestRecipientSetDetectsSignKeySwap(t *testing.T) {
	base := recipientSet([]recipients.Member{{Name: "alice", Key: "age1alice", SignKey: "signalice"}})
	swapped := recipientSet([]recipients.Member{{Name: "alice", Key: "age1alice", SignKey: "signEVIL"}})
	if setsEqual(base, swapped) {
		t.Fatal("a swapped signing key should be detected as a change")
	}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
