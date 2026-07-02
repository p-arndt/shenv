package command

import (
	"os"
	"path/filepath"
	"testing"

	"shenv/internal/backend"
	"shenv/internal/recipients"
)

func members(pairs ...string) []recipients.Member {
	var m []recipients.Member
	for i := 0; i+1 < len(pairs); i += 2 {
		m = append(m, recipients.Member{Name: pairs[i], Key: pairs[i+1]})
	}
	return m
}

// TestConfirmRecipientsFirstPushSelfOnly: encrypting only for yourself on a fresh
// machine needs no confirmation.
func TestConfirmRecipientsFirstPushSelfOnly(t *testing.T) {
	setup(t)
	feed(t, "") // must not read any input
	proceed, err := confirmRecipients(members("me", "age1self"), "age1self")
	if err != nil {
		t.Fatal(err)
	}
	if !proceed {
		t.Fatal("self-only first push should proceed without a prompt")
	}
}

// TestConfirmRecipientsFirstPushForeign: a foreign recipient on the first push is
// gated behind a y/N prompt.
func TestConfirmRecipientsFirstPushForeign(t *testing.T) {
	setup(t)
	m := members("me", "age1self", "alice", "age1alice")

	feed(t, "n\n")
	if proceed, err := confirmRecipients(m, "age1self"); err != nil || proceed {
		t.Fatalf("declined foreign recipient should not proceed (proceed=%v err=%v)", proceed, err)
	}

	feed(t, "y\n")
	if proceed, err := confirmRecipients(m, "age1self"); err != nil || !proceed {
		t.Fatalf("approved foreign recipient should proceed (proceed=%v err=%v)", proceed, err)
	}
}

// TestConfirmRecipientsUnchangedSetIsSilent: after a recorded push, an identical
// set proceeds without prompting.
func TestConfirmRecipientsUnchangedSetIsSilent(t *testing.T) {
	setup(t)
	m := members("me", "age1self", "alice", "age1alice")
	if err := rememberRecipients(m); err != nil {
		t.Fatal(err)
	}
	feed(t, "") // must not read input
	proceed, err := confirmRecipients(m, "age1self")
	if err != nil {
		t.Fatal(err)
	}
	if !proceed {
		t.Fatal("an unchanged recipient set should proceed silently")
	}
}

// TestConfirmRecipientsChangedSetPrompts: adding a member after a recorded push
// prompts, and declining aborts.
func TestConfirmRecipientsChangedSetPrompts(t *testing.T) {
	setup(t)
	base := members("me", "age1self")
	if err := rememberRecipients(base); err != nil {
		t.Fatal(err)
	}
	changed := members("me", "age1self", "eve", "age1eve")

	feed(t, "n\n")
	if proceed, err := confirmRecipients(changed, "age1self"); err != nil || proceed {
		t.Fatalf("declined change should not proceed (proceed=%v err=%v)", proceed, err)
	}

	feed(t, "y\n")
	if proceed, err := confirmRecipients(changed, "age1self"); err != nil || !proceed {
		t.Fatalf("approved change should proceed (proceed=%v err=%v)", proceed, err)
	}
}

func TestConfirmExec(t *testing.T) {
	feed(t, "y\n")
	if ok, err := confirmExec("get cmd", "put cmd"); err != nil || !ok {
		t.Fatalf("y should approve (ok=%v err=%v)", ok, err)
	}
	feed(t, "n\n")
	if ok, err := confirmExec("get cmd", "put cmd"); err != nil || ok {
		t.Fatalf("n should decline (ok=%v err=%v)", ok, err)
	}
}

func TestLoadBackendDefaultsToFile(t *testing.T) {
	setup(t)
	b, err := loadBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.(backend.FileBackend); !ok {
		t.Fatalf("expected a FileBackend, got %T", b)
	}
}

func TestLoadBackendExecNeedsApproval(t *testing.T) {
	setup(t)
	if err := os.WriteFile("config.shenv", []byte("backend = exec\nget = fetch\nput = store\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Declining the exec approval fails the load.
	feed(t, "n\n")
	if _, err := loadBackend(); err == nil {
		t.Fatal("an unapproved exec backend should fail to load")
	}

	// Approving it returns the ExecBackend and records the trust.
	feed(t, "y\n")
	b, err := loadBackend()
	if err != nil {
		t.Fatalf("approved exec load: %v", err)
	}
	if _, ok := b.(backend.ExecBackend); !ok {
		t.Fatalf("expected an ExecBackend, got %T", b)
	}
}

// TestLoadPushedRecipientsIgnoresBlanks: blank lines and line endings are
// skipped, but entries themselves are kept verbatim — a member without a sign
// key ends in a tab that must survive the round-trip.
func TestLoadPushedRecipientsIgnoresBlanks(t *testing.T) {
	setup(t)
	path, err := pushedRecipientsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\nme\tage1self\tsignme\r\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, have, err := loadPushedRecipients()
	if err != nil || !have {
		t.Fatalf("expected a recorded set (have=%v err=%v)", have, err)
	}
	if !set["me\tage1self\tsignme"] {
		t.Fatalf("expected the entry to be present, got %v", set)
	}
}
