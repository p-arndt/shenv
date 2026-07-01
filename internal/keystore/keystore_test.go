package keystore

import (
	"testing"

	"github.com/zalando/go-keyring"
)

// mock swaps the real OS secret store for go-keyring's in-memory mock, so these
// tests never touch (or leave junk in) the developer's actual keychain.
func mock(t *testing.T) {
	t.Helper()
	keyring.MockInit()
}

func TestSetGetRoundTrip(t *testing.T) {
	mock(t)

	const account = "age1example"
	if err := Set(account, "hunter2"); err != nil {
		t.Fatalf("set: %v", err)
	}

	secret, ok := Get(account)
	if !ok {
		t.Fatal("expected a hit after Set")
	}
	if secret != "hunter2" {
		t.Fatalf("got %q, want %q", secret, "hunter2")
	}
}

func TestGetMissReportsFalse(t *testing.T) {
	mock(t)
	if secret, ok := Get("never-stored"); ok || secret != "" {
		t.Fatalf("expected a miss, got secret=%q ok=%v", secret, ok)
	}
}

func TestSetReplacesExisting(t *testing.T) {
	mock(t)

	const account = "age1example"
	if err := Set(account, "first"); err != nil {
		t.Fatal(err)
	}
	if err := Set(account, "second"); err != nil {
		t.Fatal(err)
	}
	if secret, _ := Get(account); secret != "second" {
		t.Fatalf("Set should replace: got %q, want %q", secret, "second")
	}
}

func TestDeleteRemovesSecret(t *testing.T) {
	mock(t)

	const account = "age1example"
	if err := Set(account, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := Delete(account); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := Get(account); ok {
		t.Fatal("secret should be gone after Delete")
	}
}

// TestDeleteMissingIsNotAnError: Delete must treat an absent entry as success, so
// `shenv forget` is idempotent.
func TestDeleteMissingIsNotAnError(t *testing.T) {
	mock(t)
	if err := Delete("never-stored"); err != nil {
		t.Fatalf("deleting a missing entry should be a no-op, got %v", err)
	}
}
