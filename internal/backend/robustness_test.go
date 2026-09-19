package backend

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestFileBackendMissingIsNotFound: callers must be able to tell "nothing sealed
// yet" from "the read failed", so the missing-file case carries ErrNotFound.
func TestFileBackendMissingIsNotFound(t *testing.T) {
	b := FileBackend{Path: filepath.Join(t.TempDir(), "nope.age")}
	_, err := b.Get()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing blob should report ErrNotFound, got %v", err)
	}
}

// TestFileBackendGetErrorIsNotNotFound: an unreadable — but existing — blob is a
// storage failure, never a missing one.
func TestFileBackendGetErrorIsNotNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.age")
	if err := os.WriteFile(path, make([]byte, MaxBlobSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := (FileBackend{Path: path}).Get()
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("an oversized blob must be an error, not a not-found, got %v", err)
	}
}

// TestFileBackendPutRefusesOversize: a blob the backend could not read back must
// never replace a readable one, and the rejected write must leave no temp files.
func TestFileBackendPutRefusesOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.shenv")
	b := FileBackend{Path: path}
	previous := []byte("previous-blob")
	if err := b.Put(previous); err != nil {
		t.Fatal(err)
	}

	if err := b.Put(make([]byte, MaxBlobSize+1)); err == nil {
		t.Fatal("storing a blob past the read cap must fail")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(previous) {
		t.Fatalf("previous blob must survive, got %q (%v)", got, err)
	}
	assertNoLeftovers(t, dir, "env.shenv")
}

// TestFileBackendPutKeepsPreviousBlobOnFailure: when the write cannot complete,
// the old blob must still be there — the team's only copy of its secrets.
func TestFileBackendPutKeepsPreviousBlobOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block file creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "env.shenv")
	b := FileBackend{Path: path}
	previous := []byte("previous-blob")
	if err := b.Put(previous); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := b.Put([]byte("new-blob")); err == nil {
		t.Fatal("a write into a read-only directory must fail")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(previous) {
		t.Fatalf("previous blob must survive a failed write, got %q (%v)", got, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	assertNoLeftovers(t, dir, "env.shenv")
}

// TestWriteFileAtomicReplacesExisting covers the ordinary path: the destination
// ends up with the new content and the requested permissions.
func TestWriteFileAtomicReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("got %q (%v)", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("permissions should be 0600, got %v", fi.Mode().Perm())
		}
	}
	assertNoLeftovers(t, dir, "state")
}

// TestExecBackendGetOversizeWithZeroExit: a command that streams past the cap and
// exits 0 used to hand back a silently truncated blob.
func TestExecBackendGetOversizeWithZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell to stream bytes")
	}
	cmd := "head -c " + strconv.Itoa(MaxBlobSize+1) + " /dev/zero"
	data, err := (ExecBackend{GetCmd: cmd}).Get()
	if err == nil {
		t.Fatalf("output past the cap must be an error, got %d bytes", len(data))
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("a truncated read must not look like a missing blob")
	}
}

// TestExecBackendGetEmptyOutputIsNotFound pins the exec not-found contract: exit
// 0 with no output means nothing is stored yet.
func TestExecBackendGetEmptyOutputIsNotFound(t *testing.T) {
	cmd := "exit 0"
	_, err := (ExecBackend{GetCmd: cmd}).Get()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty output with exit 0 should report ErrNotFound, got %v", err)
	}
}

// TestExecBackendGetFailureIsNotNotFound: the other half of the contract — a
// non-zero exit is a storage error even when it printed nothing.
func TestExecBackendGetFailureIsNotNotFound(t *testing.T) {
	_, err := (ExecBackend{GetCmd: "exit 7"}).Get()
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("a failing get must be an error, not a not-found, got %v", err)
	}
}

// TestExecBackendPutRefusesOversize: the exec side shares the cap, so it cannot
// upload a blob that could never be fetched back.
func TestExecBackendPutRefusesOversize(t *testing.T) {
	b := ExecBackend{PutCmd: "exit 0"}
	if err := b.Put(make([]byte, MaxBlobSize+1)); err == nil {
		t.Fatal("storing a blob past the read cap must fail")
	}
}

// TestExecBackendTimeoutIsEnforced: a stalled storage command must not hang shenv
// forever.
func TestExecBackendTimeoutIsEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell to sleep")
	}
	t.Setenv("SHENV_EXEC_TIMEOUT", "50ms")
	if _, err := (ExecBackend{GetCmd: "sleep 30"}).Get(); err == nil {
		t.Fatal("a stalled get command must be aborted")
	}
}

// assertNoLeftovers fails when the atomic write left a temp file behind.
func assertNoLeftovers(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != name {
			t.Fatalf("unexpected leftover %q in %s", e.Name(), dir)
		}
	}
}
