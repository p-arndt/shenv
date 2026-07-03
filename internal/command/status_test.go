package command

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runStatus captures what `shenv status` prints, failing the test if it errors.
func runStatus(t *testing.T) string {
	t.Helper()
	var out string
	var err error
	out = captureStdout(t, func() { err = Status(nil) })
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return out
}

// TestStatusNoIdentity: on a fresh machine with no key and no repo state, status
// reports the missing identity instead of erroring.
func TestStatusNoIdentity(t *testing.T) {
	setup(t)

	out := runStatus(t)
	if !strings.Contains(out, "identity") || !strings.Contains(out, "shenv keygen") {
		t.Fatalf("expected a missing-identity hint, got:\n%s", out)
	}
	if !strings.Contains(out, "no members yet") {
		t.Fatalf("expected empty team, got:\n%s", out)
	}
}

// TestStatusRegisteredInSync: after init + seal with a matching .env, status
// shows the registration, the signer, and that .env is in sync.
func TestStatusRegisteredInSync(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")

	out := runStatus(t)
	for _, want := range []string{
		`registered here as "me"`,
		"1 member(s) — me",
		"file → env.shenv",
		"sealed by me",
		"in sync with .env",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status missing %q, got:\n%s", want, out)
		}
	}
}

// TestStatusDetectsDrift: editing .env after sealing must surface as a diff, so
// the user knows a `seal` is pending.
func TestStatusDetectsDrift(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	writeEnv(t, "X=2\n") // local edit, not yet sealed

	out := runStatus(t)
	if !strings.Contains(out, ".env differs") || !strings.Contains(out, "shenv seal") {
		t.Fatalf("expected drift to be reported, got:\n%s", out)
	}
}

// TestStatusMissingLocalEnv: with a sealed blob but no local .env, status points
// the user at `open` rather than claiming a mismatch.
func TestStatusMissingLocalEnv(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	if err := os.Remove(defaultEnvFile); err != nil {
		t.Fatal(err)
	}

	out := runStatus(t)
	if !strings.Contains(out, "no local .env") || !strings.Contains(out, "shenv open") {
		t.Fatalf("expected a missing-.env hint, got:\n%s", out)
	}
}

// TestStatusNotSealed: an identity registered but nothing sealed yet reports the
// blob as absent instead of trying to decrypt.
func TestStatusNotSealed(t *testing.T) {
	setup(t)
	mustInit(t)

	out := runStatus(t)
	if !strings.Contains(out, "not sealed yet") {
		t.Fatalf("expected not-sealed hint, got:\n%s", out)
	}
}

// TestStatusWarnsTrackedEnv: if git tracks .env, .gitignore can't protect it, so
// status must warn that plaintext could be committed.
func TestStatusWarnsTrackedEnv(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	setup(t)
	mustInit(t)
	writeEnv(t, "X=1\n")

	for _, args := range [][]string{{"init"}, {"add", defaultEnvFile}} {
		cmd := exec.Command("git", args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}

	out := runStatus(t)
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "tracked by git") {
		t.Fatalf("expected a tracked-.env warning, got:\n%s", out)
	}
}
