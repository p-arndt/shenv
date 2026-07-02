package command

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mustPush seeds the default blob so a pull has something to decrypt.
func mustPush(t *testing.T, secrets string) {
	t.Helper()
	writeEnv(t, secrets)
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}
}

// TestPullRefusesGitTrackedTarget: .gitignore cannot keep an already-tracked
// file out of commits, so ensureIgnored's "plaintext never committable"
// promise must fail closed for tracked pull targets (e.g. --out env.shenv).
func TestPullRefusesGitTrackedTarget(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	setup(t)
	mustInit(t)
	mustPush(t, "X=1\n")

	if err := os.WriteFile("notes.txt", []byte("tracked content"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "notes.txt"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	feed(t, "y\n") // the file exists and differs, so the overwrite prompt fires first
	err := Pull([]string{"--out", "notes.txt"})
	if err == nil || !strings.Contains(err.Error(), "tracked") {
		t.Fatalf("pull over a tracked file must be refused, got %v", err)
	}
	if got, _ := os.ReadFile("notes.txt"); string(got) != "tracked content" {
		t.Fatalf("tracked file must be untouched, got %q", got)
	}
}

// TestPullRefusesSymlinkDirTarget: a committed symlink *directory* must not
// let the decrypted plaintext escape the repo — the final-component check
// alone would miss it.
func TestPullRefusesSymlinkDirTarget(t *testing.T) {
	setup(t)
	mustInit(t)
	mustPush(t, "X=1\n")

	outside := t.TempDir()
	if err := os.Symlink(outside, "linked"); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	err := Pull([]string{"--out", "linked/.env"})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("pull through a symlinked directory must be refused, got %v", err)
	}
}

// TestPushRefusesSymlinkDirSource: the read side of the same trap — a repo
// shipping a symlinked directory must not trick push into encrypting and
// sharing an unrelated file's contents with every recipient.
func TestPushRefusesSymlinkDirSource(t *testing.T) {
	setup(t)
	mustInit(t)

	outside := t.TempDir()
	secretPath := outside + string(os.PathSeparator) + "victim"
	if err := os.WriteFile(secretPath, []byte("SSH_KEY=oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, "linked"); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	err := Push([]string{"linked/victim"})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("push through a symlinked directory must be refused, got %v", err)
	}
}
