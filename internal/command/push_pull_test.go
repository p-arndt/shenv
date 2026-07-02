package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"shenv/internal/backend"
)

// TestPushPullRoundTrip is the core end-to-end: init, push .env, wipe it, pull it
// back byte-for-byte.
func TestPushPullRoundTrip(t *testing.T) {
	setup(t)
	mustInit(t)
	const secrets = "API_KEY=abc123\nDB_PASS=hunter2\n"
	writeEnv(t, secrets)

	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err != nil {
		t.Fatalf("push should have written the blob: %v", err)
	}

	// Remove the plaintext, then pull it back.
	if err := os.Remove(defaultEnvFile); err != nil {
		t.Fatal(err)
	}
	feed(t, "y\n")
	if err := Pull(nil); err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, err := os.ReadFile(defaultEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secrets {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, secrets)
	}
}

func TestPushMissingEnv(t *testing.T) {
	setup(t)
	mustInit(t)
	feed(t, "y\n")
	if err := Push(nil); err == nil {
		t.Fatal("push with no .env should error")
	}
}

func TestPushCustomInputFile(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := os.WriteFile(".env.prod", []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feed(t, "y\n")
	if err := Push([]string{".env.prod"}); err != nil {
		t.Fatalf("push .env.prod: %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err != nil {
		t.Fatalf("blob not written: %v", err)
	}
}

// TestPushForeignRecipientRequiresConfirmation: on first push, any recipient that
// isn't yourself must be confirmed — a fresh clone's list is untrusted.
func TestPushForeignRecipientAborts(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := AddMember([]string{"alice", testPubKey(t), testSignKey(t)}); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")

	feed(t, "n\n") // decline the first-push confirmation
	if err := Push(nil); err != nil {
		t.Fatalf("push should return nil (aborted), got %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err == nil {
		t.Fatal("aborted push must not write the blob")
	}
}

func TestPushForeignRecipientProceeds(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := AddMember([]string{"alice", testPubKey(t), testSignKey(t)}); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "X=1\n")

	feed(t, "y\n") // approve the first-push confirmation
	if err := Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err != nil {
		t.Fatalf("approved push should write the blob: %v", err)
	}
}

func TestPushSymlinkEnvRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	setup(t)
	mustInit(t)
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, defaultEnvFile); err != nil {
		t.Fatal(err)
	}
	feed(t, "y\n")
	if err := Push(nil); err == nil {
		t.Fatal("pushing through a symlinked .env must be refused")
	}
}

func TestPullNoBlob(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := Pull(nil); err == nil {
		t.Fatal("pull with no blob should error")
	}
}

// TestPullOverwriteDeclined: a local .env that differs from the decrypted version
// prompts, and answering no leaves the local file untouched.
func TestPullOverwriteDeclined(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "ORIGINAL=1\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}
	// Diverge the local copy.
	writeEnv(t, "LOCAL_EDIT=changed\n")

	feed(t, "n\n") // decline overwrite
	if err := Pull(nil); err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, _ := os.ReadFile(defaultEnvFile)
	if string(got) != "LOCAL_EDIT=changed\n" {
		t.Fatalf("declined pull must not overwrite local edits, got %q", got)
	}
}

func TestPullForceSkipsPrompt(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "ORIGINAL=1\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, "LOCAL_EDIT=changed\n")

	// No stdin: --force must not prompt.
	feed(t, "")
	if err := Pull([]string{"--force"}); err != nil {
		t.Fatalf("pull --force: %v", err)
	}
	got, _ := os.ReadFile(defaultEnvFile)
	if string(got) != "ORIGINAL=1\n" {
		t.Fatalf("--force should overwrite, got %q", got)
	}
}

func TestPullCustomOutTarget(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "K=v\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--out", "out1.env"},
		{"--out=out2.env"},
		{"out3.env"}, // positional
	} {
		feed(t, "y\n")
		if err := Pull(args); err != nil {
			t.Fatalf("pull %v: %v", args, err)
		}
	}
	for _, f := range []string{"out1.env", "out2.env", "out3.env"} {
		got, err := os.ReadFile(f)
		if err != nil || string(got) != "K=v\n" {
			t.Fatalf("%s: got %q err %v", f, got, err)
		}
	}
}

// TestPullEnsuresOutputGitignored: pull must never leave decrypted plaintext
// where git could commit it — every repo-local output path is added to
// .gitignore before the secrets are written.
func TestPullEnsuresOutputGitignored(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "K=v\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}

	feed(t, "y\n")
	if err := Pull([]string{"--out", ".env.production"}); err != nil {
		t.Fatalf("pull: %v", err)
	}

	ignore, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("pull must create .gitignore for a custom target: %v", err)
	}
	found := false
	for _, line := range strings.Split(string(ignore), "\n") {
		if strings.TrimSpace(line) == ".env.production" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf(".gitignore must list the pull target, got:\n%s", ignore)
	}

	// A second pull to the same target must not duplicate the entry.
	feed(t, "y\n")
	if err := Pull([]string{"--out", ".env.production"}); err != nil {
		t.Fatalf("second pull: %v", err)
	}
	again, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(again), ".env.production") != 1 {
		t.Fatalf(".gitignore entry duplicated:\n%s", again)
	}
}

func TestPullSymlinkOutRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	setup(t)
	mustInit(t)
	writeEnv(t, "K=v\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(defaultEnvFile); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "evil")
	if err := os.Symlink(target, defaultEnvFile); err != nil {
		t.Fatal(err)
	}
	feed(t, "y\n")
	if err := Pull(nil); err == nil {
		t.Fatal("pulling through a symlinked target must be refused")
	}
}
