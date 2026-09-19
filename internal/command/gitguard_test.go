package command

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// secretMarker is the synthetic payload the git guard tests look for in the
// index — unique enough that finding it can only mean plaintext got staged.
const secretMarker = "SHENV_TEST_MARKER_9d41f2"

// requireGit skips a test that cannot run without git on PATH.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

// git runs a git command in the current working directory and fails the test if
// it does not succeed.
func git(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// gitInit turns the isolated working directory into a repository.
func gitInit(t *testing.T) {
	t.Helper()
	git(t, "init", "-q")
}

// gitIgnores asks git for its effective ignore decision, the same way a user
// would check the claim shenv prints.
func gitIgnores(t *testing.T, path string) bool {
	t.Helper()
	err := exec.Command("git", "check-ignore", "-q", "--no-index", "--", path).Run()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false
	}
	if err != nil {
		t.Fatalf("git check-ignore %s: %v", path, err)
	}
	return true
}

// secretStaged reports whether an ordinary `git add -A` — no -f — puts the
// marker into the index. That plain staging/commit workflow is what every S01
// reproduction abused.
func secretStaged(t *testing.T, marker string) bool {
	t.Helper()
	git(t, "add", "-A")
	err := exec.Command("git", "grep", "--cached", "-q", "-e", marker).Run()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false
	}
	if err != nil {
		t.Fatalf("git grep --cached: %v", err)
	}
	return true
}

// sealMarker seals the marker secret and removes the local .env again, so the
// only plaintext a test can find afterwards is the one the command under test
// wrote.
func sealMarker(t *testing.T) {
	t.Helper()
	mustSeal(t, "TOKEN="+secretMarker+"\n")
	if err := os.Remove(defaultEnvFile); err != nil {
		t.Fatal(err)
	}
}

// TestOpenSurvivesGitignoreNegation: a `.env` rule followed by `!.env` used to
// satisfy the text-matching check while git happily staged the plaintext. The
// guard now asks git for the effective decision, so open either refuses or
// leaves a genuinely ignored file.
func TestOpenSurvivesGitignoreNegation(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)
	if err := os.WriteFile(".gitignore", []byte(".env\n!.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Open([]string{"--force"})
	if err == nil && !gitIgnores(t, defaultEnvFile) {
		t.Error("open claimed success but git does not ignore the plaintext")
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenRefusesSymlinkedGitignore: appending through a symlinked .gitignore
// modifies the link target while the repository's own ignore rules stay as they
// were — the write must be refused instead.
func TestOpenRefusesSymlinkedGitignore(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	decoy := filepath.Join(t.TempDir(), "decoy-gitignore")
	if err := os.WriteFile(decoy, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, ".gitignore"); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	if err := Open([]string{"--force"}); err == nil {
		t.Error("open through a symlinked .gitignore must be refused")
	}
	if _, err := os.Stat(defaultEnvFile); err == nil {
		t.Error("no plaintext may be written when the ignore rule could not be established")
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenRefusesNestedGitignoreNegation: a nested .gitignore wins over the
// repository root's rules, so a rule written at the root is not enough.
func TestOpenRefusesNestedGitignoreNegation(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	if err := os.Mkdir("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("sub", ".gitignore"), []byte("!.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Open([]string{"--out", "sub/.env"}); err == nil {
		t.Error("open must refuse a target a nested .gitignore un-ignores")
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenEscapesGlobMetacharactersInIgnoreRule: a name like `.env[prod]` is a
// character class when written verbatim, so the rule matched anything but the
// file it was meant to protect.
func TestOpenEscapesGlobMetacharactersInIgnoreRule(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	const out = ".env[prod]"
	if err := Open([]string{"--out", out}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !gitIgnores(t, out) {
		gi, _ := os.ReadFile(".gitignore")
		t.Errorf("git does not ignore %s, .gitignore is:\n%s", out, gi)
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenRefusesTrackedTargetByAbsolutePath: an absolute path is not "outside
// the repository" — it can name a tracked file in this very worktree, which
// .gitignore cannot keep out of a commit.
func TestOpenRefusesTrackedTargetByAbsolutePath(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	const tracked = "tracked.txt"
	if err := os.WriteFile(tracked, []byte("tracked content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", tracked)

	abs, err := filepath.Abs(tracked)
	if err != nil {
		t.Fatal(err)
	}
	feed(t, "y\n") // the overwrite prompt fires before the guard
	if err := Open([]string{"--out", abs}); err == nil {
		t.Error("open over a tracked file must be refused, however the path is spelled")
	}
	if got, _ := os.ReadFile(tracked); string(got) != "tracked content\n" {
		t.Errorf("tracked file must be untouched, got %q", got)
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenRefusesTrackedTargetViaParentDetour: `../<dir>/tracked.txt` resolves
// straight back into the repository; the old check read the `..` and concluded
// the destination was out of git's reach.
func TestOpenRefusesTrackedTargetViaParentDetour(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	const tracked = "tracked.txt"
	if err := os.WriteFile(tracked, []byte("tracked content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", tracked)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	detour := filepath.Join("..", filepath.Base(wd), tracked)
	feed(t, "y\n")
	if err := Open([]string{"--out", detour}); err == nil {
		t.Error("open over a tracked file must be refused, however the path is spelled")
	}
	if got, _ := os.ReadFile(tracked); string(got) != "tracked content\n" {
		t.Errorf("tracked file must be untouched, got %q", got)
	}
	if secretStaged(t, secretMarker) {
		t.Error("plain `git add -A` staged the decrypted secret")
	}
}

// TestOpenOutsideRepositoryStaysAllowed: not being in a repository is not a
// failure — there is simply nothing git could commit.
func TestOpenOutsideRepositoryStaysAllowed(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "TOKEN="+secretMarker+"\n")

	if err := Open([]string{"--force", "--out", ".env.production"}); err != nil {
		t.Fatalf("open outside a repository: %v", err)
	}
	if _, err := os.Stat(".env.production"); err != nil {
		t.Fatalf("plaintext should have been written: %v", err)
	}
}

// TestOpenIgnoresItsOwnTempFile: the temporary file writePlaintext creates
// holds the complete plaintext inside the repository, so it needs the same
// ignore cover as the destination.
func TestOpenIgnoresItsOwnTempFile(t *testing.T) {
	requireGit(t)
	setup(t)
	gitInit(t)
	mustInit(t)
	sealMarker(t)

	if err := Open([]string{"--force"}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !gitIgnores(t, plaintextTempPrefix+"abc123") {
		gi, _ := os.ReadFile(".gitignore")
		t.Errorf("the temporary plaintext file is not ignored, .gitignore is:\n%s", gi)
	}
}

func TestIgnorePatternEscaping(t *testing.T) {
	for _, tc := range []struct{ rel, want string }{
		{".env", "/.env"},
		{".env[prod]", "/.env\\[prod\\]"},
		{"sub/*.env", "/sub/\\*.env"},
		{"!weird", "/\\!weird"},
		{"#hash", "/\\#hash"},
		{"trailing ", "/trailing\\ "},
		{"back\\slash", "/back\\\\slash"},
	} {
		if got := ignorePattern(tc.rel); got != tc.want {
			t.Errorf("ignorePattern(%q) = %q, want %q", tc.rel, got, tc.want)
		}
	}
}
