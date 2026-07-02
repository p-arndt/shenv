package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binPath is the compiled shenv binary, built once for the whole test binary.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "shenv-cli")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binPath = filepath.Join(dir, "shenv")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("building shenv: " + err.Error())
	}

	os.Exit(m.Run())
}

// runCLI invokes the built binary with an isolated HOME so it never touches the
// developer's real ~/.shenv. Returns combined stdout, stderr, and the exit code.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)

	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()

	code = 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			t.Fatalf("running %v: %v", args, err)
		}
	}
	return out.String(), errBuf.String(), code
}

func TestNoArgsPrintsUsage(t *testing.T) {
	out, _, code := runCLI(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("expected usage text, got:\n%s", out)
	}
}

func TestVersion(t *testing.T) {
	for _, flag := range []string{"version", "--version", "-v"} {
		out, _, code := runCLI(t, flag)
		if code != 0 {
			t.Errorf("%s: exit = %d", flag, code)
		}
		if !strings.HasPrefix(out, "shenv ") {
			t.Errorf("%s: expected a version line, got %q", flag, out)
		}
	}
}

func TestHelp(t *testing.T) {
	for _, flag := range []string{"help", "-h", "--help"} {
		out, _, code := runCLI(t, flag)
		if code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%s: code=%d out=%q", flag, code, out)
		}
	}
}

func TestUnknownCommandExits2(t *testing.T) {
	_, stderr, code := runCLI(t, "frobnicate")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Fatalf("expected an unknown-command message, got:\n%s", stderr)
	}
}

// TestCommandErrorExits1: a subcommand that returns an error (here, whoami with no
// identity) must surface it and exit 1.
func TestCommandErrorExits1(t *testing.T) {
	_, stderr, code := runCLI(t, "whoami")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "error:") {
		t.Fatalf("expected an error line, got:\n%s", stderr)
	}
}

// TestEndToEnd exercises the real binary through the full lifecycle: init (empty
// passphrase via stdin), whoami, push, and pull.
func TestEndToEnd(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	env := append(os.Environ(), "HOME="+home, "USERPROFILE="+home)

	run := func(stdin string, args ...string) (string, string, int) {
		cmd := exec.Command(binPath, args...)
		cmd.Dir = repo
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out, errBuf strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		code := 0
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else {
				t.Fatalf("running %v: %v", args, err)
			}
		}
		return out.String(), errBuf.String(), code
	}

	if _, stderr, code := run("\n", "init"); code != 0 {
		t.Fatalf("init failed (%d): %s", code, stderr)
	}

	whoOut, _, code := run("", "whoami")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(whoOut), "age1") {
		t.Fatalf("whoami: code=%d out=%q", code, whoOut)
	}

	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("SECRET=42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run("y\n", "push"); code != 0 {
		t.Fatalf("push failed (%d): %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(repo, "env.shenv")); err != nil {
		t.Fatalf("push did not create env.shenv: %v", err)
	}

	// Wipe and pull it back.
	if err := os.Remove(filepath.Join(repo, ".env")); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run("y\n", "pull"); code != 0 {
		t.Fatalf("pull failed (%d): %s", code, stderr)
	}
	got, err := os.ReadFile(filepath.Join(repo, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SECRET=42\n" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}
