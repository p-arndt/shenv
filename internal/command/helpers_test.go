package command

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"shenv/internal/identity"
	"shenv/internal/recipients"
)

// feed replaces both os.Stdin (so the terminal check in readSecret sees a
// non-terminal) and the package-level buffered `stdin` reader with the given
// input, then restores them after the test. Every interactive prompt in the
// command package reads through one of these two, so this fully scripts a run.
func feed(t *testing.T, input string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	oldOS, oldPkg := os.Stdin, stdin
	os.Stdin = f
	stdin = bufio.NewReader(f)
	t.Cleanup(func() {
		os.Stdin = oldOS
		stdin = oldPkg
		f.Close()
	})
}

// captureStdout redirects os.Stdout to a pipe for the duration of the returned
// closure, which returns everything written. Used to assert on printed output
// (e.g. `whoami`).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		io.Copy(&b, r)
		done <- b.String()
	}()

	fn()

	os.Stdout = old
	w.Close()
	out := <-done
	r.Close()
	return out
}

// setup isolates HOME (→ ~/.shenv) and the working directory (→ a fresh repo),
// mocks the OS keychain so no test ever touches the real one, and returns the
// repo path. It mirrors isolate() but also guards the keychain.
func setup(t *testing.T) {
	t.Helper()
	isolate(t)
	keyring.MockInit()
}

// mustInit creates a plaintext identity and registers it as recipient "me", the
// common starting state for push/pull/run tests. Returns the public key.
func mustInit(t *testing.T) string {
	t.Helper()
	if _, err := identity.Create(""); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	pub, err := identity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := recipients.Add("me", pub); err != nil {
		t.Fatalf("register recipient: %v", err)
	}
	return pub
}

// writeEnv writes a local .env with the given content.
func writeEnv(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(defaultEnvFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
