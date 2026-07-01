package command

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHelperProcess is not a real test: it is re-exec'd as the child of a `shenv
// run` invocation. It writes the value of the env var named by its second
// positional arg to the file named by its first, proving that Run injected the
// decrypted secrets into the child's environment. It exits immediately when not
// running as that child.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	var rest []string
	for i, a := range os.Args {
		if a == "--" {
			rest = os.Args[i+1:]
			break
		}
	}
	if len(rest) < 2 {
		os.Exit(2)
	}
	outFile, varName := rest[0], rest[1]
	if err := os.WriteFile(outFile, []byte(os.Getenv(varName)), 0o600); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestDecryptEnvRoundTrip(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "K=v\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}
	got, err := decryptEnv()
	if err != nil {
		t.Fatalf("decryptEnv: %v", err)
	}
	if string(got) != "K=v\n" {
		t.Fatalf("got %q, want %q", got, "K=v\n")
	}
}

func TestDecryptEnvNoBlob(t *testing.T) {
	setup(t)
	mustInit(t)
	if _, err := decryptEnv(); err == nil {
		t.Fatal("decryptEnv with no blob should error")
	}
}

func TestRunMissingSeparator(t *testing.T) {
	setup(t)
	if err := Run([]string{"echo", "hi"}); err == nil {
		t.Fatal("run without `--` should error")
	}
}

// TestRunInjectsSecrets runs the test binary itself as the child command and
// checks that a secret from env.age reached the child's environment.
func TestRunInjectsSecrets(t *testing.T) {
	setup(t)
	mustInit(t)
	writeEnv(t, "INJECTED=secret-value\n")
	feed(t, "y\n")
	if err := Push(nil); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "out.txt")

	// The child re-execs this test binary; the marker sends it into TestHelperProcess.
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	args := []string{"--", os.Args[0], "-test.run=TestHelperProcess", "--", outFile, "INJECTED"}
	if err := Run(args); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("child did not write output: %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("child saw INJECTED=%q, want the decrypted secret", got)
	}
}
