package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// genQuiet runs gen with stdout captured, so the public key it prints can be
// asserted on without the test log filling up with runbook instructions.
func genQuiet(t *testing.T, keyfile string) (stdout string, err error) {
	t.Helper()
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("pipe: %v", pipeErr)
	}
	saved := os.Stdout
	os.Stdout = w
	err = gen(keyfile)
	os.Stdout = saved
	w.Close()
	out, readErr := io.ReadAll(r)
	r.Close()
	if readErr != nil {
		t.Fatalf("read captured stdout: %v", readErr)
	}
	return string(out), err
}

// seedFromFile reads back the generated key file the way `gh secret set` would.
func seedFromFile(t *testing.T, keyfile string) (b64 string, priv ed25519.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile(keyfile)
	if err != nil {
		t.Fatalf("read keyfile: %v", err)
	}
	b64 = strings.TrimSpace(string(data))
	seed, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("keyfile is not a base64 seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length = %d, want %d", len(seed), ed25519.SeedSize)
	}
	return b64, ed25519.NewKeyFromSeed(seed)
}

func TestGenRefusesExistingFile(t *testing.T) {
	keyfile := filepath.Join(t.TempDir(), "release.key")
	existing := []byte("an older release key\n")
	if err := os.WriteFile(keyfile, existing, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := genQuiet(t, keyfile); err == nil {
		t.Fatal("gen overwrote an existing release key")
	}

	// Losing the only copy of the seed strands every shipped updater, so the
	// refusal must leave the old content untouched.
	after, err := os.ReadFile(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, existing) {
		t.Fatalf("existing key file was modified: %q", after)
	}
}

func TestGenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "release.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := genQuiet(t, link); err == nil {
		t.Fatal("gen followed a symlink planted at the key path")
	}

	// A followed symlink would have written the seed through to the target.
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "not a key\n" {
		t.Fatalf("symlink target was written through: %q", content)
	}
}

func TestGenWritesOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores mode bits; SecureFile sets an owner-only DACL instead")
	}
	keyfile := filepath.Join(t.TempDir(), "release.key")
	if _, err := genQuiet(t, keyfile); err != nil {
		t.Fatalf("gen: %v", err)
	}

	info, err := os.Lstat(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("key file mode = %04o, want 0600", mode)
	}
}

func TestGenPrintsPublicKeyForTheWrittenSeed(t *testing.T) {
	keyfile := filepath.Join(t.TempDir(), "release.key")
	out, err := genQuiet(t, keyfile)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}

	_, priv := seedFromFile(t, keyfile)
	want := base64.RawStdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if !strings.Contains(out, want) {
		t.Fatalf("gen printed a public key that does not match the written seed\nstdout: %s", out)
	}
	// The seed itself must never reach stdout — CI logs and terminal recordings
	// keep whatever is printed there.
	seedB64, _ := seedFromFile(t, keyfile)
	if strings.Contains(out, seedB64) {
		t.Fatal("gen printed the private seed")
	}
}

func TestGenKeyRoundTripsThroughSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "release.key")
	if _, err := genQuiet(t, keyfile); err != nil {
		t.Fatalf("gen: %v", err)
	}
	seedB64, priv := seedFromFile(t, keyfile)

	checksums := filepath.Join(dir, "shenv_9.9.9_checksums.txt")
	if err := os.WriteFile(checksums, []byte("deadbeef  shenv_9.9.9_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RELEASE_SIGNING_KEY", seedB64)
	if err := sign(checksums); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := base64.RawStdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := verify(checksums, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A signature must not carry over to a different public key.
	otherKeyfile := filepath.Join(dir, "other.key")
	if _, err := genQuiet(t, otherKeyfile); err != nil {
		t.Fatalf("gen: %v", err)
	}
	_, otherPriv := seedFromFile(t, otherKeyfile)
	otherPub := base64.RawStdEncoding.EncodeToString(otherPriv.Public().(ed25519.PublicKey))
	if err := verify(checksums, otherPub); err == nil {
		t.Fatal("verify accepted a signature from a different key")
	}
}
