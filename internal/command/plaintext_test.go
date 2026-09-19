package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// tempLeftovers lists the write-temporaries still lying around in dir. Any of
// them would be a full copy of the plaintext under a name nobody expects.
func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), plaintextTempPrefix) {
			left = append(left, e.Name())
		}
	}
	return left
}

// TestWritePlaintextTightensLoosePermissions: overwriting a world-readable file
// used to write the secrets through its old mode and only tighten afterwards.
func TestWritePlaintextTightensLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits are not the access control on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("OLD=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writePlaintext(path, []byte("NEW=2\n")); err != nil {
		t.Fatalf("writePlaintext: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("plaintext mode is %o, want 600", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(path); string(got) != "NEW=2\n" {
		t.Errorf("content is %q", got)
	}
	if left := tempLeftovers(t, dir); left != nil {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// TestWritePlaintextLeavesNoTempOnFailure: a failed write must not leave a
// readable copy of the secrets under the temporary name.
func TestWritePlaintextLeavesNoTempOnFailure(t *testing.T) {
	dir := t.TempDir()
	if err := writePlaintext(filepath.Join(dir, "missing", ".env"), []byte("K=v\n")); err == nil {
		t.Fatal("writing into a non-existent directory should fail")
	}
	if left := tempLeftovers(t, dir); left != nil {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// TestWritePlaintextRefusesSymlink: a pre-planted symlink must not decide where
// the secrets land.
func TestWritePlaintextRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	if err := writePlaintext(link, []byte("K=v\n")); err == nil {
		t.Fatal("writing through a symlink must be refused")
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched\n" {
		t.Errorf("symlink target was modified: %q", got)
	}
}

// TestOpenTightensLoosePermissions: the same guarantee through the real
// command, where the destination already exists with loose permissions.
func TestOpenTightensLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits are not the access control on Windows")
	}
	setup(t)
	mustInit(t)
	mustSeal(t, "TOKEN=s3cret\n")
	if err := os.Chmod(defaultEnvFile, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Open([]string{"--force"}); err != nil {
		t.Fatalf("open: %v", err)
	}

	fi, err := os.Stat(defaultEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("plaintext mode is %o, want 600", fi.Mode().Perm())
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if left := tempLeftovers(t, wd); left != nil {
		t.Errorf("temporary files left behind: %v", left)
	}
}
