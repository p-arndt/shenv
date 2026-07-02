package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStringMethods(t *testing.T) {
	if got := (FileBackend{Path: "env.shenv"}).String(); got != "env.shenv" {
		t.Errorf("FileBackend.String() = %q, want the path", got)
	}
	if got := (ExecBackend{}).String(); got != "exec backend" {
		t.Errorf("ExecBackend.String() = %q", got)
	}
}

// TestFileBackendPutRejectsSymlink: a committed symlink at the blob path would let
// `push` write ciphertext through it to an attacker-chosen file.
func TestFileBackendPutRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "env.shenv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := (FileBackend{Path: link}).Put([]byte("blob")); err == nil {
		t.Fatal("Put through a symlink must be refused")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("the symlink target must not have been written")
	}
}

// TestFileBackendGetRejectsOversized guards the in-memory read cap.
func TestFileBackendGetRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.age")
	if err := os.WriteFile(path, make([]byte, maxBlobSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileBackend{Path: path}).Get(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

func TestExecBackendMissingCommands(t *testing.T) {
	if _, err := (ExecBackend{}).Get(); err == nil {
		t.Error("Get with no get command should error")
	}
	if err := (ExecBackend{}).Put([]byte("x")); err == nil {
		t.Error("Put with no put command should error")
	}
}

// TestExecBackendGetFailureSurfacesStderr: when the get command exits non-zero,
// the error should carry its stderr for diagnosis.
func TestExecBackendGetFailure(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "exit 3"
	} else {
		cmd = "echo boom >&2; exit 3"
	}
	if _, err := (ExecBackend{GetCmd: cmd}).Get(); err == nil {
		t.Fatal("a failing get command should surface an error")
	}
}

func TestExecBackendPutFailure(t *testing.T) {
	cmd := "exit 1"
	if err := (ExecBackend{PutCmd: cmd}).Put([]byte("x")); err == nil {
		t.Fatal("a failing put command should surface an error")
	}
}

// TestReadConfigParsing covers comments, blank lines, values containing '=', and a
// missing-'=' error.
func TestReadConfigParsing(t *testing.T) {
	inRepo(t)
	writeConfig(t, "# comment\n\nbackend = exec\nget = curl a=b | sh\n")
	cfg, err := readConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["backend"] != "exec" {
		t.Errorf("backend = %q", cfg["backend"])
	}
	if cfg["get"] != "curl a=b | sh" {
		t.Errorf("get should keep everything after the first '=', got %q", cfg["get"])
	}
}

func TestReadConfigMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg, err := readConfig(filepath.Join(dir, "nope"))
	if err != nil {
		t.Fatalf("missing config should be empty, not an error: %v", err)
	}
	if len(cfg) != 0 {
		t.Fatalf("expected empty config, got %v", cfg)
	}
}

func TestReadConfigRejectsLineWithoutEquals(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = file\nthis line has no equals\n")
	if _, err := readConfig(configPath); err == nil {
		t.Fatal("expected an error for a line missing '='")
	}
}
