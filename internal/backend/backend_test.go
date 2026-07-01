package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileBackendRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.age")
	b := FileBackend{Path: path}

	want := []byte("encrypted-blob")
	if err := b.Put(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := b.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFileBackendMissing(t *testing.T) {
	b := FileBackend{Path: filepath.Join(t.TempDir(), "nope.age")}
	if _, err := b.Get(); err == nil {
		t.Fatal("expected error for missing blob")
	}
}

// TestExecBackendRoundTrip pipes a blob through real shell commands: `put` writes
// stdin to a temp file, `get` cats it back to stdout.
func TestExecBackendRoundTrip(t *testing.T) {
	blobFile := filepath.Join(t.TempDir(), "store.age")

	var b ExecBackend
	if runtime.GOOS == "windows" {
		// Single-quoted, pipe-free PowerShell so cmd /c doesn't mangle quoting.
		b = ExecBackend{
			GetCmd: "powershell -NoProfile -Command [Console]::Out.Write([IO.File]::ReadAllText('" + blobFile + "'))",
			PutCmd: "powershell -NoProfile -Command [IO.File]::WriteAllText('" + blobFile + "',[Console]::In.ReadToEnd())",
		}
	} else {
		b = ExecBackend{
			GetCmd: "cat " + blobFile,
			PutCmd: "cat > " + blobFile,
		}
	}

	want := []byte("blob-through-exec\n")
	if err := b.Put(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := b.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLoadDefaultsToFile(t *testing.T) {
	inRepo(t)
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	fb, ok := b.(FileBackend)
	if !ok {
		t.Fatalf("expected FileBackend, got %T", b)
	}
	if fb.Path != DefaultBlobPath {
		t.Fatalf("path = %q, want %q", fb.Path, DefaultBlobPath)
	}
}

func TestLoadExecFromConfig(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = exec\nget = fetch it\nput = store it\n")

	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	eb, ok := b.(ExecBackend)
	if !ok {
		t.Fatalf("expected ExecBackend, got %T", b)
	}
	if eb.GetCmd != "fetch it" || eb.PutCmd != "store it" {
		t.Fatalf("unexpected commands: %+v", eb)
	}
}

func TestLoadUnknownBackend(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = ftp\n")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// inRepo switches into a throwaway working directory so config reads/writes are isolated.
func inRepo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func writeConfig(t *testing.T, content string) {
	t.Helper()
	if err := os.MkdirAll(".shenv", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
