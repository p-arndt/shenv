// Package backend abstracts where the encrypted env.age blob lives. The default
// is a file in the repo (shared via git); an exec backend delegates get/put to a
// configured shell command, making any storage tool (aws, curl, rclone, …) usable
// without shenv depending on it.
package backend

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DefaultBlobPath is where the FileBackend stores the blob, and the name shenv
// keeps un-ignored in .gitignore so it can be committed.
const DefaultBlobPath = "env.age"

// maxBlobSize caps how many bytes a backend will read for an encrypted blob. A
// hostile or runaway source (a huge env.age, an exec `get` that streams forever)
// would otherwise be buffered into memory unbounded. Real .env files are tiny;
// 16 MiB is far more than any legitimate blob needs.
const maxBlobSize = 16 << 20

// configPath is the per-repo backend configuration (optional; absent => file).
const configPath = ".shenv/config"

// Backend reads and writes the encrypted blob. Implementations know nothing about
// encryption — they move opaque bytes.
type Backend interface {
	Get() ([]byte, error)
	Put([]byte) error
	fmt.Stringer
}

// FileBackend stores the blob as a file in the repo.
type FileBackend struct{ Path string }

func (b FileBackend) Get() ([]byte, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found — has anyone run `shenv push` yet?", b.Path)
		}
		return nil, err
	}
	defer f.Close()
	return readCapped(f, b.Path)
}

func (b FileBackend) Put(data []byte) error { return os.WriteFile(b.Path, data, 0o644) }
func (b FileBackend) String() string        { return b.Path }

// ExecBackend delegates storage to shell commands: `get` must write the blob to
// stdout, `put` must read it from stdin.
type ExecBackend struct{ GetCmd, PutCmd string }

func (b ExecBackend) Get() ([]byte, error) {
	if b.GetCmd == "" {
		return nil, fmt.Errorf("exec backend: no `get` command configured in %s", configPath)
	}
	cmd := shellCommand(b.GetCmd)
	out := &capWriter{limit: maxBlobSize, what: "exec `get` output"}
	var errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &errBuf
	if err := cmd.Run(); err != nil {
		if out.err != nil {
			return nil, out.err
		}
		return nil, fmt.Errorf("exec `get` failed: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return out.buf.Bytes(), nil
}

func (b ExecBackend) Put(data []byte) error {
	if b.PutCmd == "" {
		return fmt.Errorf("exec backend: no `put` command configured in %s", configPath)
	}
	cmd := shellCommand(b.PutCmd)
	cmd.Stdin = bytes.NewReader(data)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec `put` failed: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func (b ExecBackend) String() string { return "exec backend" }

// Load reads .shenv/config and returns the configured backend. With no config
// (or backend=file) it defaults to a file in the repo.
func Load() (Backend, error) {
	cfg, err := readConfig(configPath)
	if err != nil {
		return nil, err
	}

	switch cfg["backend"] {
	case "", "file":
		path := cfg["path"]
		if path == "" {
			path = DefaultBlobPath
		}
		return FileBackend{Path: path}, nil
	case "exec":
		return ExecBackend{GetCmd: cfg["get"], PutCmd: cfg["put"]}, nil
	default:
		return nil, fmt.Errorf("unknown backend %q in %s (use `file` or `exec`)", cfg["backend"], configPath)
	}
}

// readCapped reads r into memory, refusing to buffer more than maxBlobSize bytes.
func readCapped(r io.Reader, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBlobSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBlobSize {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", what, maxBlobSize)
	}
	return data, nil
}

// capWriter buffers writes but fails as soon as the total exceeds limit, so an
// exec `get` that streams unbounded output can't exhaust memory. Once it trips it
// records err and drops further data; callers surface err over the command's own.
type capWriter struct {
	buf   bytes.Buffer
	limit int
	what  string
	err   error
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return len(p), nil // already over budget; swallow the rest so the child isn't blocked
	}
	if w.buf.Len()+len(p) > w.limit {
		w.err = fmt.Errorf("%s exceeds the %d-byte limit", w.what, w.limit)
		return len(p), nil
	}
	return w.buf.Write(p)
}

// shellCommand wraps a command string in the platform's shell so users can write
// pipelines and arguments naturally.
func shellCommand(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/c", command)
	}
	return exec.Command("sh", "-c", command)
}
