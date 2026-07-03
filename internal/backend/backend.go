// Package backend abstracts where the encrypted env.shenv blob lives. The default
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
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultBlobPath is where the FileBackend stores the blob, and the name shenv
// keeps un-ignored in .gitignore so it can be committed.
const DefaultBlobPath = "env.shenv"

// maxBlobSize caps how many bytes a backend will read for an encrypted blob. A
// hostile or runaway source (a huge env.shenv, an exec `get` that streams forever)
// would otherwise be buffered into memory unbounded. Real .env files are tiny;
// 16 MiB is far more than any legitimate blob needs.
const maxBlobSize = 16 << 20

// configPath is the per-repo backend configuration (optional; absent => file).
const configPath = "config.shenv"

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
			return nil, fmt.Errorf("%s not found — has anyone run `shenv seal` yet?", b.Path)
		}
		return nil, err
	}
	defer f.Close()
	return readCapped(f, b.Path)
}

func (b FileBackend) Put(data []byte) error {
	if err := RejectSymlinks(b.Path); err != nil {
		return err
	}
	return os.WriteFile(b.Path, data, 0o644)
}

// RejectSymlinks refuses to follow a symlink at the given path or, for a
// repo-relative path, in any directory on the way to it. A committed symlink
// would redirect a write to — or a read from — an attacker-chosen file
// (os.WriteFile/ReadFile follow symlinks), and a committed symlink *directory*
// (`dir` → ~/.ssh) with a nested path like `dir/x` would slip past a
// final-component check. Ancestors above the repo root are not checked: the
// repo may legitimately live under a symlinked path (e.g. /tmp on macOS).
// Used for the blob path, pull's output file, and push's input file alike.
func RejectSymlinks(path string) error {
	check := func(p string) error {
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to follow it", p)
		}
		return nil
	}
	if err := check(path); err != nil {
		return err
	}
	if !filepath.IsLocal(path) {
		return nil // no repo-relative ancestry to police
	}
	for p := filepath.Dir(filepath.Clean(path)); p != "."; p = filepath.Dir(p) {
		if err := check(p); err != nil {
			return err
		}
	}
	return nil
}
func (b FileBackend) String() string { return b.Path }

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

// Load reads config.shenv and returns the configured backend. With no config
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
		if err := validateBlobPath(path); err != nil {
			return nil, err
		}
		return FileBackend{Path: path}, nil
	case "exec":
		return ExecBackend{GetCmd: cfg["get"], PutCmd: cfg["put"]}, nil
	default:
		return nil, fmt.Errorf("unknown backend %q in %s (use `file` or `exec`)", cfg["backend"], configPath)
	}
}

// validateBlobPath rejects file-backend paths that reach outside the repo or
// collide with files shenv (or git) depends on. The config ships with the
// clone, and unlike exec commands the file backend has no trust prompt — an
// absolute or `..`-escaping path would let a hostile config make `push`
// overwrite arbitrary files on this machine, and a path like `.gitignore`
// would let it silently delete the rule keeping the plaintext .env out of
// commits.
func validateBlobPath(path string) error {
	// IsLocal rejects absolute, rooted, `..`-escaping, and Windows-reserved paths.
	if !filepath.IsLocal(path) {
		return fmt.Errorf("blob path %q in %s must stay inside the repo", path, configPath)
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	first := clean
	if i := strings.IndexByte(clean, filepath.Separator); i >= 0 {
		first = clean[:i]
	}
	// Writing into .git could clobber hooks or the repo config. EqualFold covers
	// Windows/macOS case-insensitive filesystems.
	if strings.EqualFold(first, ".git") {
		return fmt.Errorf("blob path %q in %s must not point into .git", path, configPath)
	}
	for _, reserved := range []string{".gitignore", ".env", configPath, "recipients.shenv"} {
		if strings.EqualFold(clean, reserved) {
			return fmt.Errorf("blob path %q in %s would overwrite %s", path, configPath, reserved)
		}
	}
	return nil
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
