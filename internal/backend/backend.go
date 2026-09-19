// Package backend abstracts where the encrypted env.shenv blob lives. The default
// is a file in the repo (shared via git); an exec backend delegates get/put to a
// configured shell command, making any storage tool (aws, curl, rclone, …) usable
// without shenv depending on it.
package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultBlobPath is where the FileBackend stores the blob, and the name shenv
// keeps un-ignored in .gitignore so it can be committed.
const DefaultBlobPath = "env.shenv"

// MaxBlobSize caps how many bytes a backend will read or write for an encrypted
// blob. A hostile or runaway source (a huge env.shenv, an exec `get` that streams
// forever) would otherwise be buffered into memory unbounded. Real .env files are
// tiny; 16 MiB is far more than any legitimate blob needs. Callers that produce a
// blob must check against the same constant before storing it: a write the backend
// can no longer read back is a silent loss of everyone's secrets.
const MaxBlobSize = 16 << 20

// ErrNotFound reports that no blob is stored yet, as opposed to a storage error.
// Callers decide very different things on the two — a missing blob means "first
// seal", while a denied or failed read means the guards that depend on the
// current blob cannot run at all — so the distinction must survive wrapping.
var ErrNotFound = errors.New("no encrypted blob yet")

// maxStderrSize caps how much of a failing exec command's stderr is kept for the
// error message. A misbehaving command can write endlessly on stderr too.
const maxStderrSize = 64 << 10

// execTimeout bounds how long an exec backend command may run, so a stalled
// storage command cannot hang shenv forever. It is generous by design: the blob
// is at most MaxBlobSize, and a slow upload over a bad link must still finish.
// SHENV_EXEC_TIMEOUT (a Go duration, e.g. "2h"; "0" disables) overrides it.
const execTimeout = 10 * time.Minute

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
			return nil, fmt.Errorf("%w: %s not found — has anyone run `shenv seal` yet?", ErrNotFound, b.Path)
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
	if err := checkBlobSize(data); err != nil {
		return err
	}
	return WriteFileAtomic(b.Path, data, 0o644)
}

// WriteFileAtomic writes data to a temporary file in the destination's directory,
// flushes it to disk, and renames it into place. A crash, a full disk, or a
// concurrent shenv run then leaves either the previous file or the complete new
// one — never a truncated blob that nobody can decrypt any more. The rename is
// within one directory, so it stays atomic on every supported platform.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	// MkdirTemp-style files are 0600; widen (or narrow) before any rename so the
	// destination never appears with the wrong permissions.
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// checkBlobSize refuses to store a blob the backends could not read back.
func checkBlobSize(data []byte) error {
	if len(data) > MaxBlobSize {
		return fmt.Errorf("blob of %d bytes exceeds the %d-byte limit; it could not be read back", len(data), MaxBlobSize)
	}
	return nil
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
//
// An arbitrary shell command has no reliable way to say "nothing stored yet", so
// the contract is fixed here: exit 0 with empty stdout means not found, and any
// non-zero exit is a storage error — never a missing blob. Reading "command
// failed" as "nothing there" would let a denied or broken read look like a first
// seal and overwrite the team's blob.
type ExecBackend struct{ GetCmd, PutCmd string }

func (b ExecBackend) Get() ([]byte, error) {
	if b.GetCmd == "" {
		return nil, fmt.Errorf("exec backend: no `get` command configured in %s", configPath)
	}
	cmd, cancel := shellCommand(b.GetCmd)
	defer cancel()
	out := &capWriter{limit: MaxBlobSize, what: "exec `get` output"}
	errBuf := &capWriter{limit: maxStderrSize, what: "exec `get` stderr"}
	cmd.Stdout, cmd.Stderr = out, errBuf
	err := cmd.Run()
	// The size cap is checked before the exit status: a command that streams past
	// the limit and still exits 0 has produced a truncated blob, which must never
	// be handed on as if it were the stored one.
	if out.err != nil {
		return nil, out.err
	}
	if err != nil {
		return nil, fmt.Errorf("exec `get` failed: %w: %s", err, strings.TrimSpace(errBuf.buf.String()))
	}
	if out.buf.Len() == 0 {
		return nil, fmt.Errorf("%w: exec `get` produced no output", ErrNotFound)
	}
	return out.buf.Bytes(), nil
}

func (b ExecBackend) Put(data []byte) error {
	if b.PutCmd == "" {
		return fmt.Errorf("exec backend: no `put` command configured in %s", configPath)
	}
	if err := checkBlobSize(data); err != nil {
		return err
	}
	cmd, cancel := shellCommand(b.PutCmd)
	defer cancel()
	cmd.Stdin = bytes.NewReader(data)
	errBuf := &capWriter{limit: maxStderrSize, what: "exec `put` stderr"}
	cmd.Stderr = errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec `put` failed: %w: %s", err, strings.TrimSpace(errBuf.buf.String()))
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
	// Matched on the final element, not the whole path: a nested .gitignore is
	// just as load-bearing as the root one, and sub/.env is still a plaintext file.
	base := filepath.Base(clean)
	for _, reserved := range []string{".gitignore", ".gitattributes", ".gitmodules", ".env", configPath, "recipients.shenv"} {
		if strings.EqualFold(base, reserved) {
			return fmt.Errorf("blob path %q in %s would overwrite %s", path, configPath, reserved)
		}
	}
	return nil
}

// readCapped reads r into memory, refusing to buffer more than MaxBlobSize bytes.
func readCapped(r io.Reader, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBlobSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", what, MaxBlobSize)
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
// pipelines and arguments naturally. The returned cancel must be called once the
// command has finished; it releases the timeout that keeps a stalled storage
// command from hanging shenv forever.
func shellCommand(command string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if d := configuredExecTimeout(); d > 0 {
		ctx, cancel = context.WithTimeout(ctx, d)
	}
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/c", command), cancel
	}
	return exec.CommandContext(ctx, "sh", "-c", command), cancel
}

// configuredExecTimeout returns the exec timeout, honouring SHENV_EXEC_TIMEOUT so
// a genuinely long transfer can raise it (or set "0" to wait indefinitely). An
// unparsable value falls back to the default rather than silently disabling the
// bound.
func configuredExecTimeout() time.Duration {
	if v := os.Getenv("SHENV_EXEC_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return execTimeout
}
