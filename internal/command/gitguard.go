package command

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	gopath "path"
	"path/filepath"
	"sort"
	"strings"
)

// plaintextTempPrefix names the temporary file writePlaintext creates next to a
// plaintext destination. The git guard has to know about it: that file holds the
// decrypted secrets in full, inside the repository, for as long as the write
// takes — long enough for a concurrent `git add -A` to catch it.
const plaintextTempPrefix = ".shenv-plaintext-"

// gitTarget is a plaintext destination that really lands inside a git worktree.
type gitTarget struct {
	root string // worktree root, symlink-free absolute path
	rel  string // destination relative to root, slash-separated
}

// ensureIgnored guards a plaintext destination: decrypted secrets must never be
// committable, so a destination inside a git worktree is ignored — verified with
// git itself — before any plaintext is written. It reports whether that
// protection applies; false means the destination is outside every repository
// this machine's git knows about, where there is nothing git could commit.
//
// Failing to establish the protection is fatal: better no plaintext than
// committable plaintext. Inside a detected repository every unexpected git
// failure is an error too — an unanswered question about committability is not
// a "no".
func ensureIgnored(path string) (bool, error) {
	target, err := resolveGitTarget(path)
	if err != nil || target == nil {
		return false, err
	}
	if err := target.refuseTracked(); err != nil {
		return false, err
	}

	dir := gopath.Dir(target.rel)
	tempRel := gopath.Join(dir, plaintextTempPrefix+"verify")
	tempPattern := ignorePattern(gopath.Join(dir, plaintextTempPrefix)) + "*"
	ignoreFile := filepath.Join(target.root, ".gitignore")

	// Only paths git does not already ignore get a rule: a repository whose
	// existing `.env` line covers the destination should not see its .gitignore
	// rewritten on every open.
	var rules []string
	for rel, rule := range map[string]string{target.rel: ignorePattern(target.rel), tempRel: tempPattern} {
		ignored, err := target.ignored(rel)
		if err != nil {
			return false, err
		}
		if !ignored {
			rules = append(rules, rule)
		}
	}
	sort.Strings(rules)

	added, err := appendGitignore(ignoreFile, rules...)
	if err != nil {
		return false, fmt.Errorf("could not add %s to %s (refusing to write plaintext that git could commit): %w", target.rel, ignoreFile, err)
	}

	// A rule in the file is not the same as git ignoring the file. A later
	// negation, a nested .gitignore with "!", or an ignore rule git reads from
	// somewhere else entirely can all override what we just wrote — so ask git
	// for the effective answer instead of trusting the text, and do it before a
	// single byte of plaintext exists.
	for _, rel := range []string{target.rel, tempRel} {
		ignored, err := target.ignored(rel)
		if err != nil {
			return false, err
		}
		if !ignored {
			return false, fmt.Errorf("git still does not ignore %s after a rule for it was added to %s — a negation or a nested .gitignore is overriding it; fix the ignore rules or pick a different output path (refusing to write plaintext that git could commit)", rel, ignoreFile)
		}
	}

	if added {
		fmt.Println("Updated .gitignore so the decrypted file can't be committed.")
	}
	return true, nil
}

// resolveGitTarget decides whether path ends up inside a git worktree, and
// where. Membership follows from the resolved destination, never from how the
// argument was spelled: an absolute path or a `../` detour can point straight
// back into this repository, and treating either as "outside" would skip both
// the tracked-file check and the ignore rule. Returns nil when no repository is
// involved (or git isn't installed at all) — then there is nothing to guard.
func resolveGitTarget(path string) (*gitTarget, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// The parent is resolved, not the destination itself: the destination may
	// legitimately not exist yet, and a symlink *at* it is refused elsewhere
	// rather than followed.
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("resolving the directory of %s: %w", path, err)
	}
	dest := filepath.Join(dir, filepath.Base(abs))

	out, stderr, code, err := runGit(dir, "rev-parse", "--show-toplevel")
	if errors.Is(err, exec.ErrNotFound) {
		return nil, nil // no git, no commits to protect against
	}
	if err != nil {
		return nil, fmt.Errorf("asking git about %s: %w", path, err)
	}
	if code != 0 {
		if strings.Contains(stderr, "not a git repository") {
			return nil, nil
		}
		return nil, fmt.Errorf("git could not tell whether %s is inside a repository, so it cannot be protected from being committed: %s", path, firstLine(stderr))
	}

	root, err := filepath.EvalSymlinks(strings.TrimSpace(out))
	if err != nil {
		return nil, fmt.Errorf("resolving the git worktree of %s: %w", path, err)
	}
	rel, err := filepath.Rel(root, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, nil // outside the worktree — this repository cannot commit it
	}
	return &gitTarget{root: root, rel: filepath.ToSlash(rel)}, nil
}

// refuseTracked rejects a destination git already tracks: .gitignore has no
// effect on a tracked file, so `git commit -a` would commit the plaintext no
// matter what rule we add.
func (t gitTarget) refuseTracked() error {
	_, stderr, code, err := runGitLiteral(t.root, "ls-files", "--error-unmatch", "--", t.rel)
	if err != nil {
		return fmt.Errorf("asking git whether %s is tracked: %w", t.rel, err)
	}
	switch code {
	case 0:
		return fmt.Errorf("%s is tracked by git, so .gitignore cannot keep it out of commits — pick a different output path (or `git rm --cached -- %s` first)", t.rel, t.rel)
	case 1:
		return nil
	}
	return fmt.Errorf("git could not tell whether %s is tracked, so it cannot be protected from being committed: %s", t.rel, firstLine(stderr))
}

// ignored asks git for its effective ignore decision on a worktree-relative
// path. --no-index answers for tracked paths too, and works for paths that do
// not exist yet. check-ignore takes plain pathnames rather than pathspecs, so
// it needs no literal-pathspec handling — and rejects it outright.
func (t gitTarget) ignored(rel string) (bool, error) {
	_, stderr, code, err := runGit(t.root, "check-ignore", "-q", "--no-index", "--", rel)
	if err != nil {
		return false, fmt.Errorf("asking git whether %s is ignored: %w", rel, err)
	}
	switch code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("git could not tell whether %s is ignored, so it cannot be protected from being committed: %s", rel, firstLine(stderr))
}

// runGitLiteral runs a git command whose path arguments are pathspecs, with
// pathspec magic and globbing turned off. Those paths are data: a destination
// named ":(attr)x" or "*.env" would otherwise be read as magic or as a glob,
// and the answer would be about something other than the file we are about to
// write.
func runGitLiteral(dir string, args ...string) (stdout, stderr string, code int, err error) {
	return runGitEnv(dir, []string{"GIT_LITERAL_PATHSPECS=1"}, args...)
}

// runGit runs git in dir and returns its stdout, its stderr, and its exit
// status. A non-zero status is a result, not an error; err is only set when git
// could not run at all (missing binary, spawn failure), which callers translate
// into either "no repository here" or a hard failure.
func runGit(dir string, args ...string) (stdout, stderr string, code int, err error) {
	return runGitEnv(dir, nil, args...)
}

func runGitEnv(dir string, env []string, args ...string) (stdout, stderr string, code int, err error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// The "not a git repository" check reads git's stderr, which a localized git
	// would translate.
	cmd.Env = append(append(os.Environ(), "LC_ALL=C", "LANGUAGE=C"), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut

	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), errOut.String(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return out.String(), errOut.String(), -1, err
	}
	return out.String(), errOut.String(), 0, nil
}

// ignorePattern turns a worktree-relative path into a .gitignore rule matching
// exactly that one file. The path is data, not a glob: an output called
// `.env[prod]` or `*.env` written verbatim becomes a pattern for something else
// — or for nothing. The leading slash anchors the rule to the worktree root and
// incidentally defuses a leading '!' or '#', which are only special at the very
// start of a line.
func ignorePattern(rel string) string {
	var b strings.Builder
	b.WriteByte('/')
	for _, r := range rel {
		// A backslash before any character means "match it literally" in git's
		// pattern matching, so escaping generously is safe. Spaces need it
		// because trailing ones are otherwise stripped from the rule.
		switch r {
		case '*', '?', '[', ']', '\\', '!', '#', ' ':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// appendGitignore appends the entries not already present (as exact lines) in
// the given ignore file under a "# shenv" block, reporting whether anything was
// added.
func appendGitignore(path string, entries ...string) (bool, error) {
	// Lstat, not Stat: a symlinked .gitignore must be refused, not followed.
	// Appending through it would rewrite whatever it points at while leaving the
	// repository's actual ignore rules — the ones deciding what gets committed —
	// untouched.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symlink; refusing to follow it", path)
	}

	existing, _ := os.ReadFile(path)
	lines := map[string]bool{}
	for line := range strings.SplitSeq(string(existing), "\n") {
		lines[strings.TrimSpace(line)] = true
	}

	var add []string
	for _, e := range entries {
		if !lines[e] {
			add = append(add, e)
		}
	}
	if len(add) == 0 {
		return false, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	block := "\n# shenv\n" + strings.Join(add, "\n") + "\n"
	if _, err := f.WriteString(block); err != nil {
		return false, err
	}
	return true, nil
}

// firstLine keeps a git diagnostic to one line so it fits inside an error
// message without dragging along hints and blank lines.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "git gave no reason"
	}
	return s
}
