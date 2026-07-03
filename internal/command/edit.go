package command

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/identity"
	"shenv/internal/recipients"
)

// Edit decrypts env.shenv into a transient file OUTSIDE the repo, opens your
// editor on it, and re-seals the result for all members — so secrets can be
// changed without a plaintext .env ever existing in the repository. The
// transient file lives in a freshly created private directory (RAM-backed
// /dev/shm on Linux when available, the per-user temp dir elsewhere), is
// locked to your OS user before the plaintext is written, and is shredded on
// every exit path — including editor failures and declined prompts. Re-sealing
// goes through the same guards as `shenv seal` (lockout check, recipient
// confirmation, signing).
func Edit(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("edit takes no arguments — it always edits the sealed env.shenv (to seal a different file, use `shenv seal %s`)", args[0])
	}

	// Resolve (and vet) the editor before anything is decrypted: a refused or
	// missing editor must fail here, while no plaintext exists anywhere yet.
	editor, err := editorArgv()
	if err != nil {
		return err
	}

	// Fetch and verify first — an edit only makes sense against a blob we can
	// decrypt and whose sealer checks out. The identity is loaded once and
	// reused for re-sealing, so an uncached passphrase is asked at most once.
	store, err := loadBackend()
	if err != nil {
		return err
	}
	blob, err := store.Get()
	if err != nil {
		return fmt.Errorf("nothing to edit: %w", err)
	}
	pub, err := identity.PublicKey()
	if err != nil {
		return err
	}
	id, err := identity.Load(unlocker(pub))
	if err != nil {
		return err
	}
	payload, err := crypto.DecryptBytes(blob, id)
	if err != nil {
		return fmt.Errorf("your key can't decrypt env.shenv — ask a member to `shenv add-member` you and re-seal: %w", err)
	}
	body, err := verifySigner(payload)
	if err != nil {
		return err
	}
	_, before := recipients.ExtractManifest(body)

	edited, err := editInTemp(before, editor)
	if err != nil {
		return err
	}
	if bytes.Equal(edited, before) {
		fmt.Println("No changes — env.shenv left untouched.")
		return nil
	}

	// The editor may have been open for a while, and this edit is based on the
	// blob fetched before it. If a teammate re-sealed meanwhile, sealing now
	// would silently discard their update — worst case re-instating a secret
	// they just rotated, under a perfectly valid signature. Re-fetch and ask.
	if cur, err := store.Get(); err == nil && !bytes.Equal(cur, blob) {
		fmt.Println("env.shenv changed while you were editing — someone re-sealed it, and your edit is based on the old contents.")
		fmt.Print("Seal your edit anyway, discarding theirs? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted — the newer env.shenv was kept and your edits were discarded. Run `shenv edit` again to redo them on top of it.")
			return nil
		}
	}

	if len(edited) == 0 {
		fmt.Print("The edited file is empty — seal an empty env.shenv for the whole team? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted — env.shenv left untouched and your edits were discarded.")
			return nil
		}
	}

	sealed, err := sealEnv(edited, "your edits", pub,
		func() (*age.X25519Identity, error) { return id, nil },
		func() (backend.Backend, error) { return store, nil })
	if err != nil {
		return err
	}
	if !sealed {
		// One of seal's guards was declined. The transient copy is already
		// shredded — losing the edit beats keeping plaintext around.
		fmt.Println("Your edits were NOT sealed and were discarded.")
		return nil
	}

	refreshLocalEnv(before, edited)
	return nil
}

// editInTemp writes content to a locked-down file in a private directory
// outside the repo, runs the user's editor on it, and returns what the editor
// left behind. The directory — including any swap/backup files the editor
// dropped next to the plaintext — is shredded before returning, on success and
// failure alike.
func editInTemp(content []byte, editor []string) ([]byte, error) {
	dir, err := secureTempDir()
	if err != nil {
		return nil, fmt.Errorf("creating a private temp directory: %w", err)
	}
	defer shredDir(dir)

	// Named .env so editors apply their usual dotenv handling. O_EXCL matches
	// identity.Create: create-if-absent is atomic and refuses to follow a
	// pre-planted symlink, and the file is locked to this user (Windows: an
	// explicit owner-only ACL; the 0600 bits cover Unix) while still empty, so
	// no byte of plaintext ever exists under looser permissions.
	path := filepath.Join(dir, ".env")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := identity.SecureFile(path); err != nil {
		f.Close()
		return nil, fmt.Errorf("securing the temp file: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	if err := runEditor(path, editor); err != nil {
		return nil, err
	}

	edited, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the edited file back: %w", err)
	}
	return edited, nil
}

// secureTempDir creates the private directory holding the transient plaintext.
// It is always outside the repo — git can never see, track, or commit it. On
// Linux it prefers /dev/shm (tmpfs): the plaintext then lives in RAM and never
// reaches persistent storage at all. Elsewhere the per-user temp dir is used
// (0700 via MkdirTemp on Unix; on Windows %TEMP% sits inside the user profile,
// which other non-admin users cannot read). The unpredictable MkdirTemp name
// doubles as protection against pre-planted paths.
func secureTempDir() (string, error) {
	if runtime.GOOS == "linux" {
		if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
			if dir, err := os.MkdirTemp("/dev/shm", "shenv-edit-*"); err == nil {
				return dir, nil
			}
		}
	}
	return os.MkdirTemp("", "shenv-edit-*")
}

// runEditor opens the user's editor on path and waits for it to exit. A
// non-zero exit aborts the edit — nothing gets sealed.
func runEditor(path string, argv []string) error {
	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	// The editor owns the terminal now, and Ctrl-C is an ordinary keystroke in
	// many of them (vim aborts a pending command with it). The terminal delivers
	// the signal to shenv too; dying on it would yank the file out from under
	// the editor mid-session. Ignore it while the editor runs — the same thing
	// git does around its editor — and restore the default afterwards.
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %s failed: %w — nothing was sealed", argv[0], err)
	}
	return nil
}

// editorArgv resolves the editor command: $VISUAL, then $EDITOR, then a
// platform fallback verified to exist on PATH. The value is whitespace-split
// so flags work (e.g. EDITOR="code --wait"); an editor at a path containing
// spaces needs a small wrapper script, the same limitation git has without
// shell quoting. Editors known to break edit's security model are refused —
// see vetEditor.
func editorArgv() ([]string, error) {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		fields := strings.Fields(os.Getenv(v))
		if len(fields) == 0 {
			continue
		}
		if err := vetEditor(fields); err != nil {
			return nil, fmt.Errorf("$%s: %w", v, err)
		}
		return fields, nil
	}
	for _, c := range fallbackEditors() {
		if _, err := exec.LookPath(c); err == nil {
			return []string{c}, nil
		}
	}
	return nil, fmt.Errorf("no editor found — set VISUAL or EDITOR to one that waits until you close the file (e.g. `vim`, `nano`, or `code --wait`)")
}

// fallbackEditors are tried on PATH, in order, when neither VISUAL nor EDITOR
// is set.
func fallbackEditors() []string {
	if runtime.GOOS == "windows" {
		// Microsoft Edit — the `edit` console editor that ships with Windows
		// 11 — blocks until closed and keeps no session cache; vim/nano turn
		// up via Git for Windows or package managers. Notepad is deliberately
		// NOT here: see vetEditor for why it can never be trusted with secrets.
		return []string{"edit", "vim", "nano"}
	}
	return []string{"vi", "nano"}
}

// vetEditor refuses configured editors that are guaranteed to break the edit
// flow or leak the plaintext, and says why — a silent bad default here would
// quietly copy secrets into an unmanaged cache.
//
// Two failure modes, often together. Returns-immediately: the command hands
// the file to an already-running instance (Notepad, Notepad++, Sublime, VS
// Code without --wait) or forks from the terminal (gvim without -f), so shenv
// can't tell when editing is done — it would read the still-unchanged file and
// shred the directory while the editor holds it open. Caches-the-content: the
// editor copies the buffer into its own on-disk store, where the secrets
// outlive the shredded temp file — Notepad's tab session (TabState), VS Code's
// hot-exit backups, Notepad++'s session snapshot/periodic backup, Sublime's
// hot-exit session. Where flags fix it (--wait, -f, -multiInst -nosession)
// the error names them; Notepad has no such flags and is refused outright.
func vetEditor(argv []string) error {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(argv[0])), ".exe")
	switch name {
	case "notepad":
		return fmt.Errorf("notepad can't be trusted with secrets: it hands the file to an already-running instance (shenv can't tell when you're done) and its tab session cache keeps a copy of the contents on disk after shenv shreds the temp file — use `edit` (ships with Windows 11), `vim`, or `code --wait` instead")
	case "notepad++":
		if hasFlag(argv, "-multiInst") && hasFlag(argv, "-nosession") {
			return nil
		}
		return fmt.Errorf("notepad++ by default hands the file to an already-running instance and snapshots unsaved content to its own backup cache — use EDITOR=\"notepad++ -multiInst -notabbar -nosession -noPlugin\"")
	case "code", "codium", "code-insiders", "subl", "sublime_text":
		if hasFlag(argv, "--wait") || hasFlag(argv, "-w") {
			return nil
		}
		return fmt.Errorf("%s returns before you finish editing — add --wait (e.g. EDITOR=\"%s --wait\")", name, name)
	case "gvim", "mvim":
		if hasFlag(argv, "-f") || hasFlag(argv, "--nofork") {
			return nil
		}
		return fmt.Errorf("%s forks away from the terminal and returns before you finish editing — add -f (e.g. EDITOR=\"%s -f\")", name, name)
	}
	return nil
}

// hasFlag reports whether the flag appears among the configured editor's
// arguments. Matching is exact: near-misses can mean something else entirely
// (gvim's -F is Farsi mode, not foreground), so a wrong casing must not pass.
func hasFlag(argv []string, flag string) bool {
	for _, a := range argv[1:] {
		if a == flag {
			return true
		}
	}
	return false
}

// shredDir best-effort destroys the transient directory: every regular file in
// it — the plaintext and any editor swap/backup copies — is overwritten with
// zeros and synced before the directory is removed. Honest caveat: on
// journaling filesystems and wear-leveled SSDs an overwrite doesn't guarantee
// the old blocks are gone; the real protections are the owner-only permissions
// and, on Linux, tmpfs keeping the plaintext out of persistent storage
// entirely. Errors are non-fatal (the secrets are already re-sealed or
// abandoned), but a directory that survives is reported so it can be removed
// by hand.
func shredDir(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Type().IsRegular() {
			zeroFile(filepath.Join(dir, e.Name()))
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove the temp directory %s: %v — its files are zeroed, but delete it manually.\n", dir, err)
	}
}

// zeroFile overwrites a file's current contents with zeros and syncs, so the
// bytes are gone even where the directory removal alone would just unlink.
// Oversized files (an editor artifact gone wrong) are skipped rather than
// ballooning memory — removal still unlinks them.
func zeroFile(path string) {
	const maxZero = 16 << 20 // same ceiling the backends place on blobs
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > maxZero {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(make([]byte, fi.Size()))
	_ = f.Sync()
}

// refreshLocalEnv keeps a local .env from silently reverting the edit: if it
// matched the old sealed content (the in-sync case), it is updated to the new
// content — otherwise the very next `shenv seal` would overwrite the edit with
// the stale file. A .env with its own local changes is left alone but flagged,
// and no .env at all means the pure no-plaintext workflow — nothing to do.
// Failures here only warn: the seal already succeeded, and refusing to write
// beats writing plaintext through a symlink or outside .gitignore's cover.
func refreshLocalEnv(before, after []byte) {
	local, err := os.ReadFile(defaultEnvFile)
	if err != nil {
		return // no local plaintext — exactly what edit is for
	}
	if bytes.Equal(local, after) {
		return
	}
	if !bytes.Equal(local, before) {
		fmt.Printf("Note: your local %s has its own changes and was left alone — it no longer matches env.shenv, and `shenv seal` would overwrite your edit with it.\n", defaultEnvFile)
		return
	}
	if err := backend.RejectSymlinks(defaultEnvFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: not updating %s: %v\n", defaultEnvFile, err)
		return
	}
	if err := ensureIgnored(defaultEnvFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: not updating %s: %v\n", defaultEnvFile, err)
		return
	}
	if err := os.WriteFile(defaultEnvFile, after, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not update %s: %v — run `shenv open` to refresh it.\n", defaultEnvFile, err)
		return
	}
	_ = os.Chmod(defaultEnvFile, 0o600)
	fmt.Printf("Updated the local %s to match (it was in sync before the edit).\n", defaultEnvFile)
}
