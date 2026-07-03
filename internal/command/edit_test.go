package command

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelperEditor is not a real test: it is re-exec'd as the fake $EDITOR of
// an `shenv edit` invocation (same pattern as TestHelperProcess). The file to
// edit arrives as the last argument; SHENV_EDITOR_MODE selects the behaviour
// and SHENV_EDITOR_LOG, when set, records the file's path so tests can verify
// it was shredded. It exits immediately when not running as that child.
func TestHelperEditor(t *testing.T) {
	if os.Getenv("SHENV_EDITOR_HELPER") != "1" {
		return
	}
	file := os.Args[len(os.Args)-1]
	if log := os.Getenv("SHENV_EDITOR_LOG"); log != "" {
		if err := os.WriteFile(log, []byte(file), 0o600); err != nil {
			os.Exit(4)
		}
	}
	// SHENV_EDITOR_TOUCH simulates a teammate re-sealing while the editor is
	// open: the named file (the blob) is modified mid-edit.
	if touch := os.Getenv("SHENV_EDITOR_TOUCH"); touch != "" {
		f, err := os.OpenFile(touch, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			os.Exit(6)
		}
		if _, err := f.Write([]byte("tamper")); err != nil {
			os.Exit(6)
		}
		f.Close()
	}
	switch os.Getenv("SHENV_EDITOR_MODE") {
	case "append":
		data, err := os.ReadFile(file)
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(file, append(data, "ADDED=yes\n"...), 0o600); err != nil {
			os.Exit(3)
		}
	case "empty":
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			os.Exit(3)
		}
	case "fail":
		os.Exit(5)
	case "noop":
	}
	os.Exit(0)
}

// fakeEditor points $EDITOR at TestHelperEditor with the given mode, returning
// the log file that will hold the temp plaintext's path.
func fakeEditor(t *testing.T, mode string) string {
	t.Helper()
	log := filepath.Join(t.TempDir(), "editor.log")
	t.Setenv("SHENV_EDITOR_HELPER", "1")
	t.Setenv("SHENV_EDITOR_MODE", mode)
	t.Setenv("SHENV_EDITOR_LOG", log)
	t.Setenv("SHENV_EDITOR_TOUCH", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", os.Args[0]+" -test.run=TestHelperEditor --")
	return log
}

// tempPlaintextPath returns where the fake editor saw the transient plaintext.
func tempPlaintextPath(t *testing.T, log string) string {
	t.Helper()
	path, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("editor never ran: %v", err)
	}
	return string(path)
}

// blobBytes snapshots the sealed blob for before/after comparisons.
func blobBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("env.shenv")
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	return data
}

// TestEditRewritesBlobAndSyncsLocalEnv: the core loop — edited content ends up
// in the re-sealed blob, and a local .env that was in sync stays in sync
// (otherwise the next `seal` would revert the edit with the stale file).
func TestEditRewritesBlobAndSyncsLocalEnv(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	log := fakeEditor(t, "append")

	if err := Edit(nil); err != nil {
		t.Fatalf("edit: %v", err)
	}

	got, err := decryptEnv()
	if err != nil {
		t.Fatalf("decrypt after edit: %v", err)
	}
	if want := "X=1\nADDED=yes\n"; string(got) != want {
		t.Fatalf("blob content = %q, want %q", got, want)
	}
	local, err := os.ReadFile(defaultEnvFile)
	if err != nil {
		t.Fatalf("read local .env: %v", err)
	}
	if string(local) != string(got) {
		t.Fatalf("local .env = %q, not refreshed to %q", local, got)
	}

	// The transient plaintext must be outside the repo and gone afterwards —
	// file and its private directory both.
	temp := tempPlaintextPath(t, log)
	cwd, _ := os.Getwd()
	if strings.HasPrefix(temp, cwd) {
		t.Fatalf("temp plaintext %q was created inside the repo %q", temp, cwd)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temp plaintext %q still exists (err=%v)", temp, err)
	}
	if _, err := os.Stat(filepath.Dir(temp)); !os.IsNotExist(err) {
		t.Fatalf("temp dir %q still exists (err=%v)", filepath.Dir(temp), err)
	}
}

// TestEditNoChanges: an unchanged file must not re-seal — the blob stays
// byte-identical (no pointless re-encryption churn in git).
func TestEditNoChanges(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	before := blobBytes(t)
	fakeEditor(t, "noop")

	out := captureStdout(t, func() {
		if err := Edit(nil); err != nil {
			t.Errorf("edit: %v", err)
		}
	})
	if !strings.Contains(out, "No changes") {
		t.Fatalf("expected a no-changes notice, got:\n%s", out)
	}
	if string(blobBytes(t)) != string(before) {
		t.Fatal("blob was rewritten despite no changes")
	}
}

// TestEditEditorFailureAborts: a non-zero editor exit means nothing gets
// sealed — and the transient plaintext is still shredded.
func TestEditEditorFailureAborts(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	before := blobBytes(t)
	log := fakeEditor(t, "fail")

	err := Edit(nil)
	if err == nil || !strings.Contains(err.Error(), "editor") {
		t.Fatalf("expected an editor error, got %v", err)
	}
	if string(blobBytes(t)) != string(before) {
		t.Fatal("blob changed after a failed editor")
	}
	temp := tempPlaintextPath(t, log)
	if _, statErr := os.Stat(temp); !os.IsNotExist(statErr) {
		t.Fatalf("temp plaintext %q survived the failed edit", temp)
	}
}

// TestEditEmptyNeedsConfirmation: wiping the whole file is more likely a
// mistake than an intent — declining the prompt must leave the blob alone.
func TestEditEmptyNeedsConfirmation(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	before := blobBytes(t)
	fakeEditor(t, "empty")
	feed(t, "n\n")

	out := captureStdout(t, func() {
		if err := Edit(nil); err != nil {
			t.Errorf("edit: %v", err)
		}
	})
	if !strings.Contains(out, "Aborted") {
		t.Fatalf("expected an abort notice, got:\n%s", out)
	}
	if string(blobBytes(t)) != string(before) {
		t.Fatal("blob changed after declining the empty-file prompt")
	}
}

// TestEditPreservesDivergentLocalEnv: a .env with its own local changes must
// not be clobbered by the refresh — but the user is told about the divergence.
func TestEditPreservesDivergentLocalEnv(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	writeEnv(t, "LOCAL=mine\n") // diverged after the seal
	fakeEditor(t, "append")

	out := captureStdout(t, func() {
		if err := Edit(nil); err != nil {
			t.Errorf("edit: %v", err)
		}
	})
	local, err := os.ReadFile(defaultEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(local) != "LOCAL=mine\n" {
		t.Fatalf("divergent local .env was overwritten: %q", local)
	}
	if !strings.Contains(out, "left alone") {
		t.Fatalf("expected a divergence note, got:\n%s", out)
	}
}

// TestEditorRejectsNotepad: notepad's tab session cache copies file contents
// to its own on-disk store (outliving the shredded temp file) and a running
// instance takes the file and returns immediately — it must be refused however
// it is spelled, with the reason in the error.
func TestEditorRejectsNotepad(t *testing.T) {
	for _, val := range []string{"notepad", "NOTEPAD.EXE", `C:\Windows\System32\notepad.exe`} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", val)
			_, err := editorArgv()
			if err == nil || !strings.Contains(err.Error(), "notepad") {
				t.Fatalf("EDITOR=%q: expected a notepad refusal, got %v", val, err)
			}
		})
	}
}

// TestEditorRejectsNotepadBeforePlaintextExists: the refusal must fire before
// anything is decrypted or written — a doomed edit must not create plaintext.
func TestEditorRejectsNotepadBeforePlaintextExists(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	log := fakeEditor(t, "append") // sets the helper env…
	t.Setenv("EDITOR", "notepad")  // …but notepad overrides the command

	err := Edit(nil)
	if err == nil || !strings.Contains(err.Error(), "notepad") {
		t.Fatalf("expected a notepad refusal, got %v", err)
	}
	if _, statErr := os.Stat(log); !os.IsNotExist(statErr) {
		t.Fatal("an editor ran despite the refusal")
	}
}

// TestEditorRequiresWaitForVSCode: without --wait, code returns immediately
// and the flow is guaranteed broken — the error must name the fix.
func TestEditorRequiresWaitForVSCode(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "code")
	if _, err := editorArgv(); err == nil || !strings.Contains(err.Error(), "--wait") {
		t.Fatalf("expected a --wait hint, got %v", err)
	}

	t.Setenv("EDITOR", "code --wait")
	argv, err := editorArgv()
	if err != nil || argv[0] != "code" {
		t.Fatalf("code --wait should be accepted, got %v / %v", argv, err)
	}
}

// TestEditorRejectsNotepadPlusPlus: default notepad++ has notepad's problems
// too — instance handoff plus a backup cache holding unsaved content — but it
// has flags that fix both, so those are required rather than refusing outright.
func TestEditorRejectsNotepadPlusPlus(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "notepad++")
	if _, err := editorArgv(); err == nil || !strings.Contains(err.Error(), "-multiInst") {
		t.Fatalf("expected a notepad++ refusal naming the flags, got %v", err)
	}

	t.Setenv("EDITOR", "notepad++ -multiInst -notabbar -nosession -noPlugin")
	if _, err := editorArgv(); err != nil {
		t.Fatalf("notepad++ with the safe flags should be accepted, got %v", err)
	}
}

// TestEditorRequiresWaitForSublime: subl without -w returns immediately and
// hot exit caches the unsaved buffer — same family as VS Code.
func TestEditorRequiresWaitForSublime(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "subl")
	if _, err := editorArgv(); err == nil || !strings.Contains(err.Error(), "--wait") {
		t.Fatalf("expected a --wait hint for subl, got %v", err)
	}

	t.Setenv("EDITOR", "subl -w")
	if _, err := editorArgv(); err != nil {
		t.Fatalf("subl -w should be accepted, got %v", err)
	}
}

// TestEditorRequiresForegroundForGvim: gvim forks from the terminal without
// -f, so shenv would shred the directory while the editor still has it open.
// -F must NOT count — that's gvim's Farsi mode, and it still forks.
func TestEditorRequiresForegroundForGvim(t *testing.T) {
	t.Setenv("VISUAL", "")
	for _, val := range []string{"gvim", "gvim -F"} {
		t.Setenv("EDITOR", val)
		if _, err := editorArgv(); err == nil || !strings.Contains(err.Error(), "-f") {
			t.Fatalf("EDITOR=%q: expected a -f hint, got %v", val, err)
		}
	}

	t.Setenv("EDITOR", "gvim -f")
	if _, err := editorArgv(); err != nil {
		t.Fatalf("gvim -f should be accepted, got %v", err)
	}
}

// TestEditRejectsArgs: `shenv edit prod.env` must error, not silently edit
// the default blob while the user believes they edited prod.env.
func TestEditRejectsArgs(t *testing.T) {
	err := Edit([]string{"prod.env"})
	if err == nil || !strings.Contains(err.Error(), "no arguments") {
		t.Fatalf("expected a no-arguments error, got %v", err)
	}
}

// TestEditDetectsConcurrentReseal: a blob re-sealed while the editor was open
// must not be silently overwritten — sealing anyway could re-instate a secret
// a teammate just rotated. Declining the prompt keeps their version.
func TestEditDetectsConcurrentReseal(t *testing.T) {
	setup(t)
	mustInit(t)
	mustSeal(t, "X=1\n")
	fakeEditor(t, "append")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHENV_EDITOR_TOUCH", filepath.Join(cwd, "env.shenv"))
	feed(t, "n\n")

	out := captureStdout(t, func() {
		if err := Edit(nil); err != nil {
			t.Errorf("edit: %v", err)
		}
	})
	if !strings.Contains(out, "changed while you were editing") {
		t.Fatalf("expected a concurrent-change warning, got:\n%s", out)
	}
	if !bytes.HasSuffix(blobBytes(t), []byte("tamper")) {
		t.Fatal("the concurrently-written blob was overwritten despite declining")
	}
}

// TestEditorPrefersVisual: $VISUAL wins over $EDITOR, per convention.
func TestEditorPrefersVisual(t *testing.T) {
	t.Setenv("VISUAL", "vim -u NONE")
	t.Setenv("EDITOR", "nano")
	argv, err := editorArgv()
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 3 || argv[0] != "vim" || argv[1] != "-u" {
		t.Fatalf("expected [vim -u NONE], got %v", argv)
	}
}

// TestEditorNoneFound: with nothing configured and an empty PATH there is no
// safe default — a clear error beats silently picking something leaky.
func TestEditorNoneFound(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := editorArgv(); err == nil || !strings.Contains(err.Error(), "no editor found") {
		t.Fatalf("expected a no-editor error, got %v", err)
	}
}

// TestEditRequiresBlob: with nothing sealed yet there is nothing to edit.
func TestEditRequiresBlob(t *testing.T) {
	setup(t)
	mustInit(t)
	fakeEditor(t, "append")

	err := Edit(nil)
	if err == nil || !strings.Contains(err.Error(), "nothing to edit") {
		t.Fatalf("expected a nothing-to-edit error, got %v", err)
	}
}
