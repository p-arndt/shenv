package backend

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// An exec backend runs shell commands out of config.shenv, which arrives over the
// same untrusted channel as the ciphertext (a clone, a merged PR). Running it
// blindly is arbitrary code execution. We gate it behind trust-on-first-use: the
// exact commands, bound to this repo's config path, must be approved once and are
// re-approved whenever they change — the same model direnv uses for .envrc.

// ExecConfirmFunc is called when an exec backend's commands are not yet trusted.
// It should show the commands to the user and return true to approve them. It is
// only ever invoked for an ExecBackend.
type ExecConfirmFunc func(getCmd, putCmd string) (bool, error)

// EnsureTrusted verifies that an exec backend's commands have been approved for
// this repo before they are ever run. Non-exec backends are always trusted. On an
// unapproved exec backend it invokes confirm; if approved, the commands are
// recorded so future runs are silent. Set SHENV_ALLOW_EXEC=1 to pre-approve in a
// non-interactive environment (CI) — use it only where the config is trusted.
func EnsureTrusted(b Backend, confirm ExecConfirmFunc) error {
	eb, ok := b.(ExecBackend)
	if !ok {
		return nil
	}

	fp, err := execFingerprint(eb)
	if err != nil {
		return err
	}
	ok, err = isTrusted(fp)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	if os.Getenv("SHENV_ALLOW_EXEC") == "1" {
		return nil
	}

	approved, err := confirm(eb.GetCmd, eb.PutCmd)
	if err != nil {
		return err
	}
	if !approved {
		return fmt.Errorf("exec backend not approved — declined to run commands from %s", configPath)
	}
	return addTrusted(fp, eb)
}

// execFingerprint identifies a specific set of exec commands bound to this repo's
// config file, so approving one repo's backend never silently approves another's.
func execFingerprint(eb ExecBackend) (string, error) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	// NUL separators can't appear in any field, so the hash is unambiguous.
	fmt.Fprintf(h, "%s\x00%s\x00%s", abs, eb.GetCmd, eb.PutCmd)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// trustFile is where approved exec-backend fingerprints are recorded, in the
// user's global shenv dir (never in the repo, so a hostile repo can't self-approve).
func trustFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "trusted"), nil
}

func isTrusted(fingerprint string) (bool, error) {
	path, err := trustFile()
	if err != nil {
		return false, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Each entry is "<fingerprint>  # <commands>"; match the first field only.
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == fingerprint {
			return true, nil
		}
	}
	return false, sc.Err()
}

func addTrusted(fingerprint string, eb ExecBackend) error {
	path, err := trustFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// The comment is a human-readable reminder of what was approved; only the
	// leading fingerprint is ever matched.
	summary := strings.ReplaceAll(eb.GetCmd+" || "+eb.PutCmd, "\n", " ")
	_, err = fmt.Fprintf(f, "%s  # %s\n", fingerprint, summary)
	return err
}
