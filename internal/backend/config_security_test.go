package backend

import (
	"strings"
	"testing"
)

// TestConfigRejectsControlCharacters: config.shenv ships with the clone, and
// its exec commands are echoed in the trust prompt before running. TrimSpace
// keeps ESC (it is a control character, not whitespace), so without this
// rejection a command like the one below could redraw the prompt and hide
// what the user is approving.
func TestConfigRejectsControlCharacters(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = exec\nget = evil.sh \x1b[2K\x1b[1A# looks harmless\n")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("expected a control-character error, got %v", err)
	}
}

// TestConfigAllowsTabs: a tab is the one control character with a legitimate
// place in a config line (alignment, shell word separation) and cannot erase
// or move terminal output.
func TestConfigAllowsTabs(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend\t=\tfile\n")
	if _, err := Load(); err != nil {
		t.Fatalf("tabs must stay legal in config lines: %v", err)
	}
}

// TestBlobPathRejectsReservedTargets: config.shenv ships with the clone and the
// file backend has no trust prompt, so a hostile `path` must not be able to
// clobber the files shenv/git rely on — most critically .gitignore, whose loss
// would let the plaintext .env be staged.
func TestBlobPathRejectsReservedTargets(t *testing.T) {
	inRepo(t)
	for _, path := range []string{
		".gitignore", ".env", "recipients.shenv", "config.shenv",
		".git/config", ".git/hooks/pre-commit", ".GIT/config", "./.gitignore",
	} {
		writeConfig(t, "backend = file\npath = "+path+"\n")
		if _, err := Load(); err == nil {
			t.Fatalf("blob path %q must be rejected", path)
		}
	}
	// Sanity: ordinary paths still work.
	for _, path := range []string{"env.shenv", "secrets/env.shenv", ".env.enc"} {
		writeConfig(t, "backend = file\npath = "+path+"\n")
		if _, err := Load(); err != nil {
			t.Fatalf("blob path %q should be allowed: %v", path, err)
		}
	}
}
