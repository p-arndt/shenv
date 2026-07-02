package recipients

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestLoadRejectsDuplicateNames: signature verification looks the signer up by
// name and takes the first match, so a shadow entry with an existing member's
// name could hijack their identity — Load must reject the file outright.
func TestLoadRejectsDuplicateNames(t *testing.T) {
	inRepo(t)
	content := fmt.Sprintf("bob %s %s\nbob %s %s\n",
		testKey(t), testSignKey(t), testKey(t), testSignKey(t))
	if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected a duplicate-name error, got %v", err)
	}
}

// TestLoadRejectsControlCharacterNames: the file arrives over an untrusted
// channel, and a name carrying ANSI escape bytes could rewrite the prompts
// that display it — the add-member name rules must hold on load too.
func TestLoadRejectsControlCharacterNames(t *testing.T) {
	inRepo(t)
	content := fmt.Sprintf("bob\x1b[31m %s %s\n", testKey(t), testSignKey(t))
	if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("a name containing control characters must be rejected on load")
	}
}
