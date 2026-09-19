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

// TestLoadRejectsDuplicateKeys: attribution maps name → keys one-to-one; an
// entry reusing another member's age key (push's "who am I" lookup) or sign
// key (pull's "who signed this" lookup) makes both ambiguous.
func TestLoadRejectsDuplicateKeys(t *testing.T) {
	inRepo(t)
	key, signKey := testKey(t), testSignKey(t)
	cases := map[string]string{
		"shared age key":  fmt.Sprintf("alice %s %s\nbob %s %s\n", key, testSignKey(t), key, testSignKey(t)),
		"shared sign key": fmt.Sprintf("alice %s %s\nbob %s %s\n", testKey(t), signKey, testKey(t), signKey),
	}
	for name, content := range cases {
		if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "share the same") {
			t.Fatalf("%s: expected a shared-key error, got %v", name, err)
		}
	}
}

// TestLoadRejectsInvalidKeys: the key columns must be validated on load, not
// only where they happen to be parsed later. Push's recipient-change prompt
// echoes these fields, so a "sign key" smuggling terminal escapes (invalid
// base64 never contains them) could redraw the prompt that exposes tampering.
func TestLoadRejectsInvalidKeys(t *testing.T) {
	inRepo(t)
	cases := map[string]string{
		"bad public key": fmt.Sprintf("bob not-a-key %s\n", testSignKey(t)),
		"bad sign key":   fmt.Sprintf("bob %s \x1b[2K\x1b[1Aspoof\n", testKey(t)),
	}
	for name, content := range cases {
		if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(); err == nil {
			t.Fatalf("%s: Load must reject the file", name)
		}
	}
}

// TestLoadRejectsFormatCharacterNames: Unicode format characters (category Cf,
// e.g. zero-width space and bidi overrides) are invisible yet are not control
// characters, so IsControl alone would let them through. A cloned recipients
// file could plant "bob<ZWSP>" as a visual duplicate of "bob" — and the
// duplicate-name guard compares exact strings, so the forgery would slip past
// it. Load must reject any non-graphic rune.
func TestLoadRejectsFormatCharacterNames(t *testing.T) {
	inRepo(t)
	for label, evil := range map[string]string{
		"zero-width space":       "bob\u200B",
		"right-to-left override": "ev\u202Eil",
	} {
		content := fmt.Sprintf("%s %s %s\n", evil, testKey(t), testSignKey(t))
		if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(); err == nil {
			t.Fatalf("%s: a name with format characters must be rejected on load", label)
		}
	}
}

// TestLookalikeNamesAreRejected: a name that differs from a member's only by
// lookalike characters is an impersonation, whichever way it gets in.
func TestLookalikeNamesAreRejected(t *testing.T) {
	if skeleton("\u0430lice") != skeleton("alice") || skeleton("\uff41lice") != skeleton("alice") {
		t.Fatal("Cyrillic and fullwidth lookalikes must share a skeleton with the Latin name")
	}
	if skeleton("j\u00f6rg") == skeleton("jorg") {
		t.Fatal("a genuinely different name must keep its own skeleton")
	}
	for _, name := range []string{"j\u00f6rg", "\u0438\u0432\u0430\u043d", "alice"} {
		if err := validateName(name); err != nil {
			t.Errorf("validateName(%q) = %v, want nil", name, err)
		}
	}
	if err := validateName(strings.Repeat("a", maxNameLen+1)); err == nil {
		t.Error("an over-long name must be rejected")
	}
}

// TestLoadAndAddRejectLookalikeMembers: both doors into the member list — a
// pulled file and `add-member` — must refuse a visual twin of an existing name.
func TestLoadAndAddRejectLookalikeMembers(t *testing.T) {
	inRepo(t)
	if err := Add("alice", testKey(t), testSignKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := Add("аlice", testKey(t), testSignKey(t)); err == nil {
		t.Fatal("add-member must refuse a lookalike of an existing member")
	}

	content := fmt.Sprintf("alice %s %s\nаlice %s %s\n",
		testKey(t), testSignKey(t), testKey(t), testSignKey(t))
	if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "look identical") {
		t.Fatalf("expected a lookalike error, got %v", err)
	}
}
