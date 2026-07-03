package command

import (
	"strings"
	"testing"
)

// stubNameSources replaces the ordered default-name providers for one test and
// restores them afterwards. Each provided string becomes a source returning it.
func stubNameSources(t *testing.T, names ...string) {
	t.Helper()
	old := defaultNameSources
	srcs := make([]func() string, len(names))
	for i, n := range names {
		n := n
		srcs[i] = func() string { return n }
	}
	defaultNameSources = srcs
	t.Cleanup(func() { defaultNameSources = old })
}

func TestDefaultNamePrefersFirstUsableSource(t *testing.T) {
	stubNameSources(t, "  ", "Ada Lovelace", "fallback")
	if got := defaultName(); got != "Ada-Lovelace" {
		t.Fatalf("expected first non-empty sanitized source, got %q", got)
	}
}

func TestDefaultNameFallsBackToMe(t *testing.T) {
	// All sources yield nothing usable after sanitizing.
	stubNameSources(t, "", "   ", "\t")
	if got := defaultName(); got != "me" {
		t.Fatalf("expected fallback to 'me', got %q", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"patrick", "patrick"},
		{"Ada Lovelace", "Ada-Lovelace"},
		{"  spaced  ", "spaced"},
		{"multiple   spaces", "multiple-spaces"},
		{"tab\tsep", "tab-sep"},
		{"line\nbreak", "line-break"}, // whitespace controls collapse to a separator
		{"#hash", "hash"},
		{"##double", "double"},
		{"", ""},
		{"   ", ""},
		{"\x00\x01", ""},
		{"café", "café"}, // non-ASCII letters are preserved
		// Format characters (category Cf) must be dropped, not just controls
		// (Cc): a cloned repo's .git/config can plant them in user.name to
		// spoof how the name renders in prompts and recipients.shenv.
		{"ali\u200Bce", "alice"},       // zero-width space → visual dup of "alice"
		{"evil\u202Elive", "evillive"}, // right-to-left override
		{"a\u200Db", "ab"},             // zero-width joiner
		{"x\u2066y\u2069z", "xyz"},     // bidi isolates
		{"\u200B\u202E", ""},           // nothing usable left
		{"###", ""},                    // trims to empty → caller falls back
	}
	for _, c := range cases {
		if got := sanitizeName(c.in); got != c.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSanitizeNameCapsLength: a hostile or bloated .git/config must not be
// able to balloon the recipients file through a huge user.name.
func TestSanitizeNameCapsLength(t *testing.T) {
	got := sanitizeName(strings.Repeat("a", 10_000))
	if len([]rune(got)) != maxDerivedNameLen {
		t.Fatalf("expected derived name capped at %d runes, got %d", maxDerivedNameLen, len([]rune(got)))
	}
	// The cap must not leave a dangling separator.
	if strings.HasSuffix(sanitizeName(strings.Repeat("ab ", 100)), "-") {
		t.Fatal("truncation must not leave a trailing '-'")
	}
}
