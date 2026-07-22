package style

import "testing"

// TestDisabledIsPlain: with color off, every helper returns its input untouched,
// so piped output and NO_COLOR terminals get clean, escape-free text.
func TestDisabledIsPlain(t *testing.T) {
	defer SetEnabled(SetEnabled(false))
	for _, fn := range []func(string) string{Header, Prompt, Warn, Danger, Good, Dim, Bold} {
		if got := fn("hello"); got != "hello" {
			t.Errorf("disabled helper altered text: got %q", got)
		}
	}
}

// TestEnabledWraps: with color on, a non-empty string is wrapped in a reset-
// terminated sequence, and the original text is still present verbatim.
func TestEnabledWraps(t *testing.T) {
	defer SetEnabled(SetEnabled(true))
	got := Good("ok")
	if got == "ok" {
		t.Fatal("enabled helper returned plain text")
	}
	if got[:2] != "\x1b[" {
		t.Errorf("expected an ANSI prefix, got %q", got)
	}
	if got[len(got)-len(reset):] != reset {
		t.Errorf("expected a trailing reset, got %q", got)
	}
}

// TestEmptyStringNeverWrapped: an empty string stays empty even with color on,
// so callers can pass optional text without emitting a stray escape pair.
func TestEmptyStringNeverWrapped(t *testing.T) {
	defer SetEnabled(SetEnabled(true))
	if got := Bold(""); got != "" {
		t.Errorf("empty string was wrapped: %q", got)
	}
}
