package dotenv

import "testing"

// TestUnescapeSequences exercises every branch of the double-quote escape handler,
// including the "unknown escape drops the backslash" default and a dangling
// trailing backslash (no following byte).
func TestUnescapeSequences(t *testing.T) {
	cases := map[string]string{
		`A="a\nb"`: "a\nb",
		`A="a\tb"`: "a\tb",
		`A="a\rb"`: "a\rb",
		`A="a\"b"`: `a"b`,
		`A="a\\b"`: `a\b`,
		`A="a\qb"`: "aqb", // unknown escape → backslash dropped, letter kept
		`A="a\"`:   `a\`,  // dangling backslash (no following byte): kept literally
	}
	for input, want := range cases {
		got, err := Parse([]byte(input + "\n"))
		if err != nil {
			t.Errorf("%q: unexpected error %v", input, err)
			continue
		}
		if got["A"] != want {
			t.Errorf("%q: got %q, want %q", input, got["A"], want)
		}
	}
}

// TestParseUnbalancedQuoteIsLiteral: a value with only a leading quote isn't a
// quoted value, so it's taken verbatim rather than being stripped/expanded.
func TestParseUnbalancedQuoteIsLiteral(t *testing.T) {
	got, err := Parse([]byte(`A="unterminated` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["A"] != `"unterminated` {
		t.Fatalf("got %q, want the raw value", got["A"])
	}
}

// TestParseEmptyInput: no lines, no error, empty map (not nil-panicking).
func TestParseEmptyInput(t *testing.T) {
	got, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
}
