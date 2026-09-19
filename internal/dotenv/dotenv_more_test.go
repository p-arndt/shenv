package dotenv

import (
	"strings"
	"testing"
)

// TestParseErrorsNeverEchoInput: parser errors reach stderr, so they must name
// the line number and the category only — never the decrypted line itself. A
// multiline credential looks exactly like a malformed line to the parser.
func TestParseErrorsNeverEchoInput(t *testing.T) {
	const marker = "sYnthEtic-sEcret-marker-9f1c"

	inputs := map[string]string{
		"missing '='":           marker + "\n",
		"invalid name":          "bad key" + marker + "=value\n",
		"empty name":            "=" + marker + "\n",
		"unterminated quote":    "MULTILINE=\"" + marker + "\n" + marker + "\n",
		"value after good pair": "TOKEN=ok\n" + marker + "\n",
	}

	for name, in := range inputs {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Errorf("%s: expected an error for %q", name, in)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: error discloses input: %q", name, err)
		}
	}
}

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
