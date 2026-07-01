package dotenv

import "testing"

func TestParseBasics(t *testing.T) {
	input := []byte(`
# a comment
API_KEY=abc123
export DB_PASS=hunter2
QUOTED="hello world"
LITERAL='no $expansion here'
EMPTY=
SPACED = trimmed
WITH_HASH=value#notacomment
ESCAPED="line1\nline2"
`)

	got, err := Parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := map[string]string{
		"API_KEY":   "abc123",
		"DB_PASS":   "hunter2",
		"QUOTED":    "hello world",
		"LITERAL":   "no $expansion here",
		"EMPTY":     "",
		"SPACED":    "trimmed",
		"WITH_HASH": "value#notacomment",
		"ESCAPED":   "line1\nline2",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d vars, want %d: %v", len(got), len(want), got)
	}
}

func TestParseLastWins(t *testing.T) {
	got, err := Parse([]byte("K=first\nK=second\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["K"] != "second" {
		t.Errorf("got %q, want last value %q", got["K"], "second")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"NOEQUALS\n", "bad key=value\n"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("expected error for %q, got nil", in)
		}
	}
}
