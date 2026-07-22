// Package style adds optional ANSI color to shenv's terminal output. Color is a
// readability aid only — it never carries meaning that plain text doesn't also
// convey, so a no-color terminal, a pipe, or NO_COLOR loses nothing but the tint.
package style

import (
	"os"

	"golang.org/x/term"
)

// ANSI SGR sequences. Kept minimal: shenv only needs a handful of semantic
// styles, and sticking to the 8 basic colors keeps output legible on the widest
// range of themes (including light backgrounds).
const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
)

// enabled reports whether color codes should be emitted. It's decided once at
// startup from the environment and whether stdout is a real terminal, then can
// be overridden for tests via SetEnabled.
var enabled = detect()

// detect follows the common conventions: NO_COLOR disables color unconditionally
// (https://no-color.org), CLICOLOR_FORCE enables it even when not a TTY, TERM=dumb
// opts out, and otherwise color is on only when stdout is an interactive terminal.
func detect() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if v, ok := os.LookupEnv("CLICOLOR_FORCE"); ok && v != "" && v != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// SetEnabled forces color on or off and returns the previous setting, so a test
// can exercise the colored paths regardless of where its output is going.
func SetEnabled(on bool) bool {
	prev := enabled
	enabled = on
	return prev
}

// Enabled reports whether color output is currently on.
func Enabled() bool { return enabled }

func wrap(codes, s string) string {
	if !enabled || s == "" {
		return s
	}
	return codes + s + reset
}

// Header styles a section heading (e.g. the key labels in `whoami`).
func Header(s string) string { return wrap(bold+cyan, s) }

// Prompt styles a line that is waiting for the user to type an answer, so a
// blocking [y/N] question can't be mistaken for ordinary output and scrolled past.
func Prompt(s string) string { return wrap(bold+yellow, s) }

// Warn styles a caution the user should read but that isn't necessarily fatal.
func Warn(s string) string { return wrap(yellow, s) }

// Danger styles a destructive or security-critical warning (lockouts, undecryptable blobs).
func Danger(s string) string { return wrap(bold+red, s) }

// Good styles a success confirmation.
func Good(s string) string { return wrap(green, s) }

// Dim de-emphasizes secondary text (hints, parentheticals).
func Dim(s string) string { return wrap(dim, s) }

// Bold emphasizes without a color, so it reads on any background.
func Bold(s string) string { return wrap(bold, s) }
