// Package dotenv is a minimal-but-robust parser for .env content: KEY=VALUE
// pairs, with comments, blank lines, an optional `export` prefix, and single-
// or double-quoted values. Double-quoted values expand \n \t \r \" \\ escapes;
// single-quoted values are literal. Inline comments after unquoted values are
// NOT stripped (a value may legitimately contain '#').
package dotenv

import (
	"fmt"
	"strings"
)

// Parse turns .env content into a map of variables. Later definitions of the
// same key win. It errors on a line that has no '=' or an invalid name.
func Parse(data []byte) (map[string]string, error) {
	out := make(map[string]string)

	lineNo := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		lineNo++
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Optional `export KEY=...` shell-style prefix.
		if rest, ok := strings.CutPrefix(line, "export "); ok {
			line = strings.TrimSpace(rest)
		}

		key, rawVal, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '=' in %q", lineNo, raw)
		}
		key = strings.TrimSpace(key)
		if key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("line %d: invalid variable name %q", lineNo, key)
		}

		out[key] = parseValue(strings.TrimSpace(rawVal))
	}
	return out, nil
}

// parseValue strips matching surrounding quotes and, for double quotes, expands
// escape sequences. Unquoted values are used verbatim (already space-trimmed).
func parseValue(v string) string {
	if len(v) >= 2 {
		switch {
		case v[0] == '"' && v[len(v)-1] == '"':
			return unescape(v[1 : len(v)-1])
		case v[0] == '\'' && v[len(v)-1] == '\'':
			return v[1 : len(v)-1]
		}
	}
	return v
}

// unescape expands the escape sequences allowed inside double-quoted values.
func unescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteByte(s[i+1]) // unknown escape → drop the backslash
			}
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
