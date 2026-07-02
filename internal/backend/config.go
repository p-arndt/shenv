package backend

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// readConfig parses a simple `key = value` config file. Blank lines and lines
// starting with '#' are ignored. A missing file yields an empty config (which
// Load treats as the default file backend). Values keep everything after the
// first '=', so exec commands may contain '=' freely.
func readConfig(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	cfg := map[string]string{}
	lineNo := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		lineNo++
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// The config ships with the clone, and exec commands from it are shown in
		// the trust prompt before running. An embedded terminal escape (ESC is not
		// whitespace, so TrimSpace keeps it) could redraw that prompt to hide what
		// is being approved. No key or single-line command needs control characters.
		if i := strings.IndexFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }); i >= 0 {
			return nil, fmt.Errorf("%s line %d: control character in %q", path, lineNo, raw)
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: missing '=' in %q", path, lineNo, raw)
		}
		cfg[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return cfg, nil
}
