package backend

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// maxProjectLen bounds the project id; it is signed and printed, never parsed.
const maxProjectLen = 64

// Project returns the project id from config.shenv, or "" when none is set.
// Signatures are bound to it (see the recipients package), so a blob sealed for
// another project — by a member trusted in both — fails verification here. The
// id is not secret and ships with the clone like the rest of the config: it
// defends against whoever can write to the blob storage, not against whoever can
// rewrite the repo.
func Project() (string, error) {
	cfg, err := readConfig(configPath)
	if err != nil {
		return "", err
	}
	id := cfg["project"]
	if id == "" {
		return "", nil
	}
	if err := validateProject(id); err != nil {
		return "", err
	}
	return id, nil
}

// validateProject keeps the id to one unambiguous token: it becomes a line of
// the signed bytes, so whitespace or a newline would let two different ids
// produce the same signed message.
func validateProject(id string) error {
	if len(id) > maxProjectLen {
		return fmt.Errorf("project id in %s is longer than %d characters", configPath, maxProjectLen)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("project id %q in %s may only contain letters, digits, '-', '_' and '.'", id, configPath)
		}
	}
	return nil
}

// InitProject gives a new repo a random project id, reporting whether it wrote
// one. It only acts when there is nothing to break: an existing id is kept, and
// a repo that already has a sealed blob or a customized backend is left alone —
// binding an existing blob is a deliberate step (set `project`, then seal), since
// every blob sealed before it stops verifying.
func InitProject() (bool, error) {
	cfg, err := readConfig(configPath)
	if err != nil {
		return false, err
	}
	if len(cfg) > 0 {
		return false, nil
	}
	if _, err := os.Lstat(DefaultBlobPath); err == nil {
		return false, nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return false, err
	}
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	var b strings.Builder
	b.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("# Binds sealed blobs to this repo, so one sealed for another project is rejected.\n")
	b.WriteString("project = " + hex.EncodeToString(raw[:]) + "\n")
	return true, WriteFileAtomic(configPath, []byte(b.String()), 0o644)
}
