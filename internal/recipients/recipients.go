// Package recipients manages the per-repo list of team members allowed to decrypt.
// The file holds only public keys, so it is safe to commit.
package recipients

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"filippo.io/age"

	"shenv/internal/crypto"
)

// Path is the per-repo recipients file, relative to the repo root.
const Path = "recipients.shenv"

// Member is one entry: a friendly name, an age public key for encryption, and
// an Ed25519 verify key so pulls can check who signed the blob.
type Member struct {
	Name    string
	Key     string // age1... public key
	SignKey string // base64 Ed25519 verify key
}

// Load reads the team list. A missing file is treated as empty.
func Load() ([]Member, error) {
	data, err := os.ReadFile(Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var members []Member
	seen := map[string]bool{}
	seenKey := map[string]string{}  // age key → member name
	seenSign := map[string]string{} // sign key → member name
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed recipients line: %q (expected `name age1... signing-key` — `shenv whoami` prints both keys)", line)
		}
		// The file arrives over an untrusted channel (a clone, a merge), so the
		// name rules enforced on `add-member` must hold on load too: a control
		// character in a name could smuggle terminal escapes into prompts.
		if err := validateName(fields[0]); err != nil {
			return nil, fmt.Errorf("%s: %w", Path, err)
		}
		// Validate both key fields here, not just where they happen to be parsed
		// later: push's recipient prompt echoes entries from this file, and a
		// "key" carrying terminal escapes could redraw the very prompt meant to
		// expose a planted recipient. Valid bech32/base64 is control-char-free.
		if _, err := age.ParseX25519Recipient(fields[1]); err != nil {
			return nil, fmt.Errorf("%s: member %q has an invalid public key: %w", Path, fields[0], err)
		}
		if _, err := crypto.ParseVerifyKey(fields[2]); err != nil {
			return nil, fmt.Errorf("%s: member %q: %w", Path, fields[0], err)
		}
		// Signer lookup during pull is by name and takes the first match — a
		// duplicate would let a shadow entry hijack an existing member's identity.
		if seen[fields[0]] {
			return nil, fmt.Errorf("duplicate member %q in %s — names must be unique so signatures can't be verified against the wrong key", fields[0], Path)
		}
		seen[fields[0]] = true
		// Keys must be one-to-one with names as well: signature attribution maps
		// name → sign key, and push identifies "you" by age key. An entry reusing
		// another member's keys would make "signed by <name>" ambiguous.
		if other, dup := seenKey[fields[1]]; dup {
			return nil, fmt.Errorf("members %q and %q in %s share the same public key — each member needs their own key so pushes attribute to the right person", other, fields[0], Path)
		}
		if other, dup := seenSign[fields[2]]; dup {
			return nil, fmt.Errorf("members %q and %q in %s share the same signing key — each member needs their own key so signatures attribute to the right person", other, fields[0], Path)
		}
		seenKey[fields[1]], seenSign[fields[2]] = fields[0], fields[0]
		members = append(members, Member{Name: fields[0], Key: fields[1], SignKey: fields[2]})
	}
	return members, nil
}

// Save writes the team list back, sorted by name for stable diffs.
func Save(members []Member) error {
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	var b strings.Builder
	b.WriteString("# shenv recipients — per member: name, age public key (encryption),\n")
	b.WriteString("# Ed25519 verify key (signing). Safe to commit. Managed by `shenv add-member` / `shenv init`.\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%s %s %s\n", m.Name, m.Key, m.SignKey)
	}

	return os.WriteFile(Path, []byte(b.String()), 0o644)
}

// Add inserts or updates a member and persists the list. Matching an existing
// entry by name refreshes its keys; matching by key renames it (e.g. `shenv
// init new-name` when already registered) — one person stays one entry, since
// Load rejects duplicate keys to keep signature attribution unambiguous.
func Add(name, key, signKey string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(key); err != nil {
		return fmt.Errorf("invalid public key %q: %w", key, err)
	}
	if _, err := crypto.ParseVerifyKey(signKey); err != nil {
		return err
	}
	members, err := Load()
	if err != nil {
		return err
	}

	byName, byKey := -1, -1
	for i, m := range members {
		if m.Name == name {
			byName = i
		}
		if m.Key == key {
			byKey = i
		}
	}
	switch {
	case byKey >= 0 && byName >= 0 && byKey != byName:
		return fmt.Errorf("key already belongs to %q — `shenv remove-member` one of %q/%q first", members[byKey].Name, members[byKey].Name, name)
	case byKey >= 0:
		members[byKey] = Member{Name: name, Key: key, SignKey: signKey}
	case byName >= 0:
		members[byName].Key, members[byName].SignKey = key, signKey
	default:
		members = append(members, Member{Name: name, Key: key, SignKey: signKey})
	}

	// Never persist a list the next Load would reject (a sign key colliding with
	// a different member's would brick the file until hand-edited).
	for _, m := range members {
		if m.Name != name && m.SignKey == signKey {
			return fmt.Errorf("signing key already belongs to %q — each member needs their own keys", m.Name)
		}
	}
	return Save(members)
}

// Remove deletes a member by name and persists the list. Removing someone only
// takes effect once `push` re-encrypts without them.
func Remove(name string) error {
	members, err := Load()
	if err != nil {
		return err
	}
	for i, m := range members {
		if m.Name == name {
			return Save(append(members[:i], members[i+1:]...))
		}
	}
	return fmt.Errorf("no member named %q in %s", name, Path)
}

// validateName rejects names that would corrupt the line-oriented recipients
// file or deceive whoever reads it: whitespace (a newline could smuggle in an
// entire extra recipient line), a leading '#' (would comment the entry out),
// and any non-graphic rune. The non-graphic test rejects both control
// characters (category Cc — ANSI escapes that could rewrite the prompts that
// display the name) and format characters (category Cf — zero-width and bidi
// runes that render invisibly). This file arrives over an untrusted channel (a
// clone, a merge), so a Cf-spoofed name could forge a visual duplicate of an
// existing member — and duplicate-name detection is by exact string, so the
// forgery would slip past it and let a shadow entry hijack that member's
// signature attribution.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("member name must not be empty")
	}
	if strings.HasPrefix(name, "#") {
		return fmt.Errorf("member name %q must not start with '#'", name)
	}
	for _, r := range name {
		// IsSpace is checked separately because a plain space (U+0020) is a
		// graphic rune, yet still splits the line into the wrong number of fields.
		if unicode.IsSpace(r) || !unicode.IsGraphic(r) {
			return fmt.Errorf("member name %q must not contain whitespace, control, or invisible characters", name)
		}
	}
	return nil
}

// Keys parses every member into an age.Recipient for encryption.
func Keys(members []Member) ([]age.Recipient, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("no recipients — add at least one with `shenv add-member`")
	}
	recipients := make([]age.Recipient, 0, len(members))
	for _, m := range members {
		r, err := age.ParseX25519Recipient(m.Key)
		if err != nil {
			return nil, fmt.Errorf("recipient %q has an invalid key: %w", m.Name, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}
