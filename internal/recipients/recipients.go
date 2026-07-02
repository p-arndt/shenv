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
)

// Path is the per-repo recipients file, relative to the repo root.
const Path = "recipients.shenv"

// Member is one entry: a friendly name and an age public key.
type Member struct {
	Name string
	Key  string // age1... public key
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
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed recipients line: %q (expected `name age1...`)", line)
		}
		members = append(members, Member{Name: fields[0], Key: fields[1]})
	}
	return members, nil
}

// Save writes the team list back, sorted by name for stable diffs.
func Save(members []Member) error {
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	var b strings.Builder
	b.WriteString("# shenv recipients — public keys of team members who can decrypt.\n")
	b.WriteString("# Safe to commit. Managed by `shenv add-member` / `shenv init`.\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%s %s\n", m.Name, m.Key)
	}

	return os.WriteFile(Path, []byte(b.String()), 0o644)
}

// Add inserts or updates a member by name and persists the list.
func Add(name, key string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(key); err != nil {
		return fmt.Errorf("invalid public key %q: %w", key, err)
	}
	members, err := Load()
	if err != nil {
		return err
	}
	for i, m := range members {
		if m.Name == name {
			members[i].Key = key // update existing
			return Save(members)
		}
	}
	return Save(append(members, Member{Name: name, Key: key}))
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
// file: whitespace or control characters (a newline could smuggle in an entire
// extra recipient line) and a leading '#' (would comment the entry out).
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("member name must not be empty")
	}
	if strings.HasPrefix(name, "#") {
		return fmt.Errorf("member name %q must not start with '#'", name)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("member name %q must not contain whitespace or control characters", name)
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
