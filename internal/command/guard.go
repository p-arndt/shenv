package command

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shenv/internal/backend"
	"shenv/internal/recipients"
)

// loadBackend resolves the configured backend and, for an exec backend, ensures
// its shell commands have been approved for this repo before they can run. See
// backend.EnsureTrusted for why this gate exists.
func loadBackend() (backend.Backend, error) {
	store, err := backend.Load()
	if err != nil {
		return nil, err
	}
	if err := backend.EnsureTrusted(store, confirmExec); err != nil {
		return nil, err
	}
	return store, nil
}

// confirmExec shows the exec backend's commands and asks the user to approve them.
func confirmExec(getCmd, putCmd string) (bool, error) {
	fmt.Println("This repo's .shenv/config uses an EXEC backend, which runs shell commands:")
	if getCmd != "" {
		fmt.Printf("    get: %s\n", getCmd)
	}
	if putCmd != "" {
		fmt.Printf("    put: %s\n", putCmd)
	}
	fmt.Println("These come from the repo and could have been added by anyone with commit access.")
	fmt.Print("Run them? [y/N] ")
	return confirm(), nil
}

// stateDir is the per-user shenv directory that holds local trust/bookkeeping
// state. It lives outside any repo so a hostile repo can't tamper with it.
func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "state"), nil
}

// pushedRecipientsPath is where the recipient set from this repo's last push is
// recorded, keyed by the absolute recipients-file path so repos don't collide.
func pushedRecipientsPath() (string, error) {
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(recipients.Path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".recipients"), nil
}

// confirmRecipients lists the members the secrets are about to be encrypted for and,
// if that set changed since this machine's last push, shows the additions/removals
// and asks the user to confirm. This turns a silent recipient injection into a
// visible, blocking prompt. selfKey is the user's own public key (may be empty);
// on the very first push from a machine, any recipient beyond it must also be
// confirmed — the list comes from the repo, so a fresh clone could otherwise
// exfiltrate to a planted key with no prompt at all. Returns true to proceed.
func confirmRecipients(members []recipients.Member, selfKey string) (bool, error) {
	fmt.Printf("Encrypting for %d recipient(s):\n", len(members))
	for _, m := range members {
		fmt.Printf("    %s  %s\n", m.Name, m.Key)
	}

	prev, havePrev, err := loadPushedRecipients()
	if err != nil {
		return false, err
	}
	if !havePrev {
		for _, m := range members {
			if m.Key != selfKey {
				fmt.Println("\nFirst push from this machine — the recipient list above comes from the repo.")
				fmt.Print("Anyone listed will be able to decrypt these secrets. Continue? [y/N] ")
				return confirm(), nil
			}
		}
		return true, nil // first push, but only encrypting for yourself
	}

	cur := recipientSet(members)
	var added, removed []string
	for k := range cur {
		if !prev[k] {
			added = append(added, k)
		}
	}
	for k := range prev {
		if !cur[k] {
			removed = append(removed, k)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return true, nil
	}

	sort.Strings(added)
	sort.Strings(removed)
	fmt.Println("\nThe recipient list CHANGED since your last push:")
	for _, a := range added {
		fmt.Printf("    + %s\n", strings.ReplaceAll(a, "\t", "  "))
	}
	for _, r := range removed {
		fmt.Printf("    - %s\n", strings.ReplaceAll(r, "\t", "  "))
	}
	fmt.Print("Anyone added here will be able to decrypt these secrets. Continue? [y/N] ")
	return confirm(), nil
}

// rememberRecipients records the recipient set after a successful push so the next
// push can detect changes.
func rememberRecipients(members []recipients.Member) error {
	path, err := pushedRecipientsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	set := recipientSet(members)
	lines := make([]string, 0, len(set))
	for k := range set {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// loadPushedRecipients reads the recipient set from the last push. The second
// result is false when no previous push has been recorded on this machine.
func loadPushedRecipients() (map[string]bool, bool, error) {
	path, err := pushedRecipientsPath()
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	set := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set, true, nil
}

// recipientSet builds a comparable set of "name\tkey" entries, so a swapped key or
// a renamed member both register as a change.
func recipientSet(members []recipients.Member) map[string]bool {
	set := make(map[string]bool, len(members))
	for _, m := range members {
		set[m.Name+"\t"+m.Key] = true
	}
	return set
}
