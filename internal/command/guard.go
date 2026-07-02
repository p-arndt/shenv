package command

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/crypto"
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
	fmt.Println("This repo's config.shenv uses an EXEC backend, which runs shell commands:")
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

// confirmNoLockout compares the members embedded in the current blob (who can
// decrypt today) against the set about to be encrypted for, and turns a silent
// lockout into a blocking prompt. Unlike confirmRecipients this needs no local
// state — the truth travels inside the blob — so it protects against drift that
// happened on any machine. A blob that exists but can't be decrypted with this
// identity gets its own warning: overwriting a blob you can't read likely locks
// out everyone who can. A blob whose signature can't be verified gets one too:
// its manifest can't be trusted, so the lockout comparison is skipped.
func confirmNoLockout(store backend.Backend, cur []recipients.Member, id age.Identity) (bool, error) {
	prevBlob, err := store.Get()
	if err != nil {
		return true, nil // no existing blob — first push, nothing to guard
	}

	payload, err := crypto.DecryptBytes(prevBlob, id)
	if err != nil {
		fmt.Println("An encrypted env.shenv already exists, but your key cannot decrypt it.")
		fmt.Println("Overwriting it would likely LOCK OUT everyone who can read it today.")
		fmt.Println("If you are new here, ask a member to run `shenv add-member` with your key instead.")
		fmt.Print("Overwrite anyway? [y/N] ")
		return confirm(), nil
	}

	// The manifest is only as trustworthy as its signature: the recipient keys
	// are public, so anyone who can write to the backend could plant a
	// decryptable blob with a fabricated member list and steer — or suppress —
	// the lockout warning. Verify before trusting it; on failure the guard
	// degrades to a blunt overwrite prompt. Legitimate paths land here too (a
	// blob from a pre-signing shenv, a last pusher who has since been removed),
	// hence the soft wording.
	_, body, err := verifiedBody(payload)
	if err != nil {
		fmt.Println("The existing env.shenv can't be verified, so who can decrypt it today is")
		fmt.Println("unknown and the lockout check is skipped:")
		fmt.Printf("    %v\n", err)
		fmt.Print("Overwrite it? [y/N] ")
		return confirm(), nil
	}
	prev, _ := recipients.ExtractManifest(body)
	if len(prev) == 0 {
		return true, nil // defensive: a signed blob always carries a manifest
	}

	curKeys := make(map[string]bool, len(cur))
	for _, m := range cur {
		curKeys[m.Key] = true
	}
	var dropped []recipients.Member
	for _, m := range prev {
		if !curKeys[m.Key] {
			dropped = append(dropped, m)
		}
	}
	if len(dropped) == 0 {
		return true, nil
	}

	fmt.Println("These members can decrypt the current env.shenv but are MISSING from", recipients.Path+":")
	for _, m := range dropped {
		fmt.Printf("    - %s  %s\n", sanitizeTerm(m.Name), sanitizeTerm(m.Key))
	}
	fmt.Println("Pushing now will LOCK THEM OUT. If that is unintended, restore them with")
	fmt.Println("`shenv add-member` (or `git checkout " + recipients.Path + "`) first.")
	fmt.Println("To revoke access on purpose, use `shenv remove-member` and confirm here.")
	fmt.Print("Lock them out? [y/N] ")
	return confirm(), nil
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

// sanitizeTerm strips control characters from strings that reach the terminal.
// The dropped-member list comes from a decrypted manifest — signed, but possibly
// by a malicious member — and a name or key carrying ANSI escape bytes could
// otherwise rewrite the very prompt that is supposed to expose the tampering.
func sanitizeTerm(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
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
		// Trim only the line ending: entries are tab-separated and a member
		// without a sign key ends in a tab that TrimSpace would eat.
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) != "" {
			set[line] = true
		}
	}
	return set, true, nil
}

// recipientSet builds a comparable set of "name\tkey\tsignkey" entries, so a
// swapped key, a renamed member, or a replaced signing key all register as a
// change. The signing key matters as much as the encryption key: pull trusts it
// to verify who pushed, so swapping it in recipients.shenv would let an attacker
// forge blobs "signed by" an existing member — that edit must hit this prompt.
func recipientSet(members []recipients.Member) map[string]bool {
	set := make(map[string]bool, len(members))
	for _, m := range members {
		set[m.Name+"\t"+m.Key+"\t"+m.SignKey] = true
	}
	return set
}
