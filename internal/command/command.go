// Package command implements the shenv subcommands, wiring together the identity,
// recipients, and crypto packages. main() stays a thin dispatcher over these.
package command

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/identity"
	"shenv/internal/recipients"
)

// defaultEnvFile is the local plaintext file — never committed.
const defaultEnvFile = ".env"

// Init generates the user's global keypair (if missing), registers them as the
// first recipient of this repo, and sets up .gitignore so plaintext never leaks.
func Init(args []string) error {
	name := "me"
	if len(args) > 0 {
		name = args[0]
	}

	passphrase, err := readNewPassphrase()
	if err != nil {
		return err
	}

	id, err := identity.Create(passphrase)
	if err != nil {
		return err
	}
	pub := id.Recipient().String()
	fmt.Printf("Created identity. Your public key:\n  %s\n\n", pub)
	if passphrase != "" {
		fmt.Println("Your private key is encrypted at rest with your passphrase.")
		offerToRemember(pub, passphrase)
	}

	if err := recipients.Add(name, pub); err != nil {
		return err
	}
	fmt.Printf("Registered you as %q in %s\n", name, recipients.Path)

	if err := ensureGitignore(); err != nil {
		return err
	}
	fmt.Println("Updated .gitignore (.env stays local, env.age is shared).")
	fmt.Println("\nNext: put your secrets in .env, then run `shenv push`.")
	return nil
}

// Whoami prints the user's public key — the thing they share to get added elsewhere.
// It never needs the passphrase, even for an encrypted key.
func Whoami(args []string) error {
	pub, err := identity.PublicKey()
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

// AddMember records another dev's public key so they can decrypt after the next push.
func AddMember(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: shenv add-member <name> <age1-public-key>")
	}
	name, key := args[0], args[1]
	if err := recipients.Add(name, key); err != nil {
		return err
	}
	fmt.Printf("Added %q. Run `shenv push` to re-encrypt so they can pull.\n", name)
	return nil
}

// Push encrypts .env for every recipient into env.age.
func Push(args []string) error {
	in := defaultEnvFile
	if len(args) > 0 {
		in = args[0]
	}
	fi, err := os.Lstat(in)
	if err != nil {
		return fmt.Errorf("no %s to push — create it first", in)
	}
	// A repo could ship .env as a committed symlink to a sensitive file (the
	// private key, ~/.aws/credentials, …); pushing would then encrypt and share
	// that file's contents with every recipient.
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to read secrets through it", in)
	}

	plaintext, err := os.ReadFile(in)
	if err != nil {
		return err
	}

	members, err := recipients.Load()
	if err != nil {
		return err
	}
	keys, err := recipients.Keys(members)
	if err != nil {
		return err
	}

	// The recipients file is committed and arrives over an untrusted channel, so a
	// silently-injected key would exfiltrate every secret on the next push. Show
	// the current members and require confirmation if the set changed since last time.
	selfKey, err := identity.PublicKey()
	if err != nil {
		selfKey = "" // no identity yet: every recipient counts as foreign
	}
	if proceed, err := confirmRecipients(members, selfKey); err != nil {
		return err
	} else if !proceed {
		fmt.Println("Aborted — recipients not confirmed.")
		return nil
	}

	blob, err := crypto.EncryptBytes(plaintext, keys)
	if err != nil {
		return err
	}

	store, err := loadBackend()
	if err != nil {
		return err
	}
	if err := store.Put(blob); err != nil {
		return err
	}
	if err := rememberRecipients(members); err != nil {
		return err
	}
	fmt.Printf("Encrypted %s → %s for %d member(s).\n", in, store, len(members))
	return nil
}

// Pull decrypts env.age back into .env, guarding against clobbering local edits.
func Pull(args []string) error {
	out := defaultEnvFile
	force := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--force" || a == "-f":
			force = true
		case a == "--out" && i+1 < len(args):
			i++
			out = args[i]
		case strings.HasPrefix(a, "--out="):
			out = strings.TrimPrefix(a, "--out=")
		default:
			out = a // positional target, e.g. `shenv pull .env.local`
		}
	}

	plaintext, err := decryptEnv()
	if err != nil {
		return err
	}

	// Refuse to write the plaintext through a pre-planted symlink, which could
	// redirect secrets to an attacker-chosen path.
	if fi, err := os.Lstat(out); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to write decrypted secrets through it", out)
	}

	if !force {
		if existing, err := os.ReadFile(out); err == nil && !bytes.Equal(existing, plaintext) {
			fmt.Printf("Local %s differs from the decrypted version. Overwrite? [y/N] ", out)
			if !confirm() {
				fmt.Println("Aborted. (Use --force to skip this check.)")
				return nil
			}
		}
	}

	if err := os.WriteFile(out, plaintext, 0o600); err != nil {
		return err
	}
	// WriteFile's mode only applies on create; if the file already existed with
	// looser permissions, tighten them now (best-effort — a no-op on Windows,
	// where the home/repo ACLs govern access).
	_ = os.Chmod(out, 0o600)
	fmt.Printf("Wrote %s (%d bytes). Keep it local — it's gitignored.\n", out, len(plaintext))
	return nil
}

// ensureGitignore makes sure .env is ignored and env.age is not.
func ensureGitignore() error {
	const path = ".gitignore"
	existing, _ := os.ReadFile(path)
	lines := map[string]bool{}
	for line := range strings.SplitSeq(string(existing), "\n") {
		lines[strings.TrimSpace(line)] = true
	}

	var add []string
	if !lines[defaultEnvFile] {
		add = append(add, defaultEnvFile)
	}
	// Explicitly un-ignore the blob in case a broad rule hides it.
	if !lines["!"+backend.DefaultBlobPath] {
		add = append(add, "!"+backend.DefaultBlobPath)
	}
	if len(add) == 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	block := "\n# shenv\n" + strings.Join(add, "\n") + "\n"
	_, err = f.WriteString(block)
	return err
}

// confirm reads a y/n answer from stdin.
func confirm() bool {
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
