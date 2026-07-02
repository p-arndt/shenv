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

// Init registers the user as a recipient of this repo and sets up .gitignore so
// plaintext never leaks. The global keypair is created first if it doesn't exist
// yet (same as `shenv keygen`); an existing one is reused — init is safe to run
// in every repo you join.
func Init(args []string) error {
	name := "me"
	if len(args) > 0 {
		name = args[0]
	}

	pub, err := identity.PublicKey()
	if err != nil {
		if pub, err = createIdentity(); err != nil {
			return err
		}
	} else {
		fmt.Printf("Using your existing identity. Your public key:\n  %s\n\n", pub)
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
	fmt.Printf("Remember to commit %s so your teammates' pushes keep you included.\n", recipients.Path)
	return nil
}

// Keygen creates the global keypair without touching any repo — for users who
// just want their key (e.g. to send their public key to a teammate) before they
// are inside a project. `init` does this implicitly when needed.
func Keygen(args []string) error {
	if pub, err := identity.PublicKey(); err == nil {
		path, _ := identity.Path()
		fmt.Printf("You already have an identity at %s. Your public key:\n  %s\n", path, pub)
		return nil
	}
	if _, err := createIdentity(); err != nil {
		return err
	}
	fmt.Println("\nNext: run `shenv init [name]` inside a repo to register yourself there.")
	return nil
}

// createIdentity prompts for a passphrase and generates the global keypair,
// returning the new public key. Shared by init and keygen.
func createIdentity() (string, error) {
	passphrase, err := readNewPassphrase()
	if err != nil {
		return "", err
	}
	id, err := identity.Create(passphrase)
	if err != nil {
		return "", err
	}
	pub := id.Recipient().String()
	fmt.Printf("Created identity. Your public key:\n  %s\n\n", pub)
	if passphrase != "" {
		fmt.Println("Your private key is encrypted at rest with your passphrase.")
		offerToRemember(pub, passphrase)
	}
	return pub, nil
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

// RemoveMember takes a dev off the recipient list — the sanctioned way to revoke
// access, as opposed to hand-editing the file (which push would flag as an
// accidental drop).
func RemoveMember(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: shenv remove-member <name>")
	}
	name := args[0]
	if err := recipients.Remove(name); err != nil {
		return err
	}
	fmt.Printf("Removed %q. Run `shenv push` to re-encrypt without them, and commit %s.\n", name, recipients.Path)
	fmt.Println("Note: they could decrypt everything pushed so far — rotate any secrets they shouldn't keep.")
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

	selfKey, err := identity.PublicKey()
	if err != nil {
		selfKey = "" // no identity yet: every recipient counts as foreign
	}

	// Encrypting for a list that doesn't include yourself locks you out of your
	// own secrets — almost always a setup mistake (e.g. `init` was run elsewhere).
	if proceed := confirmSelfIncluded(members, selfKey); !proceed {
		fmt.Println("Aborted — add yourself first, e.g. `shenv init`.")
		return nil
	}

	store, err := loadBackend()
	if err != nil {
		return err
	}

	// The current blob carries the list it was encrypted for (see the manifest in
	// the recipients package). Refuse to silently push a new blob that would lock
	// out someone who can decrypt today — the drift that causes this (a recipients
	// file that was never committed, a bad merge) is invisible in the file itself.
	if proceed, err := confirmNoLockout(store, members); err != nil {
		return err
	} else if !proceed {
		fmt.Println("Aborted — nobody was locked out.")
		return nil
	}

	// The recipients file is committed and arrives over an untrusted channel, so a
	// silently-injected key would exfiltrate every secret on the next push. Show
	// the current members and require confirmation if the set changed since last time.
	if proceed, err := confirmRecipients(members, selfKey); err != nil {
		return err
	} else if !proceed {
		fmt.Println("Aborted — recipients not confirmed.")
		return nil
	}

	blob, err := crypto.EncryptBytes(recipients.EmbedManifest(plaintext, members), keys)
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
