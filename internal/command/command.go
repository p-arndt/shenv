// Package command implements the shenv subcommands, wiring together the identity,
// recipients, and crypto packages. main() stays a thin dispatcher over these.
package command

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	var signPub string
	if err != nil {
		if pub, signPub, err = createIdentity(); err != nil {
			return err
		}
	} else {
		fmt.Printf("Using your existing identity. Your public key:\n  %s\n\n", pub)
		if signPub, err = identity.VerifyKey(unlocker(pub)); err != nil {
			return err
		}
	}

	if err := recipients.Add(name, pub, signPub); err != nil {
		return err
	}
	fmt.Printf("Registered you as %q in %s\n", name, recipients.Path)

	if err := ensureGitignore(); err != nil {
		return err
	}
	fmt.Println("Updated .gitignore (.env stays local, env.shenv is shared).")
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
	if _, _, err := createIdentity(); err != nil {
		return err
	}
	fmt.Println("\nNext: run `shenv init [name]` inside a repo to register yourself there.")
	return nil
}

// createIdentity prompts for a passphrase and generates the global keypair,
// returning the new public key and public signing key. Shared by init and keygen.
func createIdentity() (string, string, error) {
	passphrase, err := readNewPassphrase()
	if err != nil {
		return "", "", err
	}
	id, err := identity.Create(passphrase)
	if err != nil {
		return "", "", err
	}
	signKey, err := crypto.DeriveSigningKey(id)
	if err != nil {
		return "", "", err
	}
	pub := id.Recipient().String()
	fmt.Printf("Created identity. Your public key:\n  %s\n\n", pub)
	if passphrase != "" {
		fmt.Println("Your private key is encrypted at rest with your passphrase.")
		offerToRemember(pub, passphrase)
	}
	return pub, crypto.VerifyKeyString(signKey), nil
}

// Whoami prints the user's public keys — what they share to get added elsewhere.
// It never needs the passphrase for an encrypted key, except once for key files
// from before signing existed (see identity.VerifyKey).
func Whoami(args []string) error {
	pub, err := identity.PublicKey()
	if err != nil {
		return err
	}
	signPub, err := identity.VerifyKey(unlocker(pub))
	if err != nil {
		return err
	}
	fmt.Printf("public key : %s\nsigning key: %s\n", pub, signPub)
	fmt.Printf("\nA teammate grants you access with:\n  shenv add-member <your-name> %s %s\n", pub, signPub)
	return nil
}

// AddMember records another dev's public keys so they can decrypt — and their
// pushes can be verified — after the next push.
func AddMember(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: shenv add-member <name> <age1-public-key> <signing-key>\n(the new member gets both keys from `shenv whoami`)")
	}
	name, key, signKey := args[0], args[1], args[2]
	if err := recipients.Add(name, key, signKey); err != nil {
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

// Push encrypts .env for every recipient into env.shenv.
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

	// Push signs the payload, and the signature is only verifiable if the pusher
	// is a member — so both an identity and a registration here are required.
	// This also closes the classic trap of encrypting for a list without your own
	// key and locking yourself out (e.g. `init` was run in another directory).
	selfKey, err := identity.PublicKey()
	if err != nil {
		return fmt.Errorf("push signs env.shenv with your key, but you have no identity yet — run `shenv init [name]` first")
	}
	self := memberByKey(members, selfKey)
	if self == nil {
		return fmt.Errorf("your key is not in %s — after this push you could not decrypt env.shenv, and nobody could verify your signature; register yourself first with `shenv init [name]`", recipients.Path)
	}

	id, err := identity.Load(unlocker(selfKey))
	if err != nil {
		return err
	}
	signKey, err := crypto.DeriveSigningKey(id)
	if err != nil {
		return err
	}
	if verify := crypto.VerifyKeyString(signKey); self.SignKey != verify {
		return fmt.Errorf("your signing key doesn't match your entry in %s — run `shenv init %s` to update it, then push again", recipients.Path, self.Name)
	}

	store, err := loadBackend()
	if err != nil {
		return err
	}

	// The current blob carries the list it was encrypted for (see the manifest in
	// the recipients package). Refuse to silently push a new blob that would lock
	// out someone who can decrypt today — the drift that causes this (a recipients
	// file that was never committed, a bad merge) is invisible in the file itself.
	if proceed, err := confirmNoLockout(store, members, id); err != nil {
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

	blob, err := crypto.EncryptBytes(recipients.SealPayload(plaintext, members, self.Name, signKey), keys)
	if err != nil {
		return err
	}

	if err := store.Put(blob); err != nil {
		return err
	}
	if err := rememberRecipients(members); err != nil {
		return err
	}
	fmt.Printf("Encrypted %s → %s for %d member(s), signed as %q.\n", in, store, len(members), self.Name)
	return nil
}

// memberByKey finds the member entry with the given age public key.
func memberByKey(members []recipients.Member, key string) *recipients.Member {
	for i := range members {
		if members[i].Key == key {
			return &members[i]
		}
	}
	return nil
}

// Pull decrypts env.shenv back into .env, guarding against clobbering local edits.
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

	// The tool's core promise is that plaintext never lands in the repo — that
	// must hold for `pull --out .env.production` just as for the default .env.
	if err := ensureIgnored(out); err != nil {
		return err
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

// ensureGitignore makes sure .env is ignored and env.shenv is not.
// The "!" entry explicitly un-ignores the blob in case a broad rule hides it.
func ensureGitignore() error {
	_, err := appendGitignore(defaultEnvFile, "!"+backend.DefaultBlobPath)
	return err
}

// ensureIgnored guards a pull target: decrypted plaintext must never be
// committable, so any repo-local output path is added to .gitignore before the
// secrets are written. Paths outside the repo (absolute, `..`-escaping) can't
// be committed from here and are left alone. Failing to update .gitignore is
// fatal — better no plaintext than committable plaintext.
func ensureIgnored(path string) error {
	if !filepath.IsLocal(path) {
		return nil
	}
	added, err := appendGitignore(filepath.ToSlash(path))
	if err != nil {
		return fmt.Errorf("could not add %s to .gitignore (refusing to write plaintext that git could commit): %w", path, err)
	}
	if added {
		fmt.Printf("Added %s to .gitignore so the decrypted file can't be committed.\n", path)
	}
	return nil
}

// appendGitignore appends the entries not already present (as exact lines) in
// .gitignore under a "# shenv" block, reporting whether anything was added.
func appendGitignore(entries ...string) (bool, error) {
	const path = ".gitignore"
	existing, _ := os.ReadFile(path)
	lines := map[string]bool{}
	for line := range strings.SplitSeq(string(existing), "\n") {
		lines[strings.TrimSpace(line)] = true
	}

	var add []string
	for _, e := range entries {
		if !lines[e] {
			add = append(add, e)
		}
	}
	if len(add) == 0 {
		return false, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	block := "\n# shenv\n" + strings.Join(add, "\n") + "\n"
	if _, err := f.WriteString(block); err != nil {
		return false, err
	}
	return true, nil
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
