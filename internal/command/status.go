package command

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/identity"
	"shenv/internal/keystore"
	"shenv/internal/recipients"
)

// Status prints a read-only overview of this repo's shenv state: your identity,
// whether you are a registered member, the team, the storage backend, and — when
// your key can be unlocked without a prompt — whether the local .env matches the
// sealed env.shenv. It is deliberately side-effect free: it never writes, never
// prompts for a passphrase, and never runs an exec backend, so it is always safe
// to run to answer "where do I stand in this repo?".
func Status(args []string) error {
	// Identity. Everything downstream keys off your public key, but a missing
	// identity is a normal state (a fresh machine), not an error.
	pub, err := identity.PublicKey()
	if err != nil {
		statusRow("identity", "none — run `shenv keygen`, or `shenv init` inside a repo")
	} else {
		statusRow("identity", pub)
		statusRow("", keyProtection(pub))
	}

	// Membership + team. recipients.Load validates names/keys, so a malformed
	// committed file surfaces here as a real error rather than a misleading row.
	members, err := recipients.Load()
	if err != nil {
		return err
	}
	statusRow("member", membership(members, pub))
	statusRow("team", team(members))

	// Backend + sealed blob. We describe the backend from config without running
	// it, and only a file backend's blob is inspected — querying an exec backend
	// would run its shell `get`, which status must never do unprompted.
	store, err := backend.Load()
	if err != nil {
		return err
	}
	describeBackend(store, pub)

	statusRow(".env", localEnv())
	return nil
}

// keyProtection describes how the private key is guarded at rest.
func keyProtection(pub string) string {
	encrypted, err := identity.IsEncrypted()
	if err != nil {
		return "protected by file permissions"
	}
	if !encrypted {
		return "plaintext key, protected by file permissions"
	}
	if _, cached := keystore.Get(pub); cached {
		return "passphrase-protected; passphrase cached in this machine's keychain"
	}
	return "passphrase-protected"
}

// membership reports whether your key is in recipients.shenv — the thing that
// decides whether you can decrypt and whether your seals verify.
func membership(members []recipients.Member, pub string) string {
	if pub == "" {
		return "unknown — you have no identity yet"
	}
	if self := memberByKey(members, pub); self != nil {
		return fmt.Sprintf("registered here as %q", self.Name)
	}
	return "your key is NOT in " + recipients.Path + " — run `shenv init` to register"
}

// team summarizes the recipient list. Names came through recipients.Load, which
// rejects control/invisible runes, so they are safe to print as-is.
func team(members []recipients.Member) string {
	if len(members) == 0 {
		return "no members yet — run `shenv init` to add yourself"
	}
	names := make([]string, len(members))
	for i, m := range members {
		names[i] = m.Name
	}
	return fmt.Sprintf("%d member(s) — %s", len(members), strings.Join(names, ", "))
}

// describeBackend prints the backend and the state of the sealed blob. For an
// exec backend it stops at the description; for a file backend it reports whether
// env.shenv exists and, when the key unlocks without prompting, how it compares
// to the local .env.
func describeBackend(store backend.Backend, pub string) {
	switch b := store.(type) {
	case backend.FileBackend:
		statusRow("backend", "file → "+b.Path)
		if _, err := os.Stat(b.Path); err != nil {
			statusRow("env.shenv", "not sealed yet — run `shenv seal`")
			return
		}
		statusRow("env.shenv", sealedState(b, pub))
	case backend.ExecBackend:
		statusRow("backend", "exec (shell-command storage; not queried by status)")
		statusRow("env.shenv", "run `shenv open` to fetch and decrypt it")
	default:
		statusRow("backend", store.String())
	}
}

// sealedState describes the sealed blob relative to the local .env. It only
// decrypts when the key can be unlocked without a prompt (a plaintext key, or a
// passphrase already in the keychain); otherwise it degrades to a hint, keeping
// status prompt-free. Read-only throughout.
func sealedState(store backend.Backend, pub string) string {
	if pub == "" {
		return "present — no identity here to decrypt it (`shenv init`)"
	}
	if !canUnlockSilently(pub) {
		return "present — unlock your key to compare it with .env (status never prompts)"
	}

	blob, err := store.Get()
	if err != nil {
		return "unreadable: " + oneLine(err)
	}
	// unlocker prompts on a keychain miss, but canUnlockSilently guarantees a hit
	// (or a plaintext key that never asks), so no prompt can fire here.
	id, err := identity.Load(unlocker(pub))
	if err != nil {
		return "present — could not unlock your key (is the cached passphrase current?)"
	}
	payload, err := crypto.DecryptBytes(blob, id)
	if err != nil {
		return "present, but your key can't decrypt it — ask a member to add you and re-seal"
	}
	signer, body, err := verifiedBody(payload)
	if err != nil {
		return "present, but unverified: " + oneLine(err)
	}
	_, sealed := recipients.ExtractManifest(body)

	// The signer comes from a decrypted manifest — signed, but authored by a
	// possibly-hostile member — so sanitize it before it reaches the terminal,
	// exactly as the seal prompts do.
	signer = sanitizeTerm(signer)
	local, err := os.ReadFile(defaultEnvFile)
	switch {
	case err != nil:
		return fmt.Sprintf("sealed by %s · no local .env — run `shenv open` to create it", signer)
	case bytes.Equal(local, sealed):
		return fmt.Sprintf("sealed by %s · in sync with .env", signer)
	default:
		return fmt.Sprintf("sealed by %s · .env differs — run `shenv seal` to update the sealed copy", signer)
	}
}

// canUnlockSilently reports whether identity.Load can succeed without asking the
// user anything: a plaintext key needs no passphrase, and an encrypted key whose
// passphrase is cached in the keychain unlocks from there.
func canUnlockSilently(pub string) bool {
	encrypted, err := identity.IsEncrypted()
	if err != nil {
		return false
	}
	if !encrypted {
		return true
	}
	_, cached := keystore.Get(pub)
	return cached
}

// localEnv reports on the plaintext .env: present or not, and — critically — a
// warning if git tracks it, since .gitignore can't keep an already-tracked file
// out of commits and the whole point of shenv is that plaintext never lands in
// the repo.
func localEnv() string {
	if _, err := os.Stat(defaultEnvFile); err != nil {
		return "none locally"
	}
	if isGitTracked(defaultEnvFile) {
		return "present — WARNING: tracked by git; plaintext could be committed (`git rm --cached " + defaultEnvFile + "`)"
	}
	return "present (local only)"
}

// statusRow prints one aligned "label : value" line. An empty label prints a
// continuation line indented under the previous one.
func statusRow(label, value string) {
	if label == "" {
		fmt.Printf("  %-10s   %s\n", "", value)
		return
	}
	fmt.Printf("  %-10s : %s\n", label, value)
}

// oneLine collapses a multi-line error into a single row-friendly string.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
