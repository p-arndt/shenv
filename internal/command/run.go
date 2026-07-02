package command

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"shenv/internal/crypto"
	"shenv/internal/dotenv"
	"shenv/internal/identity"
	"shenv/internal/recipients"
)

// decryptEnv fetches the blob from the configured backend, decrypts it into
// memory — unlocking the key via the keychain or a prompt as needed — and
// verifies the pusher's signature against recipients.shenv before trusting the
// contents. The signer line and recipient manifest are stripped — callers get
// the bare .env content. Shared by pull (writes it to disk) and run (injects it).
func decryptEnv() ([]byte, error) {
	store, err := loadBackend()
	if err != nil {
		return nil, err
	}
	blob, err := store.Get()
	if err != nil {
		return nil, err
	}
	payload, err := decryptBlob(blob)
	if err != nil {
		return nil, err
	}
	body, err := verifySigner(payload)
	if err != nil {
		return nil, err
	}
	_, plaintext := recipients.ExtractManifest(body)
	return plaintext, nil
}

// verifySigner checks the payload's signature against the signer's verify key
// in recipients.shenv — the local, committed trust anchor — and returns the
// signed body. Encryption alone can't prove who wrote the blob (the recipient
// keys are public, so anyone could encrypt one "for the team"); the signature
// ties it to a current member, so a replaced blob is rejected instead of
// silently feeding attacker-chosen values into the app.
func verifySigner(payload []byte) ([]byte, error) {
	signer, body, err := verifiedBody(payload)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "env.shenv verified — signed by %s.\n", signer)
	return body, nil
}

// verifiedBody performs the actual signature check, silently, so push's
// lockout guard can reuse it without printing pull's confirmation line.
func verifiedBody(payload []byte) (string, []byte, error) {
	signer, sig, body, ok := recipients.ExtractSignature(payload)
	if !ok {
		return "", nil, fmt.Errorf("env.shenv is not signed — it was pushed by an older shenv; ask a member to run `shenv push` with this version")
	}
	members, err := recipients.Load()
	if err != nil {
		return "", nil, err
	}
	var verifyKey ed25519.PublicKey
	for _, m := range members {
		if m.Name == signer {
			if verifyKey, err = crypto.ParseVerifyKey(m.SignKey); err != nil {
				return "", nil, fmt.Errorf("signer %q has an invalid signing key in %s: %w", signer, recipients.Path, err)
			}
			break
		}
	}
	if verifyKey == nil {
		return "", nil, fmt.Errorf("env.shenv was signed by %q, who is not in %s — if they were just removed, a remaining member must push a fresh env.shenv; otherwise the blob may have been replaced", signer, recipients.Path)
	}
	if !recipients.VerifySignature(body, sig, verifyKey) {
		return "", nil, fmt.Errorf("SIGNATURE VERIFICATION FAILED: env.shenv claims to be from %q but was not signed with their key — refusing to use it; the blob may have been tampered with or replaced", signer)
	}
	return signer, body, nil
}

// decryptBlob decrypts an already-fetched blob with the user's identity,
// returning the raw payload (manifest included).
func decryptBlob(blob []byte) ([]byte, error) {
	pub, err := identity.PublicKey()
	if err != nil {
		return nil, err
	}
	id, err := identity.Load(unlocker(pub))
	if err != nil {
		return nil, err
	}
	return crypto.DecryptBytes(blob, id)
}

// Run decrypts the secrets into memory and runs a command with them injected as
// environment variables — so no plaintext .env is ever written to disk.
func Run(args []string) error {
	cmdArgs, err := commandAfterSeparator(args)
	if err != nil {
		return err
	}

	plaintext, err := decryptEnv()
	if err != nil {
		return err
	}
	vars, err := dotenv.Parse(plaintext)
	if err != nil {
		return err
	}

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	child.Env = mergeEnv(os.Environ(), vars)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := child.Run(); err != nil {
		// Propagate the child's own exit code so scripts and CI see it.
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exit.ExitCode())
		}
		return fmt.Errorf("running %s: %w", cmdArgs[0], err)
	}
	return nil
}

// commandAfterSeparator returns the command and its arguments that follow the
// `--` separator, e.g. `shenv run -- npm start` → ["npm", "start"].
func commandAfterSeparator(args []string) ([]string, error) {
	for i, a := range args {
		if a == "--" {
			rest := args[i+1:]
			if len(rest) == 0 {
				return nil, fmt.Errorf("usage: shenv run -- <command> [args...]")
			}
			return rest, nil
		}
	}
	return nil, fmt.Errorf("usage: shenv run -- <command> [args...] (missing `--` separator)")
}

// mergeEnv layers the decrypted secrets on top of the inherited environment,
// with the secrets winning on conflicts.
func mergeEnv(base []string, overrides map[string]string) []string {
	env := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if _, overridden := overrides[name]; !overridden {
			env = append(env, kv)
		}
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}
