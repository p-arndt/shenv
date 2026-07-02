package command

import (
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

// decryptEnv fetches the blob from the configured backend and decrypts it into
// memory, unlocking the key via the keychain or a prompt as needed. The embedded
// recipient manifest is stripped — callers get the bare .env content. Shared by
// pull (writes it to disk) and run (injects it).
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
	_, plaintext := recipients.ExtractManifest(payload)
	return plaintext, nil
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
