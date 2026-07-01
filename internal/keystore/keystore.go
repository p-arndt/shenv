// Package keystore is a thin, optional wrapper around the OS secret store
// (Windows Credential Manager, Linux Secret Service, macOS Keychain). It caches
// the passphrase that unlocks an encrypted key so pull need not ask every time.
//
// It is deliberately best-effort: on systems without a secret store (headless
// Linux, containers) Get simply reports a miss and callers fall back to a prompt.
package keystore

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// service namespaces our entries within the OS store.
const service = "shenv"

// Get returns the secret stored for account (the user's public key). The second
// result is false on a miss OR when no secret store is available — both mean
// "fall back to asking".
func Get(account string) (string, bool) {
	secret, err := keyring.Get(service, account)
	if err != nil {
		return "", false
	}
	return secret, true
}

// Set stores (or replaces) the secret for account. Errors are surfaced so the
// caller can tell the user the keychain was unreachable.
func Set(account, secret string) error {
	return keyring.Set(service, account, secret)
}

// Delete removes the secret for account. A missing entry is not an error.
func Delete(account string) error {
	if err := keyring.Delete(service, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}
