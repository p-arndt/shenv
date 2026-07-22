package command

import (
	"fmt"

	"shenv/internal/identity"
	"shenv/internal/keystore"
	"shenv/internal/style"
)

// unlocker builds a PassphraseFunc that first tries the OS keychain and only
// prompts on a miss — the whole point of the DX-comfort feature.
func unlocker(pub string) identity.PassphraseFunc {
	return func() (string, error) {
		if pass, ok := keystore.Get(pub); ok {
			return pass, nil
		}
		return askPassphrase()
	}
}

// offerToRemember asks, at init time, whether to cache the passphrase so future
// opens don't prompt. A keychain failure is non-fatal — the key still works.
func offerToRemember(pub, passphrase string) {
	if !askYesNo("Remember this passphrase in your OS keychain so open won't ask?") {
		return
	}
	if err := keystore.Set(pub, passphrase); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("(could not save to keychain: %v)", err)))
		return
	}
	fmt.Println(style.Good("Saved.") + " Remove it anytime with `shenv forget`.")
}

// Remember caches the key's passphrase in the OS keychain after verifying it
// actually unlocks the key, so a wrong passphrase is never stored.
func Remember(args []string) error {
	encrypted, err := identity.IsEncrypted()
	if err != nil {
		return err
	}
	if !encrypted {
		return fmt.Errorf("your key has no passphrase — nothing to remember")
	}

	pub, err := identity.PublicKey()
	if err != nil {
		return err
	}
	pass, err := askPassphrase()
	if err != nil {
		return err
	}
	if _, err := identity.Load(func() (string, error) { return pass, nil }); err != nil {
		return err // wrong passphrase — don't cache it
	}
	if err := keystore.Set(pub, pass); err != nil {
		return fmt.Errorf("could not access the OS keychain: %w", err)
	}
	fmt.Println(style.Good("Passphrase saved.") + " `shenv open` won't ask on this machine anymore.")
	return nil
}

// Forget removes the cached passphrase from the OS keychain.
func Forget(args []string) error {
	pub, err := identity.PublicKey()
	if err != nil {
		return err
	}
	if err := keystore.Delete(pub); err != nil {
		return fmt.Errorf("could not access the OS keychain: %w", err)
	}
	fmt.Println(style.Good("Removed the saved passphrase from this machine's keychain."))
	return nil
}
