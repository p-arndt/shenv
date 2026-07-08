// Command shenv shares encrypted .env files across a small team using age
// end-to-end encryption. See README.md for the full workflow.
package main

import (
	"fmt"
	"os"

	"shenv/internal/buildinfo"
	"shenv/internal/command"
	"shenv/internal/harden"
	"shenv/internal/update"
)

const usage = `shenv — share encrypted .env files across a team

Usage:
  shenv keygen                      Create your keypair (no repo needed)
  shenv init [name]                 Register yourself in this repo (name defaults to your git/OS user; creates your keypair if missing)
  shenv whoami                      Print your public keys (share them to get added)
  shenv status                      Show this repo's state: identity, team, backend, sync
  shenv add-member <name> <key> <signing-key>
                                    Grant a teammate access (then seal)
  shenv remove-member <name>        Revoke a teammate's access (then seal)
  shenv seal [file]                 Encrypt .env → env.shenv for all members, signed with your key
  shenv open [file] [--force]       Decrypt env.shenv → .env (verifies who sealed it)
  shenv edit                        Edit secrets in your $EDITOR — decrypt, edit, re-seal; no plaintext in the repo
  shenv run -- <command> [args...]  Run a command with secrets injected (no .env on disk)
  shenv remember                    Cache your passphrase in the OS keychain
  shenv forget                      Remove the cached passphrase
  shenv update [--check]            Update shenv to the latest release (--check only reports)
  shenv version                     Print the shenv version

Your private key lives in ~/.shenv/key.txt and is created once, for all repos.
env.shenv is safe to commit; .env is not (and is gitignored automatically).

(push and pull are deprecated aliases for seal and open.)`

// deprecatedAlias warns (to stderr, so piped stdout stays clean) that an old
// command name still works but should be replaced by its new name.
func deprecatedAlias(old, replacement string) {
	fmt.Fprintf(os.Stderr, "warning: `shenv %s` is deprecated and will be removed in a future release; use `shenv %s` instead.\n", old, replacement)
}

func main() {
	// Best-effort process hardening before anything sensitive runs: disable
	// core/crash dumps and block casual same-user memory inspection so decrypted
	// secrets can't leak that way. Silent by design — it never fails the program.
	harden.Process()

	// Clean up any leftover binary from a previous self-update (Windows can't
	// delete the running .exe during the swap, so it's removed on the next run).
	update.CleanupLeftovers()

	if len(os.Args) < 2 {
		fmt.Println(usage)
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "keygen":
		err = command.Keygen(args)
	case "init":
		err = command.Init(args)
	case "whoami":
		err = command.Whoami(args)
	case "status":
		err = command.Status(args)
	case "add-member":
		err = command.AddMember(args)
	case "remove-member":
		err = command.RemoveMember(args)
	case "seal":
		err = command.Seal(args)
	case "open":
		err = command.Open(args)
	case "edit":
		err = command.Edit(args)
	case "push":
		deprecatedAlias("push", "seal")
		err = command.Seal(args)
	case "pull":
		deprecatedAlias("pull", "open")
		err = command.Open(args)
	case "run":
		err = command.Run(args)
	case "remember":
		err = command.Remember(args)
	case "forget":
		err = command.Forget(args)
	case "update":
		err = command.Update(args)
	case "version", "--version", "-v":
		fmt.Printf("shenv %s\n", buildinfo.String())
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// After a successful command, hint (to stderr, so piped stdout stays clean)
	// if a newer release is out. Skipped for update/version/help — where it'd be
	// redundant — and for run, which must stay a transparent exec wrapper.
	switch cmd {
	case "update", "version", "--version", "-v", "help", "-h", "--help", "run":
	default:
		update.NotifyIfAvailable(os.Stderr, buildinfo.Version)
	}
}
