// Command shenv shares encrypted .env files across a small team using age
// end-to-end encryption. See README.md for the full workflow.
package main

import (
	"fmt"
	"os"

	"shenv/internal/buildinfo"
	"shenv/internal/command"
	"shenv/internal/update"
)

const usage = `shenv — share encrypted .env files across a team

Usage:
  shenv keygen                      Create your keypair (no repo needed)
  shenv init [name]                 Register yourself in this repo (creates your keypair if missing)
  shenv whoami                      Print your public keys (share them to get added)
  shenv add-member <name> <key> <signing-key>
                                    Grant a teammate access (then push)
  shenv remove-member <name>        Revoke a teammate's access (then push)
  shenv push [file]                 Encrypt .env → env.shenv for all members, signed with your key
  shenv pull [file] [--force]       Decrypt env.shenv → .env (verifies who pushed it)
  shenv run -- <command> [args...]  Run a command with secrets injected (no .env on disk)
  shenv remember                    Cache your passphrase in the OS keychain
  shenv forget                      Remove the cached passphrase
  shenv update [--check]            Update shenv to the latest release (--check only reports)
  shenv version                     Print the shenv version

Your private key lives in ~/.shenv/key.txt and is created once, for all repos.
env.shenv is safe to commit; .env is not (and is gitignored automatically).`

func main() {
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
	case "add-member":
		err = command.AddMember(args)
	case "remove-member":
		err = command.RemoveMember(args)
	case "push":
		err = command.Push(args)
	case "pull":
		err = command.Pull(args)
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
