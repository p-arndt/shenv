// Command shenv shares encrypted .env files across a small team using age
// end-to-end encryption. See README.md for the full workflow.
package main

import (
	"fmt"
	"os"

	"shenv/internal/command"
)

const usage = `shenv — share encrypted .env files across a team

Usage:
  shenv init [name]                 Create your keypair + register in this repo
  shenv whoami                      Print your public key (share it to get added)
  shenv add-member <name> <key>     Grant a teammate access (then push)
  shenv push [file]                 Encrypt .env → env.age for all members
  shenv pull [file] [--force]       Decrypt env.age → .env
  shenv run -- <command> [args...]  Run a command with secrets injected (no .env on disk)
  shenv remember                    Cache your passphrase in the OS keychain
  shenv forget                      Remove the cached passphrase

Your private key lives in ~/.shenv/key.txt and is created once, for all repos.
env.age is safe to commit; .env is not (and is gitignored automatically).`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		return
	}

	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "init":
		err = command.Init(args)
	case "whoami":
		err = command.Whoami(args)
	case "add-member":
		err = command.AddMember(args)
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
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
