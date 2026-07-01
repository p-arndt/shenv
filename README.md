# shenv

Share encrypted `.env` files across a small team — no server, no accounts, no plaintext in git.

`shenv` uses [age](https://age-encryption.org) end-to-end encryption: the plaintext `.env`
never leaves your machine, and only teammates whose public key is on the recipients list can
decrypt. The encrypted `env.age` blob is safe to commit or drop in S3/a Gist — storage never
sees your secrets.

## How it works

- Your **private key** lives in `~/.shenv/key.txt`. Created **once**, used for every repo — like an SSH key.
- Each repo has `.shenv/recipients`: a list of teammates' **public keys**. Public, so it's committed.
- `env.age` is the encrypted `.env`, encrypted _for all recipients at once_. Committed / shared.
- `.env` is plaintext. Stays local, auto-gitignored.

```
push:  .env  ──encrypt for every recipient──►  env.age   (shared)
pull:  env.age  ──decrypt with your key──►  .env          (local only)
```

## Quick start

First dev in a repo:

```sh
shenv init patrick        # make your keypair (once ever) + set up this repo
# ...put secrets in .env...
shenv push                # .env → env.age, then commit env.age + .shenv/recipients
```

A new teammate:

```sh
shenv init bob            # once ever, on their machine
shenv whoami              # prints their public key: age1...
# they send you that key (it's public — Slack/mail is fine)
```

You grant them access:

```sh
shenv add-member bob age1...
shenv push                # re-encrypt so bob is included; commit env.age
```

Now bob can:

```sh
shenv pull                # env.age → .env
```

Or skip the file entirely and inject secrets straight into a process:

```sh
shenv run -- npm start    # secrets live only in npm's environment, no .env written
```

## Commands

| Command                         | What it does                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| `shenv init [name]`             | Create your keypair (if missing), register yourself in this repo, set up `.gitignore` |
| `shenv whoami`                  | Print your public key                                                                 |
| `shenv add-member <name> <key>` | Add a teammate's public key (then `push`)                                             |
| `shenv push [file]`             | Encrypt `.env` (or `file`) → `env.age` for all members                                |
| `shenv pull [file] [--force]`   | Decrypt `env.age` → `.env`; asks before clobbering local edits                        |
| `shenv run -- <command>`        | Run a command with secrets injected as env vars — no plaintext `.env` on disk         |
| `shenv remember`                | Cache your passphrase in the OS keychain so `pull` stops asking                       |
| `shenv forget`                  | Remove the cached passphrase from the keychain                                        |

## Build

```sh
go build -o shenv ./cmd/shenv
go test ./...
```

## Project layout

```
cmd/shenv/          # entry point: arg dispatch + usage
internal/
  identity/         # the global ~/.shenv/key.txt keypair (+ optional passphrase)
  recipients/       # the per-repo .shenv/recipients list
  crypto/           # age encrypt/decrypt (storage-agnostic)
  keystore/         # optional OS-keychain passphrase cache
  dotenv/           # minimal .env parser (for `run`)
  command/          # subcommands wiring the above together
```

## Protecting your private key

The private key in `~/.shenv/key.txt` decrypts every secret you have access to, so
`shenv` protects it in layers:

- **File permissions (always).** On Unix the key is `0600`; on Windows an explicit
  owner-only ACL is applied (the Unix bits are ignored there), so no other local
  user can read it.
- **Passphrase (optional).** `shenv init` offers to encrypt the key at rest with a
  passphrase (age/scrypt). If set, `pull` prompts for it; `whoami` still works
  without it, since the public key is kept as a plaintext comment.
- **OS keychain (optional, for comfort).** `shenv remember` caches the passphrase
  in the OS keychain (Windows Credential Manager, Linux Secret Service, macOS
  Keychain), bound to your login, so `pull` stops asking. `shenv forget` removes it.
  On systems without a keychain (headless Linux, containers) `pull` simply falls
  back to prompting — it never hard-fails.

These layers compose: a synced/copied `key.txt` is useless without the passphrase,
and the cached passphrase is bound to your OS login. Note: no software measure
protects against malware running _as you_ — once the key is unlocked it lives in
process memory. For that threat, use a hardware-backed key.

## Notes & roadmap

- **Onboarding re-push:** adding a member requires one existing member to `push` again
  (their key wasn't in the previous blob). Inherent to E2E; it's a one-liner.
- `shenv run` keeps secrets out of any file, but environment variables are still
  readable by other processes running *as you* (`/proc/<pid>/environ`, `ps e`).
  It reduces the leak surface versus a file; it is not a hard boundary.
- Planned: pluggable storage backends (S3, Gist, `github:user` key lookup), CI
  support via `SHENV_IDENTITY` / `SHENV_PASSPHRASE` environment variables.
