<div align="center">

<img src="assets/logo.png" width="220" alt="shenv icon" />

# shenv 

**Share encrypted `.env` files across a small team — no server, no accounts, no plaintext in git.**

`shenv` uses [age](https://age-encryption.org) end-to-end encryption: the plaintext `.env`
never leaves your machine, and only teammates whose public key is on the recipients list can
decrypt. The encrypted `env.age` blob is safe to commit or drop in S3/a Gist — storage never
sees your secrets.

[![Release](https://img.shields.io/github/v/release/p-arndt/shenv?display_name=tag&sort=semver)](https://github.com/p-arndt/shenv/releases)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>


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
shenv init bob            # register in this repo (creates your keypair on first use)
# ...put secrets in .env...
shenv push                # .env → env.age, then commit env.age + .shenv/recipients
```

> Run `shenv init` **inside the repo** — it registers you in *this* repo's
> `.shenv/recipients`. If you only want a keypair (no repo yet), use `shenv keygen`.
> Re-running `init` in another repo reuses your existing key.

A new teammate:

```sh
shenv keygen              # once ever, on their machine
shenv whoami              # prints their public key: age1...
# they send you that key (it's public — Slack/mail is fine)
```

You grant them access:

```sh
shenv add-member alice age1...
shenv push                # re-encrypt so alice is included; commit env.age
```

Now alice can:

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
| `shenv keygen`                  | Create your keypair — no repo needed (`init` does this implicitly too)                |
| `shenv init [name]`             | Register yourself in this repo, set up `.gitignore` (creates your keypair if missing) |
| `shenv whoami`                  | Print your public key                                                                 |
| `shenv add-member <name> <key>` | Add a teammate's public key (then `push`)                                             |
| `shenv remove-member <name>`    | Revoke a teammate's access (then `push` — and rotate the secrets they knew)           |
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
  backend/          # where the encrypted blob lives (file | exec)
  command/          # subcommands wiring the above together
```

## Storage backends

By default the encrypted blob is a file (`env.age`) in the repo — share it by
committing it. For anything else, an **exec** backend delegates get/put to shell
commands, so any storage tool works without shenv depending on it. Configure it
in `.shenv/config` (safe to commit — it holds no secrets):

```ini
backend = exec
# `get` writes the blob to stdout; `put` reads it from stdin.
get = aws s3 cp s3://my-bucket/env.age -
put = aws s3 cp - s3://my-bucket/env.age
```

Swap in `curl`, `rclone`, `gh gist`, `scp`, … — whatever moves bytes. With no
config (or `backend = file`) it stays a repo file; set `path = ...` to relocate it.

Because the exec backend runs shell commands that arrive with the repo (a clone,
a merged PR), shenv treats them as untrusted: the first time it would run an
`exec` backend — and again whenever the commands change — it prints them and asks
for approval, recording your answer under `~/.shenv/trusted` so later runs are
silent. Review the commands before approving; only approve what you'd be willing
to run yourself. In CI (no prompt), set `SHENV_ALLOW_EXEC=1` to pre-approve, and
only where you control the config.

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
- **Recipients are committed, so `push` guards them:** the `.shenv/recipients` list
  travels over the same untrusted channel as the ciphertext. `push` lists exactly who
  it will encrypt for and, if the set changed since your last push on this machine,
  shows the added/removed keys and asks you to confirm — so an injected key can't
  silently grant an outsider access to your secrets.
- **Lockout protection:** every blob carries the member list it was encrypted for,
  embedded *inside* the ciphertext. Before overwriting, `push` compares that list
  with `.shenv/recipients` and blocks if anyone would lose access — so a drifted or
  never-committed recipients file can't silently lock a teammate (or yourself:
  pushing a list without your own key warns too) out of `env.age`. Works with any
  backend, since the truth travels with the blob. Deliberate removal goes through
  `shenv remove-member` + confirming the prompt.
- **Confidentiality, not sender authentication:** the age recipients used here hide
  contents from non-members, but they do not prove *who* wrote `env.age`. Any current
  member (or anyone who can edit the recipients list) can replace the blob; a puller
  can't cryptographically tell who produced it. shenv assumes a small, mutually
  trusted team — it is not a defense against a malicious member.
- `shenv run` keeps secrets out of any file, but environment variables are still
  readable by other processes running *as you* (`/proc/<pid>/environ`, `ps e`).
  It reduces the leak surface versus a file; it is not a hard boundary.
- Planned: `github:user` public-key lookup for onboarding, CI support via
  `SHENV_IDENTITY` / `SHENV_PASSPHRASE` environment variables.
