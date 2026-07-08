<div align="center">

<img src="assets/logo.png" width="220" alt="shenv icon" />

# shenv 

**Share encrypted `.env` files across a small team — no server, no accounts, no plaintext in git.**

`shenv` uses [age](https://age-encryption.org) end-to-end encryption: the plaintext `.env`
never leaves your machine, and only teammates whose public key is on the recipients list can
decrypt. The encrypted `env.shenv` blob is safe to commit or drop in S3/a Gist — storage never
sees your secrets.

[![Release](https://img.shields.io/github/v/release/p-arndt/shenv?display_name=tag&sort=semver)](https://github.com/p-arndt/shenv/releases)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>


## How it works

- Your **private key** lives in `~/.shenv/key.txt`. Created **once**, used for every repo — like an SSH key.
- Each repo has `recipients.shenv`: teammates' **public keys** (one for encryption, one for
  verifying signatures). Public, so it's committed.
- `env.shenv` is the encrypted `.env`, encrypted _for all recipients at once_ and **signed by
  whoever sealed it**. Committed / shared.
- `.env` is plaintext. Stays local, auto-gitignored.

```
seal:  .env  ──sign with your key, encrypt for every recipient──►  env.shenv   (shared)
open:  env.shenv  ──decrypt, verify who signed it──►  .env                      (local only)
```

## Quick start

First dev in a repo:

```sh
shenv init bob            # register in this repo (creates your keypair on first use)
# ...put secrets in .env...
shenv seal                # .env → env.shenv, then commit env.shenv + recipients.shenv
```

> Run `shenv init` **inside the repo** — it registers you in *this* repo's
> `recipients.shenv`. If you only want a keypair (no repo yet), use `shenv keygen`.
> Re-running `init` in another repo reuses your existing key.

A new teammate:

```sh
shenv keygen              # once ever, on their machine
shenv whoami              # prints their public key and signing key
# they send you both keys (they're public — Slack/mail is fine)
```

You grant them access:

```sh
shenv add-member alice age1... <signing-key>
shenv seal                # re-encrypt so alice is included; commit env.shenv
```

Now alice can:

```sh
shenv open                # env.shenv → .env
```

Or skip the file entirely and inject secrets straight into a process:

```sh
shenv run -- npm start    # secrets live only in npm's environment, no .env written
```

Changing a secret doesn't need a plaintext `.env` either:

```sh
shenv edit                # decrypt → your $EDITOR → re-seal; plaintext never touches the repo
```

## Commands

| Command                         | What it does                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| `shenv keygen`                  | Create your keypair — no repo needed (`init` does this implicitly too)                |
| `shenv init [name]`             | Register yourself in this repo, set up `.gitignore` (name defaults to your git/OS username; creates your keypair if missing) |
| `shenv whoami`                  | Print your public key and signing key                                                 |
| `shenv status`                  | Read-only overview: your identity, whether you're a member, the team, backend, and whether `.env` is in sync with `env.shenv` |
| `shenv add-member <name> <key> <signing-key>` | Add a teammate's public keys (then `seal`)                              |
| `shenv remove-member <name>`    | Revoke a teammate's access (then `seal` — and rotate the secrets they knew)           |
| `shenv seal [file]`             | Encrypt `.env` (or `file`) → `env.shenv` for all members, signed with your key          |
| `shenv open [file] [--force]`   | Decrypt `env.shenv` → `.env`, verifying who sealed it; asks before clobbering local edits |
| `shenv edit`                    | Edit the secrets in `$EDITOR` and re-seal — the plaintext lives only in a locked-down temp file outside the repo, shredded afterwards |
| `shenv run -- <command>`        | Run a command with secrets injected as env vars — no plaintext `.env` on disk         |
| `shenv remember`                | Cache your passphrase in the OS keychain so `open` stops asking                       |
| `shenv forget`                  | Remove the cached passphrase from the keychain                                        |
| `shenv update [--check]`        | Update to the latest release (checksum-verified); `--check` only reports what's out   |

> `push` and `pull` still work as **deprecated aliases** for `seal` and `open`. They
> print a deprecation warning and will be removed in a future release.

## Updating

```sh
shenv update            # download the latest release, verify its SHA-256, swap in place
shenv update --check    # just tell me if a newer version is out
```

`update` pulls the archive for your platform from GitHub Releases and verifies it
twice before touching anything: the checksums file must carry a valid **Ed25519
signature from the project's release key** (the public key is embedded in the
binary; the private key never leaves the release pipeline's secret), and only
then does the archive's SHA-256 have to match it. An unsigned release, a
re-signed checksums file, or an old signed release replayed under a newer
version is refused outright. It also refuses to run on a `dev`/source build
(nothing to compare against) and on install locations you can't write to (it
tells you to reinstall or elevate).

shenv also shows a one-line _"a newer version is available"_ hint on stderr at
most once a day. It never installs anything on its own — set
`SHENV_NO_UPDATE_CHECK=1` to turn the hint off.

Maintainers: how the release key is generated, held, and rotated (without
stranding already-shipped updaters) is documented in
[docs/release-signing.md](docs/release-signing.md).

## Build

```sh
go build -o shenv ./cmd/shenv
go test ./...
```

## Project layout

```
cmd/shenv/          # entry point: arg dispatch + usage
cmd/release-sign/   # release tooling: sign/verify the checksums file (never shipped)
internal/
  identity/         # the global ~/.shenv/key.txt keypair (+ optional passphrase)
  recipients/       # the per-repo recipients.shenv list
  crypto/           # age encrypt/decrypt (storage-agnostic)
  keystore/         # optional OS-keychain passphrase cache
  dotenv/           # minimal .env parser (for `run`)
  backend/          # where the encrypted blob lives (file | exec)
  update/           # signed self-update from GitHub Releases + "new version" notice
  command/          # subcommands wiring the above together
```

## Storage backends

By default the encrypted blob is a file (`env.shenv`) in the repo — share it by
committing it. For anything else, an **exec** backend delegates get/put to shell
commands, so any storage tool works without shenv depending on it. Configure it
in `config.shenv` (safe to commit — it holds no secrets):

```ini
backend = exec
# `get` writes the blob to stdout; `put` reads it from stdin.
get = aws s3 cp s3://my-bucket/env.shenv -
put = aws s3 cp - s3://my-bucket/env.shenv
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
  passphrase (age/scrypt). If set, `open` prompts for it; `whoami` still works
  without it, since the public key is kept as a plaintext comment.
- **OS keychain (optional, for comfort).** `shenv remember` caches the passphrase
  in the OS keychain (Windows Credential Manager, Linux Secret Service, macOS
  Keychain), bound to your login, so `open` stops asking. `shenv forget` removes it.
  On systems without a keychain (headless Linux, containers) `open` simply falls
  back to prompting — it never hard-fails.
- **Process hardening (always, best-effort).** While shenv runs it disables core
  dumps (and, on Linux, blocks other same-user processes from ptrace-attaching;
  on Windows it excludes itself from Windows Error Reporting dumps), so a crash
  can't spill the decrypted key or `.env` plaintext to disk. It also zeroes those
  secret buffers as soon as it's done with them. Honest caveat: Go's garbage
  collector may already have copied the bytes, so zeroing shrinks the exposure
  window rather than guaranteeing erasure — and none of this stops malware or
  root running as you. A hardware-backed key remains the answer to that.

These layers compose: a synced/copied `key.txt` is useless without the passphrase,
and the cached passphrase is bound to your OS login. Note: no software measure
protects against malware running _as you_ — once the key is unlocked it lives in
process memory. For that threat, use a hardware-backed key.

## Security

shenv assumes a small, mutually trusted team. A few highlights:

- **Every blob is signed.** `seal` signs the payload (Ed25519, sign-then-encrypt);
  `open`/`run` reject anything not signed by a current member and tell you who sealed
  it — so a hijacked bucket or gist can't plant a replacement `env.shenv`.
- **No accidental lockouts.** Each blob embeds the member list it was encrypted for;
  `seal` refuses to ship one that would drop a current member — or yourself — from access.
- **Recipient changes are surfaced.** `recipients.shenv` rides the same untrusted
  channel as the ciphertext, so `seal` shows added/removed keys and asks you to confirm
  before encrypting for a changed set.
- **Your private key is protected in layers** — file permissions, an optional
  passphrase, and an optional OS-keychain cache. See
  [Protecting your private key](#protecting-your-private-key).

Full threat model — what signing does and doesn't cover, replays, and `run`'s
process-environment exposure — is in [docs/security.md](docs/security.md).

> The security design was reviewed by Claude (Fable 5) 🤖 — a sanity check, not a
> substitute for a professional audit. Found a hole? Please report it **privately**
> via [GitHub's security advisories](https://github.com/p-arndt/shenv/security/advisories/new),
> not a public issue. Regular bugs and feature requests are welcome as
> [issues](https://github.com/p-arndt/shenv/issues).

## Roadmap

- `github:user` public-key lookup for onboarding
- CI support via `SHENV_IDENTITY` / `SHENV_PASSPHRASE` environment variables
