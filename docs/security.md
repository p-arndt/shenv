# Security model

shenv assumes a **small, mutually trusted team**. Encryption keeps storage (git,
S3, a gist) from ever seeing your secrets; signing keeps other people who can
*write* to that storage from impersonating a teammate. It is not a defense
against a malicious member — signing authenticates members to each other.

This document covers the threat model in detail. For the local-key protections
(file permissions, passphrase, keychain) see
[Protecting your private key](../README.md#protecting-your-private-key) in the README.

## Every blob is signed

The recipient keys in `recipients.shenv` are public, so without more, *anyone*
could encrypt a replacement `env.shenv` "for the team" — a hijacked S3 bucket or
gist would be enough. That's why `seal` signs the payload (Ed25519,
sign-then-encrypt: the signature lives *inside* the ciphertext, covering the
member manifest and the secrets), and `open`/`run` verify it against the signer's
key in `recipients.shenv` before trusting a single value.

A blob that isn't signed by a *current member* is rejected outright, and every
open tells you who sealed it (`signed by bob`). The signing key is derived from
your age key, so there is still only one secret to protect and back up.

## What signing does not cover

`recipients.shenv` is the trust anchor, so someone with **commit access to the
repo** could swap both a key and the blob. That edit is visible in git history
and guarded by seal's recipient-change prompt, but `open` does not independently
detect it.

Replays aren't prevented either: an old, validly-signed blob can be restored by
anyone with write access — enable storage versioning to spot this.

## Avoiding lockouts

Every blob carries the member list it was encrypted for, embedded *inside* the
ciphertext. Before overwriting, `seal` compares that list with `recipients.shenv`
and blocks if anyone would lose access — so a drifted or never-committed
recipients file can't silently lock a teammate out of `env.shenv`. Because the
truth travels with the blob, this works with any backend.

Locking *yourself* out is impossible: seal refuses outright when your own key
isn't in the list (it couldn't sign a verifiable blob anyway). Deliberate
removal goes through `shenv remove-member` plus confirming the prompt.

## Recipients are committed, so seal guards them

The `recipients.shenv` list travels over the same untrusted channel as the
ciphertext. `seal` lists exactly who it will encrypt for and, if the set changed
since your last seal on this machine, shows the added/removed keys and asks you
to confirm — so an injected key can't silently grant an outsider access to your
secrets.

## Onboarding requires a re-seal

Adding a member requires one existing member to `seal` again, because the new
teammate's key wasn't in the previous blob. This is inherent to end-to-end
encryption; it's a one-liner.

## `shenv run` and the process environment

`shenv run` keeps secrets out of any file, but environment variables are still
readable by other processes running *as you* (`/proc/<pid>/environ`, `ps e`). It
reduces the leak surface versus a file; it is not a hard boundary.

## `shenv edit` and the transient plaintext

`shenv edit` has to hand your editor a plaintext file; the design bounds that
exposure:

- The file lives in a freshly created private directory **outside the repo** —
  git can never see, track, or commit it. On Linux the directory is placed in
  `/dev/shm` (tmpfs) when available, so the plaintext stays in RAM and never
  reaches persistent storage; elsewhere it's the per-user temp dir (`0700` on
  Unix; on Windows, inside the user profile).
- The file is created with `O_EXCL` (no pre-planted symlink can redirect it)
  and locked to your OS user **before** the plaintext is written — the same
  owner-only Windows ACL / Unix `0600` treatment as the private key file.
- On every exit path — editor failure, declined confirmation, success — every
  regular file in that directory (including editor swap/backup files, which
  land next to the plaintext) is overwritten with zeros and the directory
  removed. Two honest limits: a hard kill (`kill -9`, closing the terminal
  window) can't be intercepted, so the directory then survives until temp/tmpfs
  cleanup — still owner-only, and in RAM on Linux. And on journaling
  filesystems and wear-leveled SSDs an overwrite can't guarantee old blocks
  are unrecoverable; the permissions and tmpfs placement are the real
  mitigations there too.
- Re-sealing goes through the same guards as `shenv seal` (lockout check,
  recipient confirmation, signing) — `edit` adds no bypass around them. And
  because the editor may sit open for a while, `edit` re-fetches the blob
  before sealing: if a teammate re-sealed in the meantime, it warns instead of
  silently overwriting their update (which could re-instate a secret they had
  just rotated).

The editor itself is the remaining trust boundary, so `edit` vets it before
anything is decrypted:

- **Windows Notepad is refused outright**, however `$EDITOR` spells it. The
  tabbed Notepad both breaks the flow (a running instance takes the file and
  returns immediately, so shenv can't tell when you're done) and leaks: its
  session restore writes the tab's *content* to its own on-disk cache
  (`…\Microsoft.WindowsNotepad_…\LocalState\TabState`), where the secrets
  outlive the shredded temp file and reappear in a restored tab.
- **VS Code and Sublime Text without `--wait` are refused** with the fix in
  the error — without the flag they return immediately, and their hot-exit
  backups would cache the orphaned buffer. Likewise **Notepad++ needs
  `-multiInst -nosession`** (instance handoff + backup cache) and
  **gvim/mvim need `-f`** (they fork from the terminal, so shenv would shred
  the directory while the editor still has the file open).
- With nothing configured, the fallbacks are console editors verified on PATH:
  Microsoft's `edit` (ships with Windows 11), `vim`/`nano` on Windows;
  `vi`/`nano` elsewhere. No safe editor found is an error, never a leaky guess.

Beyond that, editors may still write undo history, swap, or backup copies to
*configured* locations outside the temp directory (e.g. vim's `undodir`,
editors with cloud sync). If that's in your threat model, point `$EDITOR` at
something spartan.
