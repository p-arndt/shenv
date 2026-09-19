# Release signing & key rotation

`shenv update` installs a new binary over the running one. That is the single
most attractive thing to compromise in the whole project — whoever controls
what the updater installs runs code on every user's machine. This document
explains how releases are authenticated, and the exact procedure for
generating and rotating the key that authenticates them.

If you only want to know *how* the updater checks a download, read
[Trust model](#trust-model). If you need to *do* something — first release,
routine rotation, or a suspected key compromise — jump to the runbook that
matches.

## Trust model

TLS and a checksums file are not enough on their own. The checksums file
travels over the same channel as the archive it vouches for, so anyone who can
edit release assets — a stolen GitHub token, a compromised CI run, a hostile
CDN — can regenerate *both* the archive and its checksums, and naïve
verification still "passes".

shenv closes that gap by signing the checksums file with an Ed25519 **release
key** that GitHub's release assets do not carry. The chain the updater verifies,
in order, is:

```
Ed25519 signature  ──vouches for──▶  checksums file  ──vouches for──▶  release archive  ──contains──▶  shenv binary
        ▲
        └── verified against a public key compiled into the running binary
```

Two properties make this hard to forge with *asset* write access alone:

- **The key is not in the repository or the release.** It lives in the
  `RELEASE_SIGNING_KEY` Actions secret and the maintainer's offline backup,
  never committed and never attached to a release. Editing release assets or
  the checksums file therefore does not get you a valid signature.
- **The signed message binds the version.** The bytes that get signed are
  `"shenv release checksums v1" + "\n" + <checksums file name> + "\n" + <content>`.
  The file name carries the version (`shenv_0.4.0_checksums.txt`), so a
  genuinely-signed `0.3.1` release cannot be replayed under a `0.4.0` tag, and
  the domain-separation prefix stops the signature from being reused for
  anything else the project signs with Ed25519.

The updater accepts a download only if the signature verifies against one of
the public keys embedded in the binary (`releaseVerifyKeys` in
[`internal/update/sign.go`](../internal/update/sign.go)). A build with no valid
embedded key, an unsigned release, or a signature from any other key **fails
closed** — the update is refused, never installed unverified.

### What this does *not* protect against

- **A stolen private key.** Whoever holds it can sign forgeries. Rotation
  (below) is the response; there is no online revocation.
- **Whoever can run the release workflow.** This is **not** an offline signer.
  The key is an Actions secret, read by a job on a GitHub runner, and the thing
  that uses it is code from this repository. Anyone who can get code into a
  release run — a maintainer, a stolen account, a compromised action — can sign
  with it or exfiltrate it. See
  [Protecting the signing job](#protecting-the-signing-job); the cryptography
  does not substitute for those repository settings.
- **A freeze / rollback of the *newest* release.** An attacker who controls the
  API responses can keep serving an older but genuinely-signed release as
  "latest". The updater already refuses to *downgrade* (it only installs a
  strictly newer version), so this can stall users on the current version but
  cannot push a known-vulnerable older one onto an up-to-date machine.

## Components

| Thing | Where | Role |
|---|---|---|
| `releaseVerifyKeys` | `internal/update/sign.go` | Public keys compiled into every binary; a signature is trusted if it verifies under **any** of them. |
| `RELEASE_SIGNING_KEY` | GitHub Actions secret | Base64 Ed25519 **seed** (private key). Read online, by the release job on a GitHub runner. |
| `cmd/release-sign` | repo, CI-only tool | `gen` a keypair, `sign` a file, `verify`/`selfcheck` a signature. Never shipped to users. |
| `.github/workflows/release.yml` | repo | Signs the checksums file and, via `selfcheck`, refuses to publish a release the embedded key can't verify. |

## Protecting the signing job

The signing key is only as protected as the pipeline that reads it, and that
pipeline is online. `.github/workflows/release.yml` does what a workflow file
can do:

- The secret is declared on the signing step alone, so no other step in the job
  can read it; the signer binary is compiled in an earlier step, without it.
- `selfcheck` runs in its own step without the secret — verification needs only
  the public key.
- Third-party actions are pinned to commit SHAs, never tags.
- Every `${{ … }}` value reaches a `run:` block through `env:`, never inline.
- The job declares `environment: release`.

The rest cannot live in the repository and must be configured once in
**Settings** — without it, the `environment:` line is decoration:

1. **Settings → Environments → `release`:** add **required reviewers** (so a
   release run pauses for a human before the key is handed out) and a
   **deployment branch/tag rule** limiting it to `v*` tags.
2. Move `RELEASE_SIGNING_KEY` from a repository secret to an **environment
   secret** on `release`. A repository secret is readable by any workflow;
   an environment secret is only available to jobs that pass the rules above.
3. **Settings → Rules → Tag rulesets:** protect `v*` so tags cannot be created
   or moved by anyone who should not be cutting releases.
4. Keep the set of people who can push to `main`, dispatch workflows, or approve
   the `release` environment as small as the set you would hand the key to —
   because it is the same thing.

## Why the trusted keys are a **list**

A binary can only ever trust the keys it was compiled with. If `releaseVerifyKeys`
held a single key and you replaced it in one commit, every binary already in
users' hands would embed only the *old* key and would reject every release
signed with the *new* one — breaking `shenv update` for all of them, with no
in-band way to recover. They'd each have to re-download shenv by hand.

Keeping it a list turns rotation into an overlap instead of a cliff: you add
the successor key **before** retiring the old one, so during the overlap window
both old and new binaries can verify releases. Only once users have had time to
upgrade do you drop the retired key.

---

## Runbook: first-ever key

Do this once, before the first signed release ships.

1. **Generate the keypair on your own machine** (not in CI, not in a shared
   shell — the private key must not exist anywhere you don't control), into a
   private directory **outside the checkout**, so that no `git add .` in this
   repository can ever reach it:

   ```sh
   mkdir -p ~/.shenv-release && chmod 700 ~/.shenv-release
   go run ./cmd/release-sign gen ~/.shenv-release/release.key
   ```

   This writes the private seed owner-only (never printed) and prints the
   **public** key to stdout. `gen` refuses to overwrite an existing file, and
   the repository's `.gitignore` ignores `*.key` as a backstop — but the
   backstop is not the plan; keeping the file out of the tree is.

2. **Embed the public key.** Add it to `releaseVerifyKeys` in
   `internal/update/sign.go`:

   ```go
   var releaseVerifyKeys = []string{
       "<public key from step 1>",
   }
   ```

3. **Set the CI secret** from the private key file. Prefer the `release`
   environment over a repository-wide secret — see
   [Protecting the signing job](#protecting-the-signing-job):

   ```sh
   gh secret set RELEASE_SIGNING_KEY --env release < ~/.shenv-release/release.key
   ```

   (Or paste the file's contents in the GitHub UI:
   *Settings → Environments → release → Environment secrets*.)

4. **Back up the key file offline** (password manager / offline storage), then
   delete the local copy:

   ```sh
   rm ~/.shenv-release/release.key
   ```

   Losing this file means you can never sign a release the currently-shipped
   binaries will accept. Never commit it.

5. **Commit** the `sign.go` change and cut a release. The pipeline's `selfcheck`
   step verifies the fresh signature against the embedded key, so a mismatch
   fails the release loudly instead of shipping something no updater trusts.

---

## Runbook: routine key rotation

Use this to replace the key on a schedule, or because it may have been exposed
but you have no evidence it was actively misused. Done in this order it never
strands a user.

> **Timing shortcut.** As long as *no signed release exists yet*, rotation is
> free: just replace the single entry in `releaseVerifyKeys` and set the secret.
> The overlap sequence below only matters once a signed release is in users'
> hands.

The one rule that makes this safe: **a new key must be *trusted* by deployed
binaries before it is *used for signing*.** A deployed binary learns the new key
only by updating, and it will only accept that update if the update is signed by
a key it *already* trusts. So you keep signing with the old key until users have
picked up a binary that trusts both — then, and only then, switch signing over.

1. **Generate the successor keypair** on your own machine, again outside the
   checkout. Keep it offline for now — do **not** put it in CI yet:

   ```sh
   go run ./cmd/release-sign gen ~/.shenv-release/release-new.key
   ```

2. **Add** — do not replace — the new public key to `releaseVerifyKeys`, and
   keep CI signing with the **old** key (leave `RELEASE_SIGNING_KEY` untouched):

   ```go
   var releaseVerifyKeys = []string{
       "<old public key>",  // still the signing key
       "<new public key>",  // trusted now, becomes the signing key later
   }
   ```

3. **Ship the overlap release(s), still signed by the old key.** Deployed
   binaries trust the old key, so they accept these updates — and in doing so
   install a binary that now trusts *both* keys. Give users real time to pick
   this up (multiple releases / weeks, not hours).

4. **Switch signing to the new key**, once you're satisfied most users run a
   both-trusting binary:

   ```sh
   gh secret set RELEASE_SIGNING_KEY --env release < ~/.shenv-release/release-new.key
   ```

   Back the new key up offline, delete the local copy, and delete the old key's
   secret material. From here CI signs with the new key; both-trusting binaries
   accept it.

5. **Retire the old key.** Remove the old entry from `releaseVerifyKeys` and
   commit, then delete its offline backup. Any binary that never updated during
   the overlap trusts only the old key and will now need a manual re-download —
   which is exactly why the window in step 3 should be generous.

---

## Runbook: suspected key compromise

If the private key may have leaked — generated somewhere you don't fully
control, written inside a Git checkout, seen in a log or transcript, or on a
machine that was compromised — treat it as burned and rotate **now**, not on a
schedule. Deleting the file does not revoke the key; only rotation does. The tension here is
real: you want to stop trusting the old key immediately, but deployed binaries
can only receive the new key through a release the old key still signs. You
cannot fully close the window for users who never update; aim to make it short
and loud.

1. Do routine-rotation steps 1–2 immediately: generate a fresh key and add it to
   `releaseVerifyKeys`.
2. Ship one overlap release that delivers the new trusted key. It still has to
   be signed by the old key (that is the only signature deployed binaries
   accept) — acceptable because an attacker holding the key can already sign
   anyway; the point is to get the successor key trusted.
3. As soon as that release has propagated, switch signing to the new key
   (step 4) and **retire the old key from `releaseVerifyKeys` aggressively**
   (step 5) — a much shorter window than a routine rotation. Every release the
   old key stays trusted is one an attacker could forge.
4. Delete the compromised secret and every offline copy.
5. If forged releases may already have shipped, announce it out of band (README,
   release notes, wherever users will see it) and tell them to re-download from
   a link you control rather than trusting `shenv update`.

---

## Verifying a release by hand

To spot-check a downloaded release against a public key you obtained out of band:

```sh
# verify against an explicit public key
go run ./cmd/release-sign verify shenv_0.4.0_checksums.txt <public-key>

# or verify against the key embedded in this checkout (what shipped updaters do)
go run ./cmd/release-sign selfcheck shenv_0.4.0_checksums.txt
```

Both expect the matching `shenv_0.4.0_checksums.txt.sig` alongside the file.
`selfcheck` is what the release pipeline runs immediately after signing, so a
signing key that has drifted from the embedded public key fails the release
instead of stranding every updater.
