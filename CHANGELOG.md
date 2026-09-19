# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.8.0 - 2026-09-19

### Added

- Exec backend commands time out after 10 minutes instead of hanging forever. Change it with `SHENV_EXEC_TIMEOUT` (for example `30m`, or `0` to disable).
- `open`, `run` and `edit` now ask before trusting a changed recipients.shenv, the same way `seal` already did. You confirm a member change once per machine. A fresh machine (CI) trusts the list as cloned; set `SHENV_TRUST_RECIPIENTS=1` to accept changes without a prompt.
- Sealed files are now tied to their project. `shenv init` writes a random `project` id to config.shenv (commit it), and an env.shenv that a teammate sealed for a different repo is rejected here. Existing repos keep working unchanged. To bind one: `shenv open`, add a `project = <name>` line to config.shenv, `shenv seal`, commit. After that everyone on the team needs this version.

### Changed

- Exec backends: your `get` command must exit 0 with empty output when nothing is stored yet. Any failing `get` now stops `seal`. If your command fails on a missing object (like `aws s3 cp`), the very first seal needs a `get` that handles that case. Repos that already have a sealed file are not affected.
- Member names are limited to 64 characters.
- `SHENV_ALLOW_EXEC=1` now prints one line saying it skipped the approval prompt, so the bypass shows up in CI logs.

### Fixed

- A failed or interrupted write can no longer leave a half-written env.shenv. The new file replaces the old one only once it is complete.
- An exec backend that returned more than the size limit was silently cut off. That is now an error.
- On macOS and Linux, shenv deleted any file named `shenv.old` next to its binary on every start. That cleanup now only runs on Windows, where the updater creates that file.
- Sealing a very large .env could succeed and produce a file that shenv itself refused to open. Anything over the 16 MiB limit is now rejected before the existing env.shenv is touched.
- The "a newer shenv is available" hint could stop appearing forever after the system clock had been wrong once.

### Security

- A `path` in config.shenv can no longer point the encrypted file at a nested .gitignore or .env and overwrite it.
- Error messages never quote your secrets anymore. A malformed line in .env or a broken key file used to be printed in full, which could put a secret into your terminal history or CI log. You now get the line number and what is wrong.
- Invisible and right-to-left characters can no longer disguise what you approve. They are rejected in config.shenv (so an exec command looks like what it runs) and stripped from member names shown in prompts.
- Releases are built with Go 1.26.8, which fixes four known standard-library vulnerabilities, and every build and release is now scanned for known vulnerabilities before it ships.
- `seal` and `edit` stop when the current env.shenv can't be read (no permission, network error), instead of treating that as "nothing there yet" and overwriting it without the lockout check.
- `shenv open` no longer writes your decrypted .env anywhere git could commit it. It now asks git whether the file is really ignored and untracked first, so a negated ignore rule, a nested .gitignore or an absolute path back into the repo can't sneak secrets into a commit.
- shenv refuses a private key file that other users on the machine can read, and tells you to `chmod 600` it. This catches keys restored from a backup or copied from another computer. A symlink in place of the key file is not followed.
- `shenv update` no longer accepts plain-http downloads from localhost, and it keeps the file permissions your shenv binary had instead of resetting them.
- The decrypted .env is private from the first byte. It is written to a new owner-only file and then moved into place, instead of tightening permissions after the secrets were already on disk. On Windows it gets an owner-only ACL.
- Two members whose names look the same but use different alphabets (for example "alice" with a Cyrillic "а") are rejected, so "signed by alice" really means the alice you know. Names like "jörg" are unaffected.
