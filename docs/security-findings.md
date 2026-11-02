# Security finding review (2026-11-02)

Scope: the supplied dev-security report (179 open findings), the current source,
and a local Gosec v2.30.0 scan including tests. The dashboard redirects to login,
so its 26 omitted findings could not be matched by ID. The local scan reported
243 entries, or 181 distinct `(file, line, rule)` locations after removing
duplicate production-package reports; 118 locations were in tests. These counts
describe the baseline, not a claim that all dashboard findings were closed.

## Fixes

- Updated `golang.org/x/crypto` from v0.55.0 to v0.56.0 and tidied the module
  checksums. The SSH fixes include
  [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
  [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355).
- Hardened `release-sign sign`: writing directly to an existing `.sig` followed
  symlinks and modified hardlink targets. Signature destinations now pass the
  existing symlink guard and are replaced using `backend.WriteFileAtomic`.
  Tests reproduced both target-overwrite cases before the fix and verify that
  linked targets remain untouched afterwards. Signatures remain public `0644`
  files; their contents are not private keys.
- Updated the release toolchain from Go 1.26.8 to Go 1.26.10 after the live
  vulnerability scan found additional standard-library advisories. This includes
  [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). A newer locally installed
  Go version can override the `toolchain` preference: explicitly select
  `GOTOOLCHAIN=go1.26.10` to reproduce the release-toolchain checks. The installed
  Go 1.27.1 was subsequently updated to Go 1.27.3 using the verified official
  macOS installer.

## Remaining code findings

These dispositions apply to the reviewed call sites, not to future occurrences
of the same rule. No rules or test files have been globally suppressed.

| Finding | Assessment |
| --- | --- |
| G703/G304 in `release-sign` reads and key creation/removal | The operator explicitly chooses the input or key path. This local CLI has no confined upload directory or remote path input. Key creation uses `O_EXCL`, owner-only permissions and Windows ACL hardening before writing; cleanup only follows a successful exclusive creation. The signature output overwrite was fixed separately above. |
| G702/G204 in `command.Run` | Running the command after `--` is the requested feature. Arguments go directly to `exec.Command`; decrypted values only populate the child environment. No implicit shell interpolation is added. |
| G204 in `runEditor` | The user selects their editor through their own environment. Existing editor validation runs before decryption, and arguments are passed directly to the process. |
| G204 in backend shell commands | Shell execution is the explicit exec-backend contract. The command layer calls `EnsureTrusted` before storage use; approval is bound to the exact commands and config path, or explicitly bypassed with `SHENV_ALLOW_EXEC=1`. |
| G204 in `runGitEnv` | The executable and subcommands are selected by shenv. Existing callers pass file arguments separately, use option terminators where needed and literal pathspecs for path-sensitive checks. |
| G304 in `backend.readConfig` | The caller supplies the fixed project config path. Parse errors avoid echoing file contents, and exec configuration still goes through the trust gate. |
| G304 in `backend.trust`, `command.readPin`, `update.loadState` | Paths are derived from the user's home and fixed names (or the project pin identifier), not from downloaded ciphertext. Update-cache versions are validated before display. Same-user compromise remains outside the threat model. |
| G304 in identity reads/creation | The key path is derived from the user's home. Reads check symlinks, regular-file status and permissions; creation is exclusive and permissions are secured before key bytes are written. |
| G304 in editor temp creation/read/zeroing | The files belong to a newly created private temporary directory outside the repo. The editor is a trusted local executable and cleanup enumerates regular entries. This is not a boundary against a malicious editor or another process running as the same user. |
| G304/G302 in `.gitignore` handling | The path comes from the selected worktree; symlink destinations are refused. `0644` is appropriate for public ignore rules, which contain no secret values. |
| G104 in production cleanup | The reported close/remove calls either follow an already-failed operation, close read-only input, or remove an obsolete updater backup. Primary write errors are returned; these findings do not turn failed writes into successful operations. Cleanup is best effort: failed deletion can leave owner-only key/plaintext files, and Windows rollback failure can leave the old executable at `.old`. They are not evidence of an untrusted-input exploit under the documented model. |

## Test findings

- G703/G304 paths come from `t.TempDir`, temporary test homes/worktrees, or
  explicitly gated helper subprocesses. The helper editor and helper child only
  exist in test binaries, not the shipped executable.
- G101 is the invented `API_KEY=abc123` / `DB_PASS=hunter2` round-trip fixture,
  not a credential used by any service.
- G301/G302/G306 modes describe public fixture files, executable test binaries,
  temporary directories, or deliberately loose permissions used to test
  rejection/tightening. Changing those modes just to satisfy the scanner would
  remove coverage.
- G204 runs fixed Git commands, the test executable, or the built CLI in test
  fixtures. It does not expose a production command interface.
- G104 covers fixture setup/cleanup, capture pipes, in-memory archive writers
  and local HTTP response writers. These are test robustness opportunities, not
  vulnerabilities in the distributed program.

## Reproduction

```sh
GOTOOLCHAIN=go1.26.10 just ci
GOTOOLCHAIN=go1.26.10 just vuln
go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -tests -fmt=json -out=/tmp/shenv-gosec.json ./...
```

Gosec is expected to continue reporting the reviewed intentional operations and
test fixtures. A nonzero scanner result is not equivalent to a failed test or a
new exploitable vulnerability; review new locations against the trust boundaries
in [security.md](security.md).
