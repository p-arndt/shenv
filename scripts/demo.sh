#!/usr/bin/env bash
# Records the README demo: assets/demo.gif.
#
# It builds shenv and stands up a throwaway world in $TMPDIR: a bare git remote,
# bob's work tree, alice's clone, and a separate HOME for each of them. Nothing
# real is involved — the secrets, the team and both keypairs are invented, and
# shenv runs against HOMEs of its own, so the user's ~/.shenv key, their real
# repos and their OS keychain are never touched.
#
#   bash scripts/demo.sh           # record
#   bash scripts/demo.sh --keep    # keep the throwaway world for inspection
#
# Requires: go, vhs, git.  (brew install vhs)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="${TMPDIR:-/tmp}/shenv-demo"
keep=0
[ "${1:-}" = "--keep" ] && keep=1

for bin in go vhs git; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }
done

# shenv prompts for a passphrase on keygen and reads it straight from the tty, so
# seeding alice's identity needs a pty even though nobody is watching. BSD and GNU
# `script` disagree on argument order.
# Detected from uname rather than by probing: a probe run of `script` would eat the
# piped-in newline that answers the passphrase prompt, and keygen would hang forever.
pty() {
  if [ "$(uname -s)" = "Linux" ]; then
    script -qec "$(printf '%q ' "$@")" /dev/null
  else
    script -q /dev/null "$@"
  fi
}

echo "==> building shenv"
rm -rf "$root"
mkdir -p "$root/bin"
( cd "$repo" && go build -o "$root/bin/shenv" ./cmd/shenv )
shenv="$root/bin/shenv"

echo "==> standing up a throwaway team"
for who in bob alice; do
  mkdir -p "$root/$who-home"
  cat > "$root/$who-home/.gitconfig" <<CFG
[user]
	name = $who
	email = $who@example.com
[init]
	defaultBranch = main
[advice]
	detachedHead = false
CFG
done

git init -q --bare -b main "$root/remote.git"
git clone -q "$root/remote.git" "$root/api"
(
  cd "$root/api"
  printf '# api\n\nThe example service used by the shenv demo.\n' > README.md
  git -c user.name=bob -c user.email=bob@example.com add -A
  git -c user.name=bob -c user.email=bob@example.com commit -qm "initial commit"
  git push -q origin main
)
git clone -q "$root/remote.git" "$root/clone"

# The secrets on screen. Invented — and deliberately shaped so that no scanner can
# mistake them for real ones. A convincing `sk_live_` followed by 24 alphanumerics is
# exactly Stripe's published key pattern, so GitHub push protection rejects the whole
# repository even though the value is meaningless. Underscores break the run and keep
# the line readable. Do not "improve" these back into realistic-looking keys.
cat > "$root/api/.env" <<'ENV'
DATABASE_URL=postgres://api:hunter2@db.internal:5432/api
STRIPE_SECRET_KEY=sk_live_EXAMPLE_ONLY_not_a_real_key
SESSION_SECRET=example_only_not_a_real_session_secret
ENV

echo "==> seeding alice's identity"
printf '\n\n' | HOME="$root/alice-home" pty "$shenv" keygen >/dev/null 2>&1 || true
HOME="$root/alice-home" pty "$shenv" whoami </dev/null 2>/dev/null \
  | tr -d '\r' | sed $'s/\033\\[[0-9;]*m//g' > "$root/alice-whoami.txt"

add_line="$(grep -o 'shenv add-member .*' "$root/alice-whoami.txt" | head -1)"
[ -n "$add_line" ] || { echo "could not read alice's keys" >&2; exit 1; }

# The tape pastes alice's add-member line, so the demo shows exactly what `shenv
# whoami` tells you to copy. Her keys are generated fresh every run, so the line cannot
# live in the tape — it is written out here as a Copy instruction and pulled in with
# `Source`. Generated, not committed: a fixed keypair in the repo would look like a
# leaked one.
#
# Note: VHS `Copy` writes to the real system clipboard, so recording replaces whatever
# you had on it.
printf 'Copy "%s"\n' "$add_line" > "$repo/demo/.add-member.tape"
if ! grep -qxF 'demo/.add-member.tape' "$repo/.gitignore" 2>/dev/null; then
  printf 'demo/.add-member.tape\n' >> "$repo/.gitignore"
fi

echo "==> recording"
cd "$repo"
# `Require shenv` in the tape is checked against vhs's own PATH, before any
# shell exists to source demo/setup.sh — so the built binary has to be here too.
export PATH="$root/bin:$PATH"
DEMO_ROOT="$root" DEMO_SETUP="$repo/demo/setup.sh" vhs demo/shenv.tape

if [ "$keep" = "1" ]; then
  echo "==> kept: $root"
else
  rm -rf "$root"
fi
echo "==> assets/demo.gif"
