# shenv — task runner
#
# Install `just`:  winget install Casey.Just   (or  brew install just)
# List recipes:    just
#
# Shared recipes (build, test, fmt, ci, release, …) live in .just/, copied from
# ~/coding/just-common. Edit them there and run `just sync-common`; this file
# only holds what is specific to shenv.

import '.just/common.just'
import '.just/go.just'
import '.just/release.just'

set allow-duplicate-variables

BIN_NAME := "shenv"
BUILDINFO_PKG := "shenv/internal/buildinfo"
MAIN := "./cmd/shenv"

# Scan dependencies and the compiled-in stdlib for known advisories, pinned to
# the same govulncheck version CI gates on. Downloads the scanner on first run.
# Deliberately not in `ci`: it needs the network and the vuln database, so it
# would turn `just ci` into something that fails on a plane. CI runs it as its
# own job.

# Scan for known vulnerabilities.
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Builds shenv and runs it against a throwaway team in $TMPDIR (bare remote, two
# HOMEs, invented secrets), never your own key or repos. Needs vhs: brew install
# vhs.  just demo --keep  keeps the throwaway world for inspection.

# Re-record the README demo GIF -> assets/demo.gif.
[unix]
demo *ARGS:
    bash scripts/demo.sh {{ARGS}}
