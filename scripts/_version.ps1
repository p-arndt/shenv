# Shared version helpers, dot-sourced by set-version.ps1 and release.ps1.
# The repo-root VERSION file is the single source of truth for shenv's version.

$script:RepoRoot   = Split-Path -Parent $PSScriptRoot
$script:VersionFile = Join-Path $script:RepoRoot 'VERSION'

# Read the current version (e.g. "0.1.0") from the VERSION file.
function Get-CurrentVersion {
    (Get-Content $script:VersionFile -Raw).Trim()
}

# Resolve a bump keyword or an explicit version to a concrete x.y.z string.
#   Resolve-NextVersion '0.1.3' 'patch' -> '0.1.4'
#   Resolve-NextVersion '0.1.3' 'minor' -> '0.2.0'
#   Resolve-NextVersion '0.1.3' 'major' -> '1.0.0'
#   Resolve-NextVersion '0.1.3' '1.4.0' -> '1.4.0'  (explicit, may include -pre suffix)
function Resolve-NextVersion {
    param(
        [Parameter(Mandatory)][string]$Current,
        [Parameter(Mandatory)][string]$Bump
    )
    if ($Bump -notin @('patch', 'minor', 'major')) {
        if ($Bump -notmatch '^\d+\.\d+\.\d+') {
            throw "invalid version '$Bump' (expected patch|minor|major or x.y.z)"
        }
        return $Bump
    }
    if ($Current -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
        throw "current version '$Current' is not plain semver"
    }
    $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
    switch ($Bump) {
        'major' { $major++; $minor = 0; $patch = 0 }
        'minor' { $minor++; $patch = 0 }
        'patch' { $patch++ }
    }
    "$major.$minor.$patch"
}

# Write a version into the VERSION file (no trailing newline).
function Set-CurrentVersion {
    param([Parameter(Mandatory)][string]$Version)
    Set-Content -Path $script:VersionFile -Value $Version -NoNewline
}
