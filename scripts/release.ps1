#!/usr/bin/env pwsh
# Cut a release: bump the version, stamp it, commit, tag, and push.
# Pushing the tag triggers the "Build and Publish Release" GitHub Action.
#
#   pwsh scripts/release.ps1           # patch bump (default)
#   pwsh scripts/release.ps1 minor
#   pwsh scripts/release.ps1 major
#   pwsh scripts/release.ps1 1.4.0     # explicit version
#
# Safety: refuses to run on a dirty working tree (so the release commit holds
# only the version bump) and refuses to clobber an existing tag.

[CmdletBinding()]
param([string]$Bump = 'patch')

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_version.ps1')
Set-Location $script:RepoRoot

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments)][string[]]$Args)
    $out = & git @Args
    if ($LASTEXITCODE -ne 0) { throw "git $($Args -join ' ') failed" }
    $out
}

# 1. Clean tree — the release commit must contain only the version bump.
if (Invoke-Git status --porcelain) {
    throw 'working tree is not clean — commit or stash your changes first.'
}

# 2. Resolve the target version and make sure the tag is free BEFORE writing.
$current = Get-CurrentVersion
$next    = Resolve-NextVersion -Current $current -Bump $Bump
$tag     = "v$next"
if ((Invoke-Git tag --list) -split "`r?`n" | Where-Object { $_.Trim() -eq $tag }) {
    throw "tag $tag already exists."
}

Write-Host "Releasing $tag  ($current -> $next)`n"

# 3. Stamp the VERSION file.
Set-CurrentVersion -Version $next

# 4. Commit the bump — unless VERSION is already at the target (e.g. the very
#    first release, where the version is already in the file), in which case
#    there's nothing to commit and we simply tag the current HEAD.
& git diff --quiet -- VERSION
if ($LASTEXITCODE -ne 0) {
    Invoke-Git add VERSION | Out-Null
    Invoke-Git commit -m "release: $tag" | Out-Null
} else {
    Write-Host "VERSION already at $next — tagging the current commit."
}

# 5. Annotated tag on HEAD.
Invoke-Git tag -a $tag -m $tag | Out-Null

# 6. Push the current branch together with the new tag.
$branch = Invoke-Git rev-parse --abbrev-ref HEAD
Write-Host "`nPushing $branch + $tag ..."
Invoke-Git push origin $branch --follow-tags | Out-Null

Write-Host "`nDone. $tag pushed — the ""Build and Publish Release"" workflow is now running."
