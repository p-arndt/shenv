#!/usr/bin/env pwsh
# Stamp / bump the version in the repo-root VERSION file.
#
#   pwsh scripts/set-version.ps1 patch     # 0.1.3 -> 0.1.4
#   pwsh scripts/set-version.ps1 minor     # 0.1.3 -> 0.2.0
#   pwsh scripts/set-version.ps1 major     # 0.1.3 -> 1.0.0
#   pwsh scripts/set-version.ps1 1.4.0     # explicit version
#
# The version is injected into the binary at build time via -ldflags, so no
# source file needs editing — the VERSION file is the only thing stamped.

[CmdletBinding()]
param([string]$Bump = 'patch')

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_version.ps1')

$current = Get-CurrentVersion
$next    = Resolve-NextVersion -Current $current -Bump $Bump
Set-CurrentVersion -Version $next
Write-Host "Stamped version $next (was $current)."
