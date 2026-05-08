#Requires -Version 5.1
<#
.SYNOPSIS
    Checks for a newer version of the monitoring agent and updates in place.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enable TLS 1.2 for older Windows versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$ConfigFile  = if ($env:CONFIG_FILE)        { $env:CONFIG_FILE }        else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$VersionFile = if ($env:AGENT_VERSION_FILE) { $env:AGENT_VERSION_FILE } else { 'C:\ProgramData\monitoring-agent\AGENT_VERSION' }

if (-not (Test-Path $ConfigFile)) {
    Write-Error "Config file not found: $ConfigFile"
    exit 1
}

# Parse config
$cfg = @{}
foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    }
}

$InstallDir = if ($cfg.ContainsKey('INSTALL_DIR'))   { $cfg['INSTALL_DIR'] }   else { 'C:\ProgramData\monitoring-agent' }
$RawBaseUrl = if ($cfg.ContainsKey('RAW_BASE_URL'))  { $cfg['RAW_BASE_URL'] }  else { 'https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main' }
$GithubRepo = if ($cfg.ContainsKey('GITHUB_REPO'))   { $cfg['GITHUB_REPO'] }   else { 'rolfwalker71-commits/monitoring' }
$ApiBaseUrl = "https://api.github.com/repos/$GithubRepo/contents"
$DirectRawBaseUrl = "https://raw.githubusercontent.com/$GithubRepo/main"

$wc = New-Object System.Net.WebClient
$wc.Headers['Accept'] = 'application/vnd.github.v3.raw'
$wc.Headers['User-Agent'] = 'monitoring-agent-self-update'
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
if ($wc.Proxy) {
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

function Download-RepoFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $cacheBust = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    $attemptErrors = New-Object System.Collections.Generic.List[string]

    # Prefer GitHub contents API first (pinned to main) to reduce stale CDN payload risk.
    try {
        $wc.Headers['Accept'] = 'application/vnd.github.v3.raw'
        $wc.DownloadFile("$ApiBaseUrl/${RelativePath}?ref=main&cb=$cacheBust", $DestinationPath)
        return $true
    } catch {
        $attemptErrors.Add("api-main-cb: $($_.Exception.Message)")
    }

    # Fallback to raw URL (branch-pinned in RAW_BASE_URL), with cache-busting query.
    try {
        $wc.DownloadFile("$RawBaseUrl/${RelativePath}?cb=$cacheBust", $DestinationPath)
        return $true
    } catch {
        $attemptErrors.Add("raw-config-cb: $($_.Exception.Message)")
    }

    # Fallback to canonical raw.githubusercontent.com URL generated from GITHUB_REPO.
    try {
        $wc.DownloadFile("$DirectRawBaseUrl/${RelativePath}?cb=$cacheBust", $DestinationPath)
        return $true
    } catch {
        $attemptErrors.Add("raw-direct-cb: $($_.Exception.Message)")
    }

    # Fallback to GitHub contents API pinned to main to avoid default-branch drift.
    try {
        $wc.Headers['Accept'] = 'application/vnd.github.v3.raw'
        $wc.DownloadFile("$ApiBaseUrl/${RelativePath}?ref=main", $DestinationPath)
        return $true
    } catch {
        $attemptErrors.Add("api-main: $($_.Exception.Message)")
        $global:LastDownloadRepoFileError = ($attemptErrors -join ' | ')
        return $false
    }
}

# ---- Version check ----
$remoteVersion = ''
$remoteVersionSource = ''
try {
    $remoteVersion = ($wc.DownloadString("$RawBaseUrl/AGENT_VERSION?cb=$([System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())")).Trim()
    if ($remoteVersion) { $remoteVersionSource = 'AGENT_VERSION' }
} catch {
    $remoteVersion = ''
}
if (-not $remoteVersion) {
    try {
        $remoteVersion = ($wc.DownloadString("$ApiBaseUrl/AGENT_VERSION?ref=main")).Trim()
        if ($remoteVersion) { $remoteVersionSource = 'AGENT_VERSION' }
    } catch {
        $remoteVersion = ''
    }
}
if (-not $remoteVersion) {
    try {
        $remoteVersion = ($wc.DownloadString("$RawBaseUrl/BUILD_VERSION?cb=$([System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())")).Trim()
        if ($remoteVersion) { $remoteVersionSource = 'BUILD_VERSION' }
    } catch {
        $remoteVersion = ''
    }
}
if (-not $remoteVersion) {
    try {
        $remoteVersion = ($wc.DownloadString("$ApiBaseUrl/BUILD_VERSION?ref=main")).Trim()
        if ($remoteVersion) { $remoteVersionSource = 'BUILD_VERSION' }
    } catch {
        $remoteVersion = ''
    }
}
if (-not $remoteVersion) {
    Write-Error 'Remote version is empty; aborting update check.'
    exit 1
}

$localVersion = 'unknown'
if (Test-Path $VersionFile) {
    $localVersion = ((Get-Content $VersionFile -TotalCount 1 -Encoding UTF8) -replace '\s', '')
}

# ---- Version comparison: only proceed if remote is strictly newer ----
function Compare-Versions {
    param([string]$Newer, [string]$Older)
    if ($Newer -eq $Older) { return $false }
    try {
        $n = [System.Version]::new(($Newer -replace '[^0-9.]', ''))
        $o = [System.Version]::new(($Older -replace '[^0-9.]', ''))
        return $n -gt $o
    } catch {
        return $Newer -ne $Older
    }
}

# ---- Download to temp dir ----
$tmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    if (-not (Download-RepoFile -RelativePath 'client/windows/collect_and_send.ps1' -DestinationPath "$tmpDir\collect_and_send.ps1")) {
        throw "Failed to download collect_and_send.ps1 from API/raw sources. Details: $global:LastDownloadRepoFileError"
    }
    if (-not (Download-RepoFile -RelativePath 'client/windows/self_update.ps1' -DestinationPath "$tmpDir\self_update.ps1")) {
        throw "Failed to download self_update.ps1 from API/raw sources. Details: $global:LastDownloadRepoFileError"
    }
    # Guard against stale or incompatible script payloads before replacing local files.
    $collectContent = [System.IO.File]::ReadAllText("$tmpDir\collect_and_send.ps1", [System.Text.Encoding]::UTF8)
    if ($collectContent -match '\$[A-Za-z_][A-Za-z0-9_]*\s*\?\s*') {
        throw 'Downloaded collect_and_send.ps1 contains unsupported ternary syntax for PowerShell 5.1.'
    }

    # If AGENT_VERSION was resolved, enforce that downloaded collect script carries the same embedded version.
    if ($remoteVersionSource -eq 'AGENT_VERSION') {
        $embeddedVersion = ''
        if ($collectContent -match "`$EmbeddedAgentVersion\s*=\s*'([^']+)'") {
            $embeddedVersion = $Matches[1]
        }

        if (-not $embeddedVersion -or $embeddedVersion -ne $remoteVersion) {
            # Force one more refresh through the API path and validate again.
            $wc.Headers['Accept'] = 'application/vnd.github.v3.raw'
            $wc.DownloadFile("$ApiBaseUrl/client/windows/collect_and_send.ps1?ref=main&cb=$([System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())", "$tmpDir\collect_and_send.ps1")
            $collectContent = [System.IO.File]::ReadAllText("$tmpDir\collect_and_send.ps1", [System.Text.Encoding]::UTF8)
            $embeddedVersion = ''
            if ($collectContent -match "`$EmbeddedAgentVersion\s*=\s*'([^']+)'") {
                $embeddedVersion = $Matches[1]
            }

            if (-not $embeddedVersion -or $embeddedVersion -ne $remoteVersion) {
                throw "Downloaded collect_and_send.ps1 embedded version '$embeddedVersion' does not match remote AGENT_VERSION '$remoteVersion'."
            }
        }
    }

    [System.IO.File]::WriteAllText("$tmpDir\AGENT_VERSION", "$remoteVersion`n", [System.Text.Encoding]::UTF8)

    Copy-Item "$tmpDir\collect_and_send.ps1" "$InstallDir\collect_and_send.ps1" -Force
    Copy-Item "$tmpDir\self_update.ps1"      "$InstallDir\self_update.ps1"      -Force
    Copy-Item "$tmpDir\AGENT_VERSION"        $VersionFile                       -Force
} finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (Compare-Versions -Newer $remoteVersion -Older $localVersion) {
    $ts = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    Write-Host "${ts} Monitoring agent updated from $localVersion to $remoteVersion"
}
