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

$wc = New-Object System.Net.WebClient

# ---- Version check ----
$remoteVersion = ($wc.DownloadString("$RawBaseUrl/BUILD_VERSION")).Trim()
if (-not $remoteVersion) {
    Write-Error 'Remote version is empty; aborting update check.'
    exit 1
}

$localVersion = 'unknown'
if (Test-Path $VersionFile) {
    $localVersion = ((Get-Content $VersionFile -TotalCount 1 -Encoding UTF8) -replace '\s', '')
}

if ($remoteVersion -eq $localVersion) {
    Write-Host "Monitoring agent already up to date: $localVersion"
    exit 0
}

Write-Host "Updating from $localVersion to $remoteVersion..."

# ---- Download to temp dir ----
$tmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    $wc.DownloadFile("$RawBaseUrl/client/windows/collect_and_send.ps1", "$tmpDir\collect_and_send.ps1")
    $wc.DownloadFile("$RawBaseUrl/client/windows/self_update.ps1",      "$tmpDir\self_update.ps1")
    [System.IO.File]::WriteAllText("$tmpDir\AGENT_VERSION", "$remoteVersion`n", [System.Text.Encoding]::UTF8)

    Copy-Item "$tmpDir\collect_and_send.ps1" "$InstallDir\collect_and_send.ps1" -Force
    Copy-Item "$tmpDir\self_update.ps1"      "$InstallDir\self_update.ps1"      -Force
    Copy-Item "$tmpDir\AGENT_VERSION"        $VersionFile                       -Force
} finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Monitoring agent updated from $localVersion to $remoteVersion"
