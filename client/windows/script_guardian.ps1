#Requires -Version 5.1
<#
.SYNOPSIS
    Script guardian: refreshes collect_and_send, self_update, and AGENT_VERSION from /updates only.
    Does not update itself. Default interval: 125 minutes (scheduled task).
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$ConfigFile = if ($env:CONFIG_FILE) { $env:CONFIG_FILE } else { 'C:\ProgramData\monitoring-agent\agent.conf' }
if (-not (Test-Path -LiteralPath $ConfigFile)) {
    Write-Error "Config file not found: $ConfigFile"
    exit 1
}

$cfg = @{}
foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    }
}

$InstallDir = if ($cfg.ContainsKey('INSTALL_DIR')) { $cfg['INSTALL_DIR'] } else { 'C:\ProgramData\monitoring-agent' }
$VersionFile = if ($cfg.ContainsKey('AGENT_VERSION_FILE')) { $cfg['AGENT_VERSION_FILE'] } else { Join-Path $InstallDir 'AGENT_VERSION' }
$GuardianLogFile = if ($cfg.ContainsKey('GUARDIAN_LOG_FILE')) { $cfg['GUARDIAN_LOG_FILE'] } else { Join-Path $InstallDir 'monitoring-agent-guardian.log' }
$LockFile = Join-Path $InstallDir '.script_guardian.lock'
$LastRunFile = Join-Path $InstallDir '.script_guardian_last_run_epoch'

$IntervalMinutes = 125
if ($cfg.ContainsKey('SCRIPT_GUARDIAN_INTERVAL_MINUTES')) {
    try {
        $parsed = [int]$cfg['SCRIPT_GUARDIAN_INTERVAL_MINUTES']
        if ($parsed -ge 30 -and $parsed -le 720) {
            $IntervalMinutes = $parsed
        }
    } catch { }
}

$CanonicalUpdateBaseUrl = 'https://infoboard.ang-schweiz.ch/updates'
$SecondaryUpdateBaseUrl = 'https://infoboard.an-group.work/updates'
$LegacyUpdateBaseUrl = 'https://monitoring.rolfwalker.ch/updates'
$UpdateBaseCandidates = New-Object System.Collections.Generic.List[string]

function Add-UpdateBaseCandidate {
    param([string]$Value)
    if (-not $Value) { return }
    $normalized = $Value.Trim().TrimEnd('/')
    if (-not $normalized) { return }
    foreach ($existing in $UpdateBaseCandidates) {
        if ($existing -ieq $normalized) { return }
    }
    [void]$UpdateBaseCandidates.Add($normalized)
}

Add-UpdateBaseCandidate -Value $CanonicalUpdateBaseUrl
Add-UpdateBaseCandidate -Value $SecondaryUpdateBaseUrl
Add-UpdateBaseCandidate -Value $LegacyUpdateBaseUrl
if ($cfg.ContainsKey('SERVER_URL') -and $cfg['SERVER_URL']) {
    Add-UpdateBaseCandidate -Value (($cfg['SERVER_URL'].TrimEnd('/')) + '/updates')
}
if ($cfg.ContainsKey('UPDATE_BASE_URL')) { Add-UpdateBaseCandidate -Value $cfg['UPDATE_BASE_URL'] }
if ($cfg.ContainsKey('RAW_BASE_URL')) { Add-UpdateBaseCandidate -Value $cfg['RAW_BASE_URL'] }

function Write-GuardianLog {
    param([string]$Message)
    $ts = (Get-Date).ToString('dd.MM.yyyy HH:mm:ss')
    Add-Content -Path $GuardianLogFile -Value "${ts} ${Message}" -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Test-VersionString {
    param([string]$Value)
    return ($Value -match '^[0-9]+\.[0-9]+\.[0-9]+')
}

function Test-PowerShellScriptParses {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $errors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    return ($null -eq $errors -or $errors.Count -eq 0)
}

function Test-CollectScriptSafeToInstall {
    param([string]$Path)
    if (-not (Test-PowerShellScriptParses -Path $Path)) { return $false }
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($text.Length -lt 20000) { return $false }
    if ($text -notmatch 'agent-report') { return $false }
    if ($text -notmatch 'function\s+Resolve-CollectAndSendCliArgs') { return $false }
    return $true
}

function Test-SelfUpdateScriptSafeToInstall {
    param([string]$Path)
    if (-not (Test-PowerShellScriptParses -Path $Path)) { return $false }
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($text.Length -lt 1500) { return $false }
    if ($text -notmatch 'self_update') { return $false }
    return $true
}

function Compare-Versions {
    param([string]$Newer, [string]$Older)
    try {
        return ([version]$Newer -gt [version]$Older)
    } catch {
        return ($Newer -ne $Older)
    }
}

function Should-SkipInterval {
    if (-not (Test-Path -LiteralPath $LastRunFile)) { return $false }
    $lastText = (Get-Content -Path $LastRunFile -TotalCount 1 -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $lastText -or $lastText -notmatch '^\d+$') { return $false }
    $last = [long]$lastText
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    return (($now - $last) -lt ($IntervalMinutes * 60))
}

function Download-UpdateFile {
    param(
        [string]$RelativePath,
        [string]$DestinationPath
    )

    $wc = New-Object System.Net.WebClient
    foreach ($base in $UpdateBaseCandidates) {
        $url = "$base/$RelativePath"
        try {
            $wc.DownloadFile($url, $DestinationPath)
            return $base
        } catch {
            continue
        }
    }
    return ''
}

if (Should-SkipInterval) {
    exit 0
}

$lockStream = $null
try {
    $lockStream = [System.IO.File]::Open($LockFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
} catch {
    Write-GuardianLog 'SKIP lock busy'
    exit 0
}

if (Should-SkipInterval) {
    $lockStream.Dispose()
    exit 0
}

Write-GuardianLog "START interval=${IntervalMinutes}min install_dir=$InstallDir"

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('monitoring-guardian-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    $selectedBase = Download-UpdateFile -RelativePath 'client/windows/collect_and_send.ps1' -DestinationPath (Join-Path $tmpDir 'collect_and_send.ps1')
    if (-not $selectedBase) {
        Write-GuardianLog 'FAIL collect_and_send download'
        exit 1
    }
    if (-not (Test-CollectScriptSafeToInstall -Path (Join-Path $tmpDir 'collect_and_send.ps1'))) {
        Write-GuardianLog 'FAIL collect_and_send validation; keeping local files'
        exit 1
    }

    if (-not (Download-UpdateFile -RelativePath 'client/windows/self_update.ps1' -DestinationPath (Join-Path $tmpDir 'self_update.ps1'))) {
        Write-GuardianLog 'FAIL self_update download'
        exit 1
    }
    if (-not (Test-SelfUpdateScriptSafeToInstall -Path (Join-Path $tmpDir 'self_update.ps1'))) {
        Write-GuardianLog 'FAIL self_update validation; keeping local files'
        exit 1
    }

    $versionPath = Join-Path $tmpDir 'AGENT_VERSION'
    if (-not (Download-UpdateFile -RelativePath 'AGENT_VERSION' -DestinationPath $versionPath)) {
        if (-not (Download-UpdateFile -RelativePath 'BUILD_VERSION' -DestinationPath $versionPath)) {
            Write-GuardianLog 'FAIL AGENT_VERSION download'
            exit 1
        }
    }
    $remoteVersion = ([System.IO.File]::ReadAllText($versionPath, [System.Text.Encoding]::UTF8)).Trim()
    if (-not (Test-VersionString -Value $remoteVersion)) {
        Write-GuardianLog 'FAIL AGENT_VERSION invalid; keeping local files'
        exit 1
    }

    $localVersion = 'unknown'
    if (Test-Path -LiteralPath $VersionFile) {
        $localVersion = ([System.IO.File]::ReadAllText($VersionFile, [System.Text.Encoding]::UTF8)).Trim()
        if (-not $localVersion) { $localVersion = 'unknown' }
    }

    $collectDest = Join-Path $InstallDir 'collect_and_send.ps1'
    $updateDest = Join-Path $InstallDir 'self_update.ps1'
    $collectNew = "$collectDest.guardian.new"
    $updateNew = "$updateDest.guardian.new"
    $versionNew = "$VersionFile.guardian.new"

    Copy-Item (Join-Path $tmpDir 'collect_and_send.ps1') $collectNew -Force
    Copy-Item (Join-Path $tmpDir 'self_update.ps1') $updateNew -Force
    Copy-Item $versionPath $versionNew -Force
    Move-Item -Force $collectNew $collectDest
    Move-Item -Force $updateNew $updateDest
    Move-Item -Force $versionNew $VersionFile

    [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() | Set-Content -Path $LastRunFile -Encoding ASCII -NoNewline

    if ((Test-VersionString -Value $localVersion) -and (Compare-Versions -Newer $remoteVersion -Older $localVersion)) {
        Write-GuardianLog "OK refreshed scripts; AGENT_VERSION $localVersion -> $remoteVersion (source: $selectedBase)"
    } elseif ($remoteVersion -eq $localVersion) {
        Write-GuardianLog "OK refreshed scripts; version unchanged ($remoteVersion)"
    } else {
        Write-GuardianLog "OK refreshed scripts; version file now $remoteVersion (was $localVersion)"
    }
} finally {
    if ($lockStream) { $lockStream.Dispose() }
    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
