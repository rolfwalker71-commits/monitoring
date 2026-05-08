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
$GithubRepo = if ($cfg.ContainsKey('GITHUB_REPO'))   { $cfg['GITHUB_REPO'] }   else { 'rolfwalker71-commits/monitoring' }
$RawBaseUrl = "https://raw.githubusercontent.com/$GithubRepo/main"
$GithubRawAltBaseUrl = "https://github.com/$GithubRepo/raw/refs/heads/main"

$wc = New-Object System.Net.WebClient
$wc.Headers['Accept'] = '*/*'
$wc.Headers['User-Agent'] = 'monitoring-agent-self-update'
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
if ($wc.Proxy) {
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

function Get-RepoUrlCandidates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = ($RelativePath -replace '\\', '/').TrimStart('/')
    $cacheBust = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    return @(
        ("{0}/{1}?cb={2}" -f $RawBaseUrl, $path, $cacheBust),
        ("{0}/{1}?raw=1&cb={2}" -f $GithubRawAltBaseUrl, $path, $cacheBust),
        ("{0}/{1}" -f $RawBaseUrl, $path),
        ("{0}/{1}?raw=1" -f $GithubRawAltBaseUrl, $path)
    )
}

function Test-DownloadedFileContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return $false
    }

    $text = ''
    try {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    } catch {
        return $false
    }

    if (-not $text) {
        return $false
    }

    # Guard against GitHub/proxy HTML pages being saved as .ps1/.txt content.
    if ($text -match '<!DOCTYPE\s+html|<html\b|<head\b|<body\b') {
        return $false
    }

    if ($RelativePath -ieq 'client/windows/collect_and_send.ps1') {
        return ($text -match '(?m)^#Requires\s+-Version\s+5\.1' -and $text -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
    }

    if ($RelativePath -ieq 'client/windows/self_update.ps1') {
        return ($text -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
    }

    if ($RelativePath -ieq 'AGENT_VERSION' -or $RelativePath -ieq 'BUILD_VERSION') {
        return ($text.Trim() -match '^\d+\.\d+\.\d+$')
    }

    return $true
}

function Download-RepoText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $attemptErrors = New-Object System.Collections.Generic.List[string]
    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue

    foreach ($url in (Get-RepoUrlCandidates -RelativePath $RelativePath)) {
        try {
            $txt = $wc.DownloadString($url)
            if ($txt) { return [string]$txt }
        } catch {
            $attemptErrors.Add("webclient: $url => $($_.Exception.Message)")
        }

        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ 'User-Agent' = 'monitoring-agent-self-update'; 'Accept' = '*/*' } -ErrorAction Stop
            $txt = [string]$resp.Content
            if ($txt) { return $txt }
        } catch {
            $attemptErrors.Add("iwr: $url => $($_.Exception.Message)")
        }

        if ($curl) {
            try {
                $result = & $curl.Source '--silent' '--show-error' '--fail' '--location' $url 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $txt = ($result | Out-String)
                    if ($txt) { return [string]$txt }
                }
                $attemptErrors.Add("curl($LASTEXITCODE): $url => $($result | Out-String)")
            } catch {
                $attemptErrors.Add("curl-exception: $url => $($_.Exception.Message)")
            }
        }
    }

    $global:LastDownloadRepoTextError = ($attemptErrors -join ' | ')
    return ''
}

function Download-RepoFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $attemptErrors = New-Object System.Collections.Generic.List[string]
    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue

    foreach ($url in (Get-RepoUrlCandidates -RelativePath $RelativePath)) {
        try {
            $wc.DownloadFile($url, $DestinationPath)
            if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
                return $true
            }
            $attemptErrors.Add("webclient-invalid-content: $url")
        } catch {
            $attemptErrors.Add("webclient: $url => $($_.Exception.Message)")
        }

        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ 'User-Agent' = 'monitoring-agent-self-update'; 'Accept' = '*/*' } -OutFile $DestinationPath -ErrorAction Stop | Out-Null
            if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
                return $true
            }
            $attemptErrors.Add("iwr-invalid-content: $url")
        } catch {
            $attemptErrors.Add("iwr: $url => $($_.Exception.Message)")
        }

        if ($curl) {
            try {
                $result = & $curl.Source '--silent' '--show-error' '--fail' '--location' '--output' $DestinationPath $url 2>&1
                if ($LASTEXITCODE -eq 0) {
                    if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
                        return $true
                    }
                    $attemptErrors.Add("curl-invalid-content: $url")
                }
                $attemptErrors.Add("curl($LASTEXITCODE): $url => $($result | Out-String)")
            } catch {
                $attemptErrors.Add("curl-exception: $url => $($_.Exception.Message)")
            }
        }
    }

    $global:LastDownloadRepoFileError = ($attemptErrors -join ' | ')
    return $false
}

# ---- Version check ----
$remoteVersion = ''
$remoteVersionSource = ''
$remoteVersion = (Download-RepoText -RelativePath 'AGENT_VERSION').Trim()
if ($remoteVersion) {
    $remoteVersionSource = 'AGENT_VERSION'
} else {
    $remoteVersion = (Download-RepoText -RelativePath 'BUILD_VERSION').Trim()
    if ($remoteVersion) { $remoteVersionSource = 'BUILD_VERSION' }
}
if (-not $remoteVersion) {
    $details = ''
    if ($global:LastDownloadRepoTextError) {
        $details = " Details: $($global:LastDownloadRepoTextError)"
    }
    Write-Error ("Remote version is empty; aborting update check." + $details)
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
        throw "Failed to download collect_and_send.ps1 from GitHub sources. Details: $global:LastDownloadRepoFileError"
    }
    # Guard against stale or incompatible script payloads before replacing local files.
    $collectContent = [System.IO.File]::ReadAllText("$tmpDir\collect_and_send.ps1", [System.Text.Encoding]::UTF8)
    if ($collectContent -match '\$[A-Za-z_][A-Za-z0-9_]*\s*\?\s*') {
        throw 'Downloaded collect_and_send.ps1 contains unsupported ternary syntax for PowerShell 5.1.'
    }

    [System.IO.File]::WriteAllText("$tmpDir\AGENT_VERSION", "$remoteVersion`n", [System.Text.Encoding]::UTF8)

    Copy-Item "$tmpDir\collect_and_send.ps1" "$InstallDir\collect_and_send.ps1" -Force
    Copy-Item "$tmpDir\AGENT_VERSION"        $VersionFile                       -Force
} finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (Compare-Versions -Newer $remoteVersion -Older $localVersion) {
    $ts = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    Write-Host "${ts} Monitoring agent updated from $localVersion to $remoteVersion"
}
