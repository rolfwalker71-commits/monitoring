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
$ServerUrl = if ($cfg.ContainsKey('SERVER_URL')) { $cfg['SERVER_URL'] } else { '' }
$ConfiguredUpdateBaseUrl = if ($cfg.ContainsKey('UPDATE_BASE_URL')) { $cfg['UPDATE_BASE_URL'] } else { '' }
$LegacyRawBaseUrl = if ($cfg.ContainsKey('RAW_BASE_URL')) { $cfg['RAW_BASE_URL'] } else { '' }
$PrimaryUpdateBaseUrl = if ($ConfiguredUpdateBaseUrl) { $ConfiguredUpdateBaseUrl.TrimEnd('/') } elseif ($ServerUrl) { ($ServerUrl.TrimEnd('/')) + '/updates' } elseif ($LegacyRawBaseUrl) { $LegacyRawBaseUrl.TrimEnd('/') } else { '' }
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

$global:UsedLocalFallback = $false
$global:LocalFallbackFiles = New-Object System.Collections.Generic.List[string]

function Get-RepoUrlCandidates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = ($RelativePath -replace '\\', '/').TrimStart('/')
    $cacheBust = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    $urls = @()
    if ($PrimaryUpdateBaseUrl) {
        $urls += @(
            ("{0}/{1}?cb={2}" -f $PrimaryUpdateBaseUrl, $path, $cacheBust),
            ("{0}/{1}" -f $PrimaryUpdateBaseUrl, $path)
        )
    }
    $urls += @(
        ("{0}/{1}?cb={2}" -f $RawBaseUrl, $path, $cacheBust),
        ("{0}/{1}?raw=1&cb={2}" -f $GithubRawAltBaseUrl, $path, $cacheBust),
        ("{0}/{1}" -f $RawBaseUrl, $path),
        ("{0}/{1}?raw=1" -f $GithubRawAltBaseUrl, $path)
    )

    return @($urls | Select-Object -Unique)
}

function Get-RepoZipUrlCandidates {
    $cacheBust = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    return @(
        ("https://codeload.github.com/{0}/zip/refs/heads/main?cb={1}" -f $GithubRepo, $cacheBust),
        ("https://github.com/{0}/archive/refs/heads/main.zip?cb={1}" -f $GithubRepo, $cacheBust),
        ("https://codeload.github.com/{0}/zip/refs/heads/main" -f $GithubRepo),
        ("https://github.com/{0}/archive/refs/heads/main.zip" -f $GithubRepo)
    )
}

function Get-RepoZipEntryText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$AttemptErrors
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $repoName = ($GithubRepo -split '/')[-1]
    $entryPath = ('{0}-main/{1}' -f $repoName, (($RelativePath -replace '\\', '/').TrimStart('/')))
    $tmpZipPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('monitoring-updater-{0}.zip' -f [System.Guid]::NewGuid().ToString('N')))

    foreach ($url in (Get-RepoZipUrlCandidates)) {
        try {
            $wc.DownloadFile($url, $tmpZipPath)
        } catch {
            $AttemptErrors.Add("zip-webclient: $url => $($_.Exception.Message)")
            continue
        }

        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($tmpZipPath)
            try {
                $entry = $zip.GetEntry($entryPath)
                if (-not $entry) {
                    $AttemptErrors.Add("zip-entry-missing: $url => $entryPath")
                    continue
                }
                $reader = New-Object System.IO.StreamReader($entry.Open(), $true)
                try {
                    $text = $reader.ReadToEnd()
                } finally {
                    $reader.Dispose()
                }
                if ($text) {
                    return [string]$text
                }
                $AttemptErrors.Add("zip-empty-content: $url => $entryPath")
            } finally {
                $zip.Dispose()
            }
        } catch {
            $AttemptErrors.Add("zip-read: $url => $($_.Exception.Message)")
        } finally {
            Remove-Item $tmpZipPath -Force -ErrorAction SilentlyContinue
        }
    }

    return ''
}

function Download-RepoFileViaZip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$AttemptErrors
    )

    $text = Get-RepoZipEntryText -RelativePath $RelativePath -AttemptErrors $AttemptErrors
    if (-not $text) {
        return $false
    }

    try {
        [System.IO.File]::WriteAllText($DestinationPath, $text, [System.Text.Encoding]::UTF8)
    } catch {
        $AttemptErrors.Add("zip-write: $RelativePath => $($_.Exception.Message)")
        return $false
    }

    if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
        return $true
    }

    $AttemptErrors.Add("zip-invalid-content: $RelativePath")
    return $false
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
        $reader = New-Object System.IO.StreamReader($Path, $true)
        try {
            $text = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } catch {
        return $false
    }

    if (-not $text) {
        return $false
    }

    # Strip NUL characters that can appear when content was transcoded unexpectedly.
    $text = $text -replace "`0", ''

    # Normalize BOM at start to avoid false negatives with strict line-anchored regex checks.
    $textNormalized = $text -replace '^[\uFEFF]+', ''

    # Guard against GitHub/proxy HTML pages being saved as .ps1/.txt content.
    if ($textNormalized -match '<!DOCTYPE\s+html|<html\b|<head\b|<body\b') {
        return $false
    }

    if ($RelativePath -ieq 'client/windows/collect_and_send.ps1') {
        $strictHeaderOk = ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
        if ($strictHeaderOk) {
            return $true
        }
        # Fallback guard for proxied/transcoded content: rely on broad, non-line-anchored markers.
        if ($textNormalized.Length -lt 1000) {
            return $false
        }
        return ($textNormalized -match 'EmbeddedAgentVersion' -and $textNormalized -match 'Send-Payload' -and $textNormalized -match 'Invoke-ServerJsonPost' -and $textNormalized -match 'Collects system metrics')
    }

    if ($RelativePath -ieq 'client/windows/collect_and_scan_sap_tables.ps1') {
        return ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
    }

    if ($RelativePath -ieq 'client/windows/self_update.ps1') {
        return ($textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest' -and $textNormalized -match '(?m)^function\s+Download-RepoFile')
    }

    if ($RelativePath -ieq 'client/windows/setup_harvest_sql_user.ps1') {
        return ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and $textNormalized -match 'Find-SqlServers')
        }

    if ($RelativePath -ieq 'AGENT_VERSION' -or $RelativePath -ieq 'BUILD_VERSION') {
        return ($textNormalized.Trim() -match '^\d+\.\d+\.\d+$')
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

    $zipText = Get-RepoZipEntryText -RelativePath $RelativePath -AttemptErrors $attemptErrors
    if ($zipText) {
        return [string]$zipText
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

    if (Download-RepoFileViaZip -RelativePath $RelativePath -DestinationPath $DestinationPath -AttemptErrors $attemptErrors) {
        return $true
    }

    $global:LastDownloadRepoFileError = ($attemptErrors -join ' | ')
    return $false
}

function Use-LocalScriptFallback {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $leaf = [System.IO.Path]::GetFileName($RelativePath)
    $installedPath = Join-Path $InstallDir $leaf
    if (-not (Test-Path $installedPath)) {
        return $false
    }

    if (-not (Test-DownloadedFileContent -RelativePath $RelativePath -Path $installedPath)) {
        return $false
    }

    Copy-Item $installedPath $DestinationPath -Force
    $global:UsedLocalFallback = $true
    $global:LocalFallbackFiles.Add($leaf) | Out-Null
    $details = ''
    if ($global:LastDownloadRepoFileError) {
        $details = " Details: $($global:LastDownloadRepoFileError)"
    }
    Write-Warning "Using local fallback for $leaf because remote download was blocked/invalid.$details"
    return $true
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
        if (-not (Use-LocalScriptFallback -RelativePath 'client/windows/collect_and_send.ps1' -DestinationPath "$tmpDir\collect_and_send.ps1")) {
            throw "Failed to download collect_and_send.ps1 from configured update sources. Details: $global:LastDownloadRepoFileError"
        }
    }
    if (-not (Download-RepoFile -RelativePath 'client/windows/collect_and_scan_sap_tables.ps1' -DestinationPath "$tmpDir\collect_and_scan_sap_tables.ps1")) {
        if (-not (Use-LocalScriptFallback -RelativePath 'client/windows/collect_and_scan_sap_tables.ps1' -DestinationPath "$tmpDir\collect_and_scan_sap_tables.ps1")) {
            throw "Failed to download collect_and_scan_sap_tables.ps1 from configured update sources. Details: $global:LastDownloadRepoFileError"
        }
    }
    if (-not (Download-RepoFile -RelativePath 'client/windows/setup_harvest_sql_user.ps1' -DestinationPath "$tmpDir\setup_harvest_sql_user.ps1")) {
        if (-not (Use-LocalScriptFallback -RelativePath 'client/windows/setup_harvest_sql_user.ps1' -DestinationPath "$tmpDir\setup_harvest_sql_user.ps1")) {
            throw "Failed to download setup_harvest_sql_user.ps1 from configured update sources. Details: $global:LastDownloadRepoFileError"
        }
    }
    # Guard against stale or incompatible script payloads before replacing local files.
    $collectContent = [System.IO.File]::ReadAllText("$tmpDir\collect_and_send.ps1", [System.Text.Encoding]::UTF8)
    if ($collectContent -match '\$[A-Za-z_][A-Za-z0-9_]*\s*\?\s*') {
        throw 'Downloaded collect_and_send.ps1 contains unsupported ternary syntax for PowerShell 5.1.'
    }

    if ((Compare-Versions -Newer $remoteVersion -Older $localVersion) -and $global:UsedLocalFallback) {
        $fallbackFiles = 'unknown'
        if ($global:LocalFallbackFiles.Count -gt 0) {
            $fallbackFiles = ($global:LocalFallbackFiles | Select-Object -Unique) -join ', '
        }
        $details = ''
        if ($global:LastDownloadRepoFileError) {
            $details = " Details: $($global:LastDownloadRepoFileError)"
        }
        throw "Remote download blocked/invalid for: $fallbackFiles. Refusing to mark version upgrade to $remoteVersion with local fallback content.$details"
    }

    [System.IO.File]::WriteAllText("$tmpDir\AGENT_VERSION", "$remoteVersion`n", [System.Text.Encoding]::UTF8)

    Copy-Item "$tmpDir\collect_and_send.ps1" "$InstallDir\collect_and_send.ps1" -Force
    Copy-Item "$tmpDir\collect_and_scan_sap_tables.ps1" "$InstallDir\collect_and_scan_sap_tables.ps1" -Force
    Copy-Item "$tmpDir\setup_harvest_sql_user.ps1" "$InstallDir\setup_harvest_sql_user.ps1" -Force
    Copy-Item "$tmpDir\AGENT_VERSION"        $VersionFile                       -Force
} finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (Compare-Versions -Newer $remoteVersion -Older $localVersion) {
    $ts = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    Write-Host "${ts} Monitoring agent updated from $localVersion to $remoteVersion"
}
