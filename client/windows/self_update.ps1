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
$CanonicalServerUrl = 'https://infoboard.ang-schweiz.ch'
$SecondaryServerUrl = 'https://infoboard.an-group.work'
$LegacyServerUrl = 'https://monitoring.rolfwalker.ch'
$OriginalServerUrl = if ($cfg.ContainsKey('SERVER_URL')) { $cfg['SERVER_URL'] } else { '' }
$ConfiguredUpdateBaseUrl = if ($cfg.ContainsKey('UPDATE_BASE_URL')) { $cfg['UPDATE_BASE_URL'] } else { '' }
$LegacyRawBaseUrl = if ($cfg.ContainsKey('RAW_BASE_URL')) { $cfg['RAW_BASE_URL'] } else { '' }
$CanonicalUpdateBaseUrl = ($CanonicalServerUrl.TrimEnd('/')) + '/updates'
$SecondaryUpdateBaseUrl = ($SecondaryServerUrl.TrimEnd('/')) + '/updates'
$LegacyUpdateBaseUrl = ($LegacyServerUrl.TrimEnd('/')) + '/updates'

$UpdateBaseCandidates = New-Object System.Collections.Generic.List[string]
function Add-UpdateBaseCandidate {
    param([string]$Value)

    if (-not $Value) {
        return
    }

    $normalized = $Value.Trim().TrimEnd('/')
    if (-not $normalized) {
        return
    }

    foreach ($existing in $UpdateBaseCandidates) {
        if ($existing -ieq $normalized) {
            return
        }
    }

    $UpdateBaseCandidates.Add($normalized) | Out-Null
}

Add-UpdateBaseCandidate -Value $CanonicalUpdateBaseUrl
Add-UpdateBaseCandidate -Value $SecondaryUpdateBaseUrl
Add-UpdateBaseCandidate -Value $LegacyUpdateBaseUrl
if ($OriginalServerUrl) {
    Add-UpdateBaseCandidate -Value (($OriginalServerUrl.TrimEnd('/')) + '/updates')
}
Add-UpdateBaseCandidate -Value $ConfiguredUpdateBaseUrl
Add-UpdateBaseCandidate -Value $LegacyRawBaseUrl

$PrimaryUpdateBaseUrl = if ($UpdateBaseCandidates.Count -gt 0) { $UpdateBaseCandidates[0] } else { '' }

if (-not $PrimaryUpdateBaseUrl) {
    Write-Error "No update source configured. Set SERVER_URL or UPDATE_BASE_URL in agent.conf."
    exit 1
}

$wc = New-Object System.Net.WebClient
$wc.Headers['Accept'] = '*/*'
$wc.Headers['User-Agent'] = 'monitoring-agent-self-update'
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
if ($wc.Proxy) {
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

$global:UsedLocalFallback = $false
$global:LocalFallbackFiles = New-Object System.Collections.Generic.List[string]
$global:LastContentValidationHint = ''

function Get-RepoUrlCandidates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = ($RelativePath -replace '\\', '/').TrimStart('/')
    $cacheBust = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    $urls = @()
    foreach ($base in $UpdateBaseCandidates) {
        if (-not $base) {
            continue
        }
        $urls += @(
            ("{0}/{1}?cb={2}" -f $base, $path, $cacheBust),
            ("{0}/{1}" -f $base, $path)
        )
    }

    return @($urls | Select-Object -Unique)
}

function Get-UpdateBaseFromUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $cleanUrl = ($Url -split '\?')[0]
    $suffix = '/' + (($RelativePath -replace '\\', '/').TrimStart('/'))
    if ($cleanUrl.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $cleanUrl.Substring(0, $cleanUrl.Length - $suffix.Length).TrimEnd('/')
    }
    return ''
}

function Get-RepoZipUrlCandidates {
    return @()
}

function Get-RepoZipEntryText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$AttemptErrors
    )
    # Server-only mode: ZIP fallback disabled.
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

    $hint = ''
    if ($global:LastContentValidationHint) {
        $hint = " => $($global:LastContentValidationHint)"
    }
    $AttemptErrors.Add("zip-invalid-content: $RelativePath$hint")
    return $false
}

function Test-DownloadedFileContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $global:LastContentValidationHint = ''
    $global:LastSuccessfulUpdateBaseUrl = ''

    if (-not (Test-Path $Path)) {
        $global:LastContentValidationHint = 'downloaded file missing'
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
        $global:LastContentValidationHint = "read failed: $($_.Exception.Message)"
        return $false
    }

    if (-not $text) {
        $global:LastContentValidationHint = 'empty response body'
        return $false
    }

    # Strip NUL characters that can appear when content was transcoded unexpectedly.
    $text = $text -replace "`0", ''

    # Normalize BOM at start to avoid false negatives with strict line-anchored regex checks.
    $textNormalized = $text -replace '^[\uFEFF]+', ''
    $preview = ($textNormalized -replace '[\r\n\t]+', ' ').Trim()
    if ($preview.Length -gt 180) {
        $preview = $preview.Substring(0, 180)
    }

    if ($RelativePath -ieq 'client/windows/collect_and_send.ps1') {
        $strictHeaderOk = ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
        if ($strictHeaderOk) {
            return $true
        }
        # Fallback guard for proxied/transcoded content: rely on broad, non-line-anchored markers.
        if ($textNormalized.Length -lt 1000) {
            $global:LastContentValidationHint = "collect script header missing and response too short (len=$($textNormalized.Length)); preview='$preview'"
            return $false
        }
        $fallbackMarkerOk = ($textNormalized -match 'EmbeddedAgentVersion' -and $textNormalized -match 'Send-Payload' -and $textNormalized -match 'Invoke-ServerJsonPost' -and $textNormalized -match 'Collects system metrics')
        if (-not $fallbackMarkerOk) {
            $global:LastContentValidationHint = "collect script markers missing; preview='$preview'"
        }
        return $fallbackMarkerOk
    }

    # Guard against HTML pages being saved as scripts.
    # Only inspect the leading chunk to avoid false positives from literal regex strings inside valid scripts.
    $leadingChunk = $textNormalized
    if ($leadingChunk.Length -gt 2048) {
        $leadingChunk = $leadingChunk.Substring(0, 2048)
    }
    if ($leadingChunk -match '^\s*(<!DOCTYPE\s+html|<html\b|<head\b|<body\b)') {
        $global:LastContentValidationHint = "html-like response preview='$preview'"
        return $false
    }

    if ($RelativePath -ieq 'client/windows/collect_and_scan_sap_tables.ps1') {
        $ok = ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest')
        if (-not $ok) {
            $global:LastContentValidationHint = "sap scan script header mismatch; preview='$preview'"
        }
        return $ok
    }

    if ($RelativePath -ieq 'client/windows/self_update.ps1') {
        $ok = ($textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest' -and $textNormalized -match '(?m)^function\s+Download-RepoFile')
        if (-not $ok) {
            $global:LastContentValidationHint = "self_update script markers missing; preview='$preview'"
        }
        return $ok
    }

    if ($RelativePath -ieq 'client/windows/setup_harvest_sql_user.ps1') {
        $ok = (
            $textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -and
            $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest' -and
            $textNormalized -match '(?m)^function\s+Get-SqlServerCandidates' -and
            $textNormalized -match '(?m)^function\s+Invoke-SqlNonQuery'
        )
        if (-not $ok) {
            $global:LastContentValidationHint = "setup_harvest script markers missing; preview='$preview'"
        }
        return $ok
        }

    if ($RelativePath -ieq 'AGENT_VERSION' -or $RelativePath -ieq 'BUILD_VERSION') {
        $ok = ($textNormalized.Trim() -match '^\d+\.\d+\.\d+$')
        if (-not $ok) {
            $global:LastContentValidationHint = "version file has unexpected format: '$preview'"
        }
        return $ok
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
            if ($txt) {
                $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                return [string]$txt
            }
        } catch {
            $attemptErrors.Add("webclient: $url => $($_.Exception.Message)")
        }

        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ 'User-Agent' = 'monitoring-agent-self-update'; 'Accept' = '*/*' } -ErrorAction Stop
            $txt = [string]$resp.Content
            if ($txt) {
                $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                return $txt
            }
        } catch {
            $attemptErrors.Add("iwr: $url => $($_.Exception.Message)")
        }

        if ($curl) {
            try {
                $result = & $curl.Source '--silent' '--show-error' '--fail' '--location' $url 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $txt = ($result | Out-String)
                    if ($txt) {
                        $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                        if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                        return [string]$txt
                    }
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
                $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                return $true
            }
            $attemptErrors.Add("webclient-invalid-content: $url => $($global:LastContentValidationHint)")
        } catch {
            $attemptErrors.Add("webclient: $url => $($_.Exception.Message)")
        }

        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ 'User-Agent' = 'monitoring-agent-self-update'; 'Accept' = '*/*' } -OutFile $DestinationPath -ErrorAction Stop | Out-Null
            if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
                $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                return $true
            }
            $attemptErrors.Add("iwr-invalid-content: $url => $($global:LastContentValidationHint)")
        } catch {
            $attemptErrors.Add("iwr: $url => $($_.Exception.Message)")
        }

        if ($curl) {
            try {
                $result = & $curl.Source '--silent' '--show-error' '--fail' '--location' '--output' $DestinationPath $url 2>&1
                if ($LASTEXITCODE -eq 0) {
                    if (Test-DownloadedFileContent -RelativePath $RelativePath -Path $DestinationPath) {
                            $base = Get-UpdateBaseFromUrl -Url $url -RelativePath $RelativePath
                            if ($base) { $global:LastSuccessfulUpdateBaseUrl = $base }
                        return $true
                    }
                    $attemptErrors.Add("curl-invalid-content: $url => $($global:LastContentValidationHint)")
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

function Set-ConfigValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [AllowEmptyString()]
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $line = $Key + '="' + $Value + '"'
    $content = @()
    if (Test-Path $Path) {
        $content = Get-Content -Path $Path -Encoding UTF8
    }

    $pattern = '^\s*' + [Regex]::Escape($Key) + '\s*='
    $updated = $false
    $newContent = foreach ($existing in $content) {
        if (-not $updated -and $existing -match $pattern) {
            $updated = $true
            $line
        } else {
            $existing
        }
    }

    if (-not $updated) {
        $newContent += $line
    }

    [System.IO.File]::WriteAllLines($Path, $newContent, [System.Text.Encoding]::UTF8)
}

function Test-ServerUrlReachable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerUrl
    )

    if (-not $ServerUrl) {
        return $false
    }

    $probeUrl = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-commands'
    try {
        Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -Method Get -TimeoutSec 12 -Headers @{ 'User-Agent' = 'monitoring-agent-self-update'; 'Accept' = '*/*' } -ErrorAction Stop | Out-Null
        return $true
    } catch {
        if ($_.Exception -and $_.Exception.Response) {
            return $true
        }
    }

    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if ($curl) {
        try {
            $null = & $curl.Source '--silent' '--show-error' '--location' '--connect-timeout' '10' '--max-time' '20' '--output' 'NUL' $probeUrl 2>&1
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
        } catch {
            return $false
        }
    }

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

    $effectiveUpdateBaseUrl = if ($global:LastSuccessfulUpdateBaseUrl) { $global:LastSuccessfulUpdateBaseUrl } else { $PrimaryUpdateBaseUrl }
    $normalizedServerUrl = $OriginalServerUrl
    if ($effectiveUpdateBaseUrl -ieq $CanonicalUpdateBaseUrl) {
        if (Test-ServerUrlReachable -ServerUrl $CanonicalServerUrl) {
            $normalizedServerUrl = $CanonicalServerUrl
        } else {
            Write-Warning "Canonical server unreachable from host, keeping current SERVER_URL: $CanonicalServerUrl"
        }
    } elseif ($effectiveUpdateBaseUrl -match '/updates$') {
        $normalizedServerUrl = $effectiveUpdateBaseUrl.Substring(0, $effectiveUpdateBaseUrl.Length - '/updates'.Length)
    }
    if ($normalizedServerUrl) {
        Set-ConfigValue -Path $ConfigFile -Key 'SERVER_URL' -Value $normalizedServerUrl
    }
    if ($effectiveUpdateBaseUrl) {
        Set-ConfigValue -Path $ConfigFile -Key 'UPDATE_BASE_URL' -Value $effectiveUpdateBaseUrl
        Set-ConfigValue -Path $ConfigFile -Key 'RAW_BASE_URL' -Value $effectiveUpdateBaseUrl
    }
    Set-ConfigValue -Path $ConfigFile -Key 'GITHUB_REPO' -Value ''
} finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (Compare-Versions -Newer $remoteVersion -Older $localVersion) {
    $ts = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    Write-Host "${ts} Monitoring agent updated from $localVersion to $remoteVersion"
}
