#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Repairs or bootstraps the Windows monitoring agent from the configured server.

.DESCRIPTION
    - Existing installs: refresh core scripts in place without overwriting the current config.
    - New installs or missing scheduled tasks: run the latest install_agent.ps1 from /updates.
    - Optional -DisableJitter suppresses send jitter only for this one run.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap_agent.ps1 -ServerUrl https://infoboard.ang-schweiz.ch -DisableJitter
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'https://infoboard.ang-schweiz.ch',

    [Parameter(Mandatory = $false)]
    [switch]$DisableJitter,

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = 'C:\ProgramData\monitoring-agent'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$IC = [System.Globalization.CultureInfo]::InvariantCulture
$ServerUrl = $ServerUrl.TrimEnd('/')
$UpdateBaseUrl = $ServerUrl + '/updates'
$ConfigFile = Join-Path $InstallDir 'agent.conf'
$VersionFile = Join-Path $InstallDir 'AGENT_VERSION'

function Read-AgentConfig {
    param([string]$Path)

    $values = @{}
    if (-not (Test-Path $Path)) {
        return $values
    }

    foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
            $values[$Matches[1]] = $Matches[2]
        } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
            $values[$Matches[1]] = $Matches[2]
        }
    }

    return $values
}

function Set-ConfigValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updatedLines = @()
    $updated = $false

    if (Test-Path $Path) {
        foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
            if ($line -match $pattern) {
                $updatedLines += ($Key + '="' + $Value + '"')
                $updated = $true
            } else {
                $updatedLines += $line
            }
        }
    }

    if (-not $updated) {
        $updatedLines += ($Key + '="' + $Value + '"')
    }

    [System.IO.File]::WriteAllLines($Path, $updatedLines, [System.Text.Encoding]::UTF8)
}

function Get-ConfigValue {
    param(
        [hashtable]$Config,
        [string]$Key,
        [string]$Default = ''
    )

    if ($Config.ContainsKey($Key) -and $Config[$Key]) {
        return [string]$Config[$Key]
    }
    return $Default
}

function Get-ConfigIntValue {
    param(
        [hashtable]$Config,
        [string]$Key,
        [int]$Default
    )

    $raw = Get-ConfigValue -Config $Config -Key $Key -Default ''
    if ($raw -match '^\d+$') {
        return [int]$raw
    }
    return $Default
}

function Download-FileBestEffort {
    param(
        [string]$Url,
        [string]$Destination
    )

    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Destination)
        return $true
    } catch { }

    try {
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $Destination -ErrorAction Stop | Out-Null
        return $true
    } catch { }

    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if ($curl) {
        try {
            $null = & $curl.Source '--silent' '--show-error' '--fail' '--location' '--ssl-no-revoke' '--output' $Destination $Url 2>&1
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
        } catch { }
    }

    return $false
}

function Download-FileFromCandidates {
    param(
        [string[]]$Urls,
        [string]$Destination
    )

    foreach ($url in $Urls) {
        if (Download-FileBestEffort -Url $url -Destination $Destination) {
            return $true
        }
    }

    return $false
}

function Test-PowerShellScriptContent {
    param([string]$Path)

    try {
        # Try UTF-8 with BOM, then without
        try {
            $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        } catch {
            $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::GetEncoding('utf-8', $null, $false))
        }
        
        if (-not $text) { 
            Write-Host "[TEST] Empty file: $Path" -ForegroundColor Red
            return $false 
        }
        
        # Remove UTF-8 BOM if present
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
            Write-Host "[TEST] Removing BOM from file" -ForegroundColor Yellow
            $text = $text.Substring(1)
        }
        
        # Check for HTML only in first 500 chars (error pages appear at start)
        $firstChars = if ($text.Length -gt 500) { $text.Substring(0, 500) } else { $text }
        if ($firstChars -match '<!DOCTYPE\s+html|<html\b|<head\b|<body\b') { 
            Write-Host "[TEST] File contains HTML in first 500 chars - download returned error page" -ForegroundColor Red
            Write-Host "[TEST] First 200 chars: $($text.Substring(0, [Math]::Min(200, $text.Length)))" -ForegroundColor Red
            return $false 
        }
        
        # Get first 300 chars for debugging
        $firstChars = $text.Substring(0, [Math]::Min(300, $text.Length))
        Write-Host "[TEST] First 300 chars: $firstChars" -ForegroundColor Cyan
        
        # Check for PowerShell markers
        $hasRequires = $text -match '#Requires\s+-Version\s+5\.1'
        $hasStrictMode = $text -match 'Set-StrictMode\s+-Version\s+Latest'
        $hasCmdletBinding = $text -match '\[CmdletBinding\(\)\]'
        
        Write-Host "[TEST] #Requires match: $hasRequires" -ForegroundColor $(if ($hasRequires) { 'Green' } else { 'Red' })
        Write-Host "[TEST] Set-StrictMode match: $hasStrictMode" -ForegroundColor $(if ($hasStrictMode) { 'Green' } else { 'Red' })
        Write-Host "[TEST] [CmdletBinding()] match: $hasCmdletBinding" -ForegroundColor $(if ($hasCmdletBinding) { 'Green' } else { 'Red' })
        
        return ($hasRequires -or $hasStrictMode -or $hasCmdletBinding)
    } catch {
        Write-Host "[TEST] Exception: $_" -ForegroundColor Red
        return $false
    }
}

function Invoke-PowerShellFile {
    param(
        [string]$FilePath,
        [string]$ExtraArgs = ''
    )

    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }

    $command = "& '$FilePath' $ExtraArgs"
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $command
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$config = Read-AgentConfig -Path $ConfigFile
$collectTask = Get-ScheduledTask -TaskName 'monitoring-agent-collect' -ErrorAction SilentlyContinue
$updateTask = Get-ScheduledTask -TaskName 'monitoring-agent-update' -ErrorAction SilentlyContinue
$hasInstall = (Test-Path $ConfigFile) -and $collectTask -and $updateTask

$previousJitter = $null
if ($DisableJitter) {
    $previousJitter = $env:SEND_JITTER_MAX_SEC
    $env:SEND_JITTER_MAX_SEC = '0'
}

try {
    if ($hasInstall) {
        Write-Host "Refreshing installed scripts from $UpdateBaseUrl ..."

        Set-ConfigValue -Path $ConfigFile -Key 'SERVER_URL' -Value $ServerUrl
        Set-ConfigValue -Path $ConfigFile -Key 'RAW_BASE_URL' -Value $UpdateBaseUrl
        Set-ConfigValue -Path $ConfigFile -Key 'UPDATE_BASE_URL' -Value $UpdateBaseUrl
        Set-ConfigValue -Path $ConfigFile -Key 'INSTALL_DIR' -Value $InstallDir

        $filesToRefresh = @(
            @{ rel = 'client/windows/collect_and_send.ps1'; target = Join-Path $InstallDir 'collect_and_send.ps1'; required = $true },
            @{ rel = 'client/windows/self_update.ps1'; target = Join-Path $InstallDir 'self_update.ps1'; required = $true },
            @{ rel = 'client/windows/setup_harvest_sql_user.ps1'; target = Join-Path $InstallDir 'setup_harvest_sql_user.ps1'; required = $true },
            @{ rel = 'client/windows/collect_and_scan_sap_tables.ps1'; target = Join-Path $InstallDir 'collect_and_scan_sap_tables.ps1'; required = $true },
            @{ rel = 'client/windows/install_agent.ps1'; target = Join-Path $InstallDir 'install_agent.ps1'; required = $false },
            @{ rel = 'AGENT_VERSION'; target = $VersionFile; required = $true }
        )

        foreach ($item in $filesToRefresh) {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N') + '.tmp')
            try {
                $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $urls = @(
                    ("{0}/{1}?cb={2}" -f $UpdateBaseUrl, $item.rel, $cacheBust),
                    ("{0}/{1}" -f $UpdateBaseUrl, $item.rel)
                )

                $downloaded = $false
                $usedUrl = ''
                foreach ($url in $urls) {
                    if (Download-FileBestEffort -Url $url -Destination $tmp) {
                        $usedUrl = $url
                        $downloaded = $true
                        break
                    }
                }

                if (-not $downloaded) {
                    if ($item.required) {
                        throw "Failed to download $($item.rel)"
                    }
                    continue
                }

                $fileSize = (Get-Item $tmp).Length
                Write-Host "[DEBUG] Downloaded $($item.rel) ($fileSize bytes) from $usedUrl" -ForegroundColor Cyan

                if ($item.rel -like '*.ps1' -and -not (Test-PowerShellScriptContent -Path $tmp)) {
                    if ($item.required) {
                        throw "Downloaded script looks invalid: $($item.rel) (size: $fileSize)"
                    }
                    continue
                }

                Copy-Item $tmp $item.target -Force
            } finally {
                if (Test-Path $tmp) {
                    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if (Test-Path (Join-Path $InstallDir 'setup_harvest_sql_user.ps1')) {
            Write-Host 'Running harvest SQL user repair ...'
            Invoke-PowerShellFile -FilePath (Join-Path $InstallDir 'setup_harvest_sql_user.ps1') | Out-Null
        }

        if (Test-Path (Join-Path $InstallDir 'collect_and_send.ps1')) {
            Write-Host 'Running collector once to refresh data ...'
            Invoke-PowerShellFile -FilePath (Join-Path $InstallDir 'collect_and_send.ps1') | Out-Null
        }

        Write-Host 'Repair completed.'
    } else {
        Write-Host "Installing fresh agent from $UpdateBaseUrl ..."

        $installScript = Join-Path ([System.IO.Path]::GetTempPath()) ('monitoring-install-agent-' + [System.Guid]::NewGuid().ToString('N') + '.ps1')
        try {
            $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $urls = @(
                ($UpdateBaseUrl + '/client/windows/install_agent.ps1?cb=' + $cacheBust),
                ($UpdateBaseUrl + '/client/windows/install_agent.ps1')
            )

            if (-not (Download-FileFromCandidates -Urls $urls -Destination $installScript)) {
                throw 'Could not download install_agent.ps1'
            }
            if (-not (Test-PowerShellScriptContent -Path $installScript)) {
                throw 'Downloaded install_agent.ps1 looks invalid'
            }

            $args = @(
                '-ServerUrl', $ServerUrl,
                '-RawBaseUrl', $UpdateBaseUrl
            )

            $existingApiKey = Get-ConfigValue -Config $config -Key 'API_KEY' -Default ''
            $existingAgentId = Get-ConfigValue -Config $config -Key 'AGENT_ID' -Default ''
            $existingDisplayName = Get-ConfigValue -Config $config -Key 'DISPLAY_NAME' -Default ''
            $existingUpdateHours = Get-ConfigIntValue -Config $config -Key 'UPDATE_HOURS' -Default 1
            $existingIntervalMinutes = Get-ConfigIntValue -Config $config -Key 'INTERVAL_MINUTES' -Default 15

            if ($existingApiKey) {
                $args += @('-ApiKey', $existingApiKey)
            }
            if ($existingAgentId) {
                $args += @('-AgentId', $existingAgentId)
            }
            if ($existingDisplayName) {
                $args += @('-DisplayName', $existingDisplayName)
            }
            if ($existingIntervalMinutes -gt 0) {
                $args += @('-IntervalMinutes', [string]$existingIntervalMinutes)
            }
            if ($existingUpdateHours -gt 0) {
                $args += @('-UpdateHours', [string]$existingUpdateHours)
            }

            if ($DisableJitter) {
                Write-Host 'Jitter disabled for this install run.'
            }

            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installScript @args
        } finally {
            if (Test-Path $installScript) {
                Remove-Item $installScript -Force -ErrorAction SilentlyContinue
            }
        }
    }
} finally {
    if ($DisableJitter) {
        if ($null -eq $previousJitter) {
            Remove-Item Env:SEND_JITTER_MAX_SEC -ErrorAction SilentlyContinue
        } else {
            $env:SEND_JITTER_MAX_SEC = $previousJitter
        }
    }
}