#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Windows monitoring agent.

.EXAMPLE
    # Run directly (as Administrator):
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\install_agent.ps1 -ServerUrl https://monitoring.example.com

    # Or via one-liner (as Administrator):
    $url = 'https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/windows/install_agent.ps1'
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString($url) + "`n" +
        'Install-MonitoringAgent -ServerUrl "https://monitoring.example.com"')
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ServerUrl,

    [Parameter(Mandatory = $false)]
    [string] $ApiKey = '',

    [Parameter(Mandatory = $false)]
    [string] $AgentId = '',

    [Parameter(Mandatory = $false)]
    [string] $DisplayName = '',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 59)]
    [int] $IntervalMinutes = 15,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int] $UpdateHours = 6,

    [Parameter(Mandatory = $false)]
    [string] $RawBaseUrl = 'https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enable TLS 1.2 for older Windows versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir      = 'C:\ProgramData\monitoring-agent'
$ConfigFile      = "$InstallDir\agent.conf"
$QueueDir        = "$InstallDir\queue"
$LogFile         = "$InstallDir\monitoring-agent.log"
$UpdateLogFile   = "$InstallDir\monitoring-agent-update.log"
$TaskNameCollect = 'monitoring-agent-collect'
$TaskNameUpdate  = 'monitoring-agent-update'

function Invoke-Icacls {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
}

function Protect-PathAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [bool] $IsDirectory
    )

    try {
        if ($IsDirectory) {
            Invoke-Icacls -Arguments @(
                $Path,
                '/inheritance:r',
                '/grant:r',
                '*S-1-5-18:(OI)(CI)F',
                '*S-1-5-32-544:(OI)(CI)F'
            )
        } else {
            Invoke-Icacls -Arguments @(
                $Path,
                '/inheritance:r',
                '/grant:r',
                '*S-1-5-18:F',
                '*S-1-5-32-544:F'
            )
        }
    } catch {
        Write-Warning "Could not harden ACL for '$Path': $($_.Exception.Message)"
    }
}

# ---- Create directories ----
foreach ($dir in @($InstallDir, $QueueDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Restrict queue dir to SYSTEM + Administrators (locale-independent via SIDs)
Protect-PathAcl -Path $QueueDir -IsDirectory $true

# ---- Download scripts ----
$wc = New-Object System.Net.WebClient

Write-Host "Downloading collect_and_send.ps1..."
$wc.DownloadFile("$RawBaseUrl/client/windows/collect_and_send.ps1", "$InstallDir\collect_and_send.ps1")

Write-Host "Downloading self_update.ps1..."
$wc.DownloadFile("$RawBaseUrl/client/windows/self_update.ps1", "$InstallDir\self_update.ps1")

Write-Host "Downloading AGENT_VERSION..."
try {
    $wc.DownloadFile("$RawBaseUrl/BUILD_VERSION", "$InstallDir\AGENT_VERSION")
} catch {
    try {
        $wc.DownloadFile("$RawBaseUrl/AGENT_VERSION", "$InstallDir\AGENT_VERSION")
    } catch {
        [System.IO.File]::WriteAllText("$InstallDir\AGENT_VERSION", "unknown`n", [System.Text.Encoding]::UTF8)
    }
}

# ---- Determine agent identity ----
if (-not $AgentId) {
    try { $AgentId = [System.Net.Dns]::GetHostEntry('').HostName } catch { $AgentId = $env:COMPUTERNAME }
    if (-not $AgentId) { $AgentId = $env:COMPUTERNAME }
}

if (-not $DisplayName) {
    $DisplayName = $AgentId
}

# ---- Write config ----
$configContent = @"
SERVER_URL="$ServerUrl"
API_KEY="$ApiKey"
AGENT_ID="$AgentId"
DISPLAY_NAME="$DisplayName"
RAW_BASE_URL="$RawBaseUrl"
INSTALL_DIR="$InstallDir"
AGENT_VERSION_FILE="$InstallDir\AGENT_VERSION"
AGENT_QUEUE_DIR="$QueueDir"
UPDATE_HOURS="$UpdateHours"
PRIORITY_UPDATE_CHECK_MINUTES="60"
UPDATE_LOG_FILE="$UpdateLogFile"
"@

[System.IO.File]::WriteAllText($ConfigFile, $configContent, [System.Text.Encoding]::UTF8)

# Restrict config to SYSTEM + Administrators only (locale-independent via SIDs)
Protect-PathAcl -Path $ConfigFile -IsDirectory $false

# ---- Register Scheduled Tasks ----
function Register-MonitoringTask {
    param(
        [string]       $TaskName,
        [string]       $ScriptPath,
        [string]       $LogPath,
        [System.TimeSpan] $RepeatInterval,
        [string]       $Description,
        [System.TimeSpan] $ExecutionTimeLimit
    )

    # Wrap the script call so stdout+stderr both go to the log file.
    # Single-quoted config paths are embedded at install time; variables
    # with $ that should expand at RUNTIME are escaped as `$.
    $psArgs = '-NonInteractive -NoProfile -ExecutionPolicy Bypass -Command ' +
              '"' +
              "`$env:CONFIG_FILE='$ConfigFile'; " +
              "`$env:AGENT_VERSION_FILE='$InstallDir\AGENT_VERSION'; " +
              "`$env:AGENT_QUEUE_DIR='$QueueDir'; " +
              "& '$ScriptPath' *>> '$LogPath'" +
              '"'

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs
    $trigger   = New-ScheduledTaskTrigger -Once `
                    -At (Get-Date).AddSeconds(30) `
                    -RepetitionInterval $RepeatInterval
    $settings  = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit $ExecutionTimeLimit `
                    -MultipleInstances  IgnoreNew `
                    -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask `
        -TaskName    $TaskName `
        -Action      $action `
        -Trigger     $trigger `
        -Settings    $settings `
        -Principal   $principal `
        -Description $Description `
        -Force | Out-Null
}

Write-Host "Registering scheduled task: $TaskNameCollect (every $IntervalMinutes min)..."
Register-MonitoringTask `
    -TaskName           $TaskNameCollect `
    -ScriptPath         "$InstallDir\collect_and_send.ps1" `
    -LogPath            $LogFile `
    -RepeatInterval     (New-TimeSpan -Minutes $IntervalMinutes) `
    -Description        'Monitoring agent - collect and send system metrics' `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Write-Host "Registering scheduled task: $TaskNameUpdate (every 6 h)..."
Register-MonitoringTask `
    -TaskName           $TaskNameUpdate `
    -ScriptPath         "$InstallDir\self_update.ps1" `
    -LogPath            $UpdateLogFile `
    -RepeatInterval     (New-TimeSpan -Hours $UpdateHours) `
    -Description        'Monitoring agent - self update' `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Non-interactive post-install self-test: run collector and updater once immediately.
Write-Host "Running self-test (collect and update)..."

& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `
    "`$env:CONFIG_FILE='$ConfigFile'; " + `
    "`$env:AGENT_VERSION_FILE='$InstallDir\AGENT_VERSION'; " + `
    "`$env:AGENT_QUEUE_DIR='$QueueDir'; " + `
    "& '$InstallDir\collect_and_send.ps1' *>> '$LogFile'"

& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `
    "`$env:CONFIG_FILE='$ConfigFile'; " + `
    "`$env:AGENT_VERSION_FILE='$InstallDir\AGENT_VERSION'; " + `
    "`$env:AGENT_QUEUE_DIR='$QueueDir'; " + `
    "& '$InstallDir\self_update.ps1' *>> '$UpdateLogFile'"

$installedAgentVersion = 'unknown'
if (Test-Path "$InstallDir\AGENT_VERSION") {
    $rawVersion = (Get-Content -Path "$InstallDir\AGENT_VERSION" -TotalCount 1 -ErrorAction SilentlyContinue)
    if ($rawVersion) {
        $installedAgentVersion = $rawVersion.Trim()
    }
}

# ---- Summary ----
Write-Host ''
Write-Host 'Monitoring agent installed successfully.'
Write-Host "  Install dir   : $InstallDir"
Write-Host "  Config        : $ConfigFile"
Write-Host "  Collect log   : $LogFile"
Write-Host "  Update log    : $UpdateLogFile"
Write-Host "  Collect task  : $TaskNameCollect  (every $IntervalMinutes min)"
Write-Host "  Update task   : $TaskNameUpdate  (every $UpdateHours h)"
Write-Host '  Self-test     : collect + self_update executed once'
Write-Host "  Agent version : $installedAgentVersion"
Write-Host ''
