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
    [string] $RawBaseUrl = 'https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enable TLS 1.2 for older Windows versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir      = 'C:\ProgramData\monitoring-agent'
$ConfigFile      = "$InstallDir\agent.conf"
$QueueDir        = "$InstallDir\queue"
$TaskNameCollect = 'monitoring-agent-collect'
$TaskNameUpdate  = 'monitoring-agent-update'

# ---- Create directories ----
foreach ($dir in @($InstallDir, $QueueDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Restrict queue dir to SYSTEM + Administrators
$acl = Get-Acl $QueueDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM',                  'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -Path $QueueDir -AclObject $acl

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
    [System.IO.File]::WriteAllText("$InstallDir\AGENT_VERSION", "unknown`n", [System.Text.Encoding]::UTF8)
}

# ---- Determine agent identity ----
if (-not $AgentId) {
    try { $AgentId = [System.Net.Dns]::GetHostEntry('').HostName } catch { $AgentId = $env:COMPUTERNAME }
    if (-not $AgentId) { $AgentId = $env:COMPUTERNAME }
}

if (-not $DisplayName) {
    Write-Host -NoNewline "Display name for this host [$AgentId]: "
    $input = Read-Host
    $DisplayName = if ($input.Trim()) { $input.Trim() } else { $AgentId }
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
"@

[System.IO.File]::WriteAllText($ConfigFile, $configContent, [System.Text.Encoding]::UTF8)

# Restrict config to SYSTEM + Administrators only
$cfgAcl = Get-Acl $ConfigFile
$cfgAcl.SetAccessRuleProtection($true, $false)
$cfgAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM',                  'FullControl', 'Allow')))
$cfgAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')))
Set-Acl -Path $ConfigFile -AclObject $cfgAcl

# ---- Register Scheduled Tasks ----
function Register-MonitoringTask {
    param(
        [string] $TaskName,
        [string] $ScriptPath,
        [string] $RepeatInterval,   # e.g. "PT15M" or "PT6H"
        [string] $Description,
        [System.TimeSpan] $ExecutionTimeLimit
    )

    $psArgs = "-NonInteractive -NoProfile -ExecutionPolicy Bypass " +
              "-Command `"`$env:CONFIG_FILE='$ConfigFile'; " +
              "`$env:AGENT_VERSION_FILE='$InstallDir\AGENT_VERSION'; " +
              "& '$ScriptPath'`""

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $trigger.Repetition.Interval           = $RepeatInterval
    $trigger.Repetition.StopAtDurationEnd  = $false
    $settings  = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit $ExecutionTimeLimit `
                    -MultipleInstances  IgnoreNew `
                    -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask `
        -TaskName   $TaskName `
        -Action     $action `
        -Trigger    $trigger `
        -Settings   $settings `
        -Principal  $principal `
        -Description $Description `
        -Force | Out-Null
}

Write-Host "Registering scheduled task: $TaskNameCollect (every $IntervalMinutes min)..."
Register-MonitoringTask `
    -TaskName            $TaskNameCollect `
    -ScriptPath          "$InstallDir\collect_and_send.ps1" `
    -RepeatInterval      "PT${IntervalMinutes}M" `
    -Description         'Monitoring agent - collect and send system metrics' `
    -ExecutionTimeLimit  (New-TimeSpan -Minutes 5)

Write-Host "Registering scheduled task: $TaskNameUpdate (every 6 h)..."
Register-MonitoringTask `
    -TaskName            $TaskNameUpdate `
    -ScriptPath          "$InstallDir\self_update.ps1" `
    -RepeatInterval      'PT6H' `
    -Description         'Monitoring agent - self update' `
    -ExecutionTimeLimit  (New-TimeSpan -Hours 1)

# ---- Summary ----
Write-Host ''
Write-Host 'Monitoring agent installed successfully.'
Write-Host "  Install dir   : $InstallDir"
Write-Host "  Config        : $ConfigFile"
Write-Host "  Collect task  : $TaskNameCollect  (every $IntervalMinutes min)"
Write-Host "  Update task   : $TaskNameUpdate  (every 6 h)"
Write-Host ''

$run = Read-Host 'Run collection once now? [y/N]'
if ($run -match '^[Yy]') {
    Start-ScheduledTask -TaskName $TaskNameCollect
    Write-Host 'Task started.'
}
