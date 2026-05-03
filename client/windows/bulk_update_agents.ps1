#Requires -Version 5.1
<#!
.SYNOPSIS
    Updates monitoring agent scripts on multiple Windows hosts and verifies runtime version details.

.DESCRIPTION
    For each target host, this script:
    - Downloads latest collect_and_send.ps1, self_update.ps1, and BUILD_VERSION from GitHub
    - Writes BUILD_VERSION into AGENT_VERSION
    - Verifies EmbeddedAgentVersion in collect_and_send.ps1
    - Optionally executes one immediate collect run
    - Returns a per-host result summary

.EXAMPLE
    .\bulk_update_agents.ps1 -ComputerName host1,host2

.EXAMPLE
    .\bulk_update_agents.ps1 -ComputerName host1,host2 -Credential (Get-Credential) -OutputCsvPath .\bulk-update-results.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false)]
    [pscredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$RawBaseUrl = 'https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main',

    [Parameter(Mandatory = $false)]
    [switch]$SkipCollectRun,

    [Parameter(Mandatory = $false)]
    [string]$OutputCsvPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$invokeParams = @{}
if ($PSBoundParameters.ContainsKey('Credential')) {
    $invokeParams.Credential = $Credential
}

$remoteScript = {
    param(
        [string]$RemoteRawBaseUrl,
        [bool]$RemoteSkipCollect
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Enable TLS 1.2 for older Windows versions
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $base = 'C:\ProgramData\monitoring-agent'
    $collectPath = Join-Path $base 'collect_and_send.ps1'
    $selfUpdatePath = Join-Path $base 'self_update.ps1'
    $versionPath = Join-Path $base 'AGENT_VERSION'
    $configPath = Join-Path $base 'agent.conf'
    $queuePath = Join-Path $base 'queue'
    $collectLogPath = Join-Path $base 'monitoring-agent.log'

    if (-not (Test-Path $base)) {
        New-Item -ItemType Directory -Path $base -Force | Out-Null
    }
    if (-not (Test-Path $queuePath)) {
        New-Item -ItemType Directory -Path $queuePath -Force | Out-Null
    }

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile("$RemoteRawBaseUrl/client/windows/collect_and_send.ps1", $collectPath)
    $wc.DownloadFile("$RemoteRawBaseUrl/client/windows/self_update.ps1", $selfUpdatePath)

    $buildVersion = ''
    try {
        $buildVersion = ($wc.DownloadString("$RemoteRawBaseUrl/BUILD_VERSION")).Trim()
    } catch {
        $buildVersion = ''
    }
    if (-not $buildVersion) {
        throw 'Could not download BUILD_VERSION from remote source.'
    }
    [System.IO.File]::WriteAllText($versionPath, "$buildVersion`n", [System.Text.Encoding]::ASCII)

    $collectContent = Get-Content -Path $collectPath -Raw -Encoding UTF8
    $embeddedVersion = ''
    if ($collectContent -match "\$EmbeddedAgentVersion\s*=\s*'([^']+)'") {
        $embeddedVersion = $Matches[1]
    }

    $agentVersionFileValue = ''
    if (Test-Path $versionPath) {
        $agentVersionFileValue = ((Get-Content $versionPath -TotalCount 1 -Encoding UTF8) -replace '\\s', '')
    }

    $collectRunStatus = 'skipped'
    $collectExitCode = 0
    if (-not $RemoteSkipCollect) {
        if (-not (Test-Path $configPath)) {
            throw "Config file missing at $configPath"
        }

        $env:CONFIG_FILE = $configPath
        $env:AGENT_VERSION_FILE = $versionPath
        $env:AGENT_QUEUE_DIR = $queuePath

        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $collectPath *>> $collectLogPath
        $collectExitCode = $LASTEXITCODE
        $collectRunStatus = if ($collectExitCode -eq 0) { 'ok' } else { 'failed' }
    }

    [pscustomobject]@{
        host_name = $env:COMPUTERNAME
        collect_script_path = $collectPath
        embedded_version = $embeddedVersion
        version_file_path = $versionPath
        version_file_value = $agentVersionFileValue
        build_version_downloaded = $buildVersion
        collect_run = $collectRunStatus
        collect_exit_code = $collectExitCode
        collect_log_path = $collectLogPath
        updated_at_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        ok = $true
        error = ''
    }
}

$results = @()
foreach ($host in $ComputerName) {
    $target = [string]$host
    if (-not $target) {
        continue
    }

    try {
        $res = Invoke-Command -ComputerName $target @invokeParams -ScriptBlock $remoteScript -ArgumentList $RawBaseUrl, [bool]$SkipCollectRun
        if ($res -is [System.Array]) {
            $results += $res
        } else {
            $results += @($res)
        }
    } catch {
        $results += [pscustomobject]@{
            host_name = $target
            collect_script_path = 'C:\ProgramData\monitoring-agent\collect_and_send.ps1'
            embedded_version = ''
            version_file_path = 'C:\ProgramData\monitoring-agent\AGENT_VERSION'
            version_file_value = ''
            build_version_downloaded = ''
            collect_run = 'failed'
            collect_exit_code = -1
            collect_log_path = 'C:\ProgramData\monitoring-agent\monitoring-agent.log'
            updated_at_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            ok = $false
            error = $_.Exception.Message
        }
    }
}

$results | Sort-Object host_name | Format-Table host_name, ok, embedded_version, version_file_value, collect_run, collect_exit_code, error -AutoSize

if ($OutputCsvPath) {
    $results | Sort-Object host_name | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputCsvPath"
}
