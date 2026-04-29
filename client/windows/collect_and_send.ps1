#Requires -Version 5.1
<#
.SYNOPSIS
    Collects system metrics and sends them to the monitoring server.
    Mirrors the Linux collect_and_send.sh payload format exactly.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enable TLS 1.2 for older Windows versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$IC          = [System.Globalization.CultureInfo]::InvariantCulture
$ConfigFile  = if ($env:CONFIG_FILE)        { $env:CONFIG_FILE }        else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$VersionFile = if ($env:AGENT_VERSION_FILE) { $env:AGENT_VERSION_FILE } else { 'C:\ProgramData\monitoring-agent\AGENT_VERSION' }
$QueueDir    = if ($env:AGENT_QUEUE_DIR)    { $env:AGENT_QUEUE_DIR }    else { 'C:\ProgramData\monitoring-agent\queue' }

if (-not (Test-Path $ConfigFile)) {
    Write-Error "Config file not found: $ConfigFile"
    exit 1
}

# Parse KEY="value" config file
$cfg = @{}
foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
        $cfg[$Matches[1]] = $Matches[2]
    }
}

$ServerUrl = $cfg['SERVER_URL']
$ApiKey    = if ($cfg.ContainsKey('API_KEY')) { $cfg['API_KEY'] } else { '' }

if (-not $ServerUrl) {
    Write-Error 'SERVER_URL is not set in config'
    exit 1
}

if (-not (Test-Path $QueueDir)) {
    New-Item -ItemType Directory -Path $QueueDir -Force | Out-Null
}

# ---- Helpers ----

function ConvertTo-JsonString([string]$s) {
    $s `
        -replace '\\',   '\\' `
        -replace '"',    '\"' `
        -replace "`r`n", '\n' `
        -replace "`n",   '\n' `
        -replace "`r",   '\r' `
        -replace "`t",   '\t'
}

function Get-QueueCount {
    $files = @(Get-ChildItem -Path $QueueDir -Filter '*.json' -ErrorAction SilentlyContinue)
    return $files.Count
}

function Send-Payload([string]$body) {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('Content-Type', 'application/json')
    if ($ApiKey) { $wc.Headers.Add('X-Api-Key', $ApiKey) }
    $uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-report'
    $null = $wc.UploadString($uri, 'POST', $body)
}

function Invoke-FlushQueue {
    $files = @(Get-ChildItem -Path $QueueDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($f in $files) {
        try {
            $data = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
            Send-Payload $data
            Remove-Item $f.FullName -Force
        } catch {
            return $false
        }
    }
    return $true
}

# ---- Collect system info ----

$hostnameValue = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
if (-not $hostnameValue) { $hostnameValue = $env:COMPUTERNAME }

$osInfo      = Get-CimInstance -ClassName Win32_OperatingSystem
$cpuInfoList = @(Get-CimInstance -ClassName Win32_Processor)

# Agent identity
$agentId     = if ($cfg.ContainsKey('AGENT_ID')      -and $cfg['AGENT_ID'])      { $cfg['AGENT_ID'] }      else { $hostnameValue }
$displayName = if ($cfg.ContainsKey('DISPLAY_NAME')  -and $cfg['DISPLAY_NAME'])  { $cfg['DISPLAY_NAME'] }  else { $hostnameValue }

$agentVersion = 'unknown'
if (Test-Path $VersionFile) {
    $agentVersion = ((Get-Content $VersionFile -TotalCount 1 -Encoding UTF8) -replace '\s', '')
}

# Timestamps / uptime
$timestampUtc  = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
$uptimeSeconds = [long]($osInfo.LocalDateTime - $osInfo.LastBootUpTime).TotalSeconds

# OS / kernel
$osName        = $osInfo.Caption.Trim()
$kernelVersion = $osInfo.Version   # e.g. "10.0.19045"

# IPs / default interface
$primaryIp        = ''
$defaultInterface = ''
try {
    $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } |
                Select-Object -First 1
    $defaultInterface = $defRoute.InterfaceAlias
    $primaryIp = (Get-NetIPAddress -InterfaceIndex $defRoute.InterfaceIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress |
                 Where-Object { $_ -ne '127.0.0.1' } | Select-Object -First 1
    if (-not $primaryIp) { $primaryIp = '' }
} catch { }

$allIps = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue) |
           Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ' '

# CPU — measure over 1 second with Get-Counter (mirrors Linux /proc/stat approach);
# fall back to WMI LoadPercentage if the performance counter is unavailable.
$cpuCores = ($cpuInfoList | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
if (-not $cpuCores -or $cpuCores -lt 1) { $cpuCores = 1 }

$cpuUsageRaw = 0.0
try {
    $samples     = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
    $cpuUsageRaw = ($samples.CounterSamples | Where-Object { $_.InstanceName -eq '_total' } | Select-Object -Last 1).CookedValue
    if ($null -eq $cpuUsageRaw) { $cpuUsageRaw = 0.0 }
} catch {
    $wmiCpu = ($cpuInfoList | Measure-Object -Property LoadPercentage -Average).Average
    $cpuUsageRaw = if ($null -eq $wmiCpu) { 0.0 } else { [double]$wmiCpu }
}
$cpuUsagePctStr = ([double]$cpuUsageRaw).ToString('F2', $IC)
$loadAvgStr     = '0.00'   # Windows has no load average concept

# Memory (Win32_OperatingSystem reports in KB)
$memTotalKb     = [long]$osInfo.TotalVisibleMemorySize
$memAvailableKb = [long]$osInfo.FreePhysicalMemory
$memUsedKb      = $memTotalKb - $memAvailableKb
$memUsedPct     = if ($memTotalKb -gt 0) { [math]::Round(($memUsedKb / $memTotalKb) * 100, 2) } else { 0.0 }
$memUsedPctStr  = $memUsedPct.ToString('F2', $IC)

# Pagefile / swap (Win32_PageFileUsage reports AllocatedBaseSize and CurrentUsage in MB)
$swapTotalKb = 0L
$swapUsedKb  = 0L
$pagefiles   = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue)
foreach ($pf in $pagefiles) {
    $swapTotalKb += [long]$pf.AllocatedBaseSize * 1024
    $swapUsedKb  += [long]$pf.CurrentUsage * 1024
}
$swapFreeKb     = $swapTotalKb - $swapUsedKb
$swapUsedPct    = if ($swapTotalKb -gt 0) { [math]::Round(($swapUsedKb / $swapTotalKb) * 100, 2) } else { 0.0 }
$swapUsedPctStr = $swapUsedPct.ToString('F2', $IC)

# Network interfaces
$ifaceEntries = @()
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
foreach ($a in $adapters) {
    $stats   = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
    $rxBytes = if ($stats) { [long]$stats.ReceivedBytes }              else { 0L }
    $txBytes = if ($stats) { [long]$stats.SentBytes }                  else { 0L }
    $rxPkts  = if ($stats) { [long]$stats.ReceivedUnicastPackets }     else { 0L }
    $txPkts  = if ($stats) { [long]$stats.SentUnicastPackets }         else { 0L }
    $rxErr   = if ($stats) { [long]$stats.ReceivedPacketErrors }       else { 0L }
    $txErr   = if ($stats) { [long]$stats.OutboundPacketErrors }       else { 0L }
    $rxDrop  = if ($stats) { [long]$stats.ReceivedDiscardedPackets }   else { 0L }
    $txDrop  = if ($stats) { [long]$stats.OutboundDiscardedPackets }   else { 0L }
    $state   = if ($a.Status -eq 'Up') { 'up' } else { 'down' }
    $mac     = if ($a.MacAddress) { $a.MacAddress -replace '-', ':' } else { 'unknown' }
    $isDef   = if ($a.InterfaceAlias -eq $defaultInterface) { 'true' } else { 'false' }

    $ifaceEntries += ('{"name":"' + (ConvertTo-JsonString $a.Name) + '",' +
                      '"state":"' + $state + '",' +
                      '"mac_address":"' + (ConvertTo-JsonString $mac) + '",' +
                      '"is_default":' + $isDef + ',' +
                      '"rx_bytes":' + $rxBytes + ',' +
                      '"tx_bytes":' + $txBytes + ',' +
                      '"rx_packets":' + $rxPkts + ',' +
                      '"tx_packets":' + $txPkts + ',' +
                      '"rx_errors":' + $rxErr + ',' +
                      '"tx_errors":' + $txErr + ',' +
                      '"rx_dropped":' + $rxDrop + ',' +
                      '"tx_dropped":' + $txDrop + '}')
}
$ifacesStr = $ifaceEntries -join ','

# Filesystems (DriveType=3 = local fixed disk)
$fsEntries    = @()
$logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
foreach ($d in $logicalDisks) {
    $totalKb = [long]([double]$d.Size / 1024)
    $freeKb  = [long]([double]$d.FreeSpace / 1024)
    $usedKb  = $totalKb - $freeKb
    $usedPct = if ($totalKb -gt 0) { [int](($usedKb / $totalKb) * 100) } else { 0 }
    $fsType  = if ($d.FileSystem) { $d.FileSystem } else { 'unknown' }

    $fsEntries += ('{"fs":"' + (ConvertTo-JsonString $d.DeviceID) + '",' +
                   '"type":"' + (ConvertTo-JsonString $fsType) + '",' +
                   '"mountpoint":"' + (ConvertTo-JsonString $d.DeviceID) + '",' +
                   '"blocks":' + $totalKb + ',' +
                   '"used":' + $usedKb + ',' +
                   '"available":' + $freeKb + ',' +
                   '"used_percent":' + $usedPct + '}')
}
$fsStr = $fsEntries -join ','

# ---- Flush queued reports ----
Invoke-FlushQueue | Out-Null
$queueDepth = Get-QueueCount

# ---- Build payload ----
# Pre-compute all escaped string values to avoid any expansion issues in the here-string
$agentIdEsc      = ConvertTo-JsonString $agentId
$agentVerEsc     = ConvertTo-JsonString $agentVersion
$displayNameEsc  = ConvertTo-JsonString $displayName
$hostnameEsc     = ConvertTo-JsonString $hostnameValue
$primaryIpEsc    = ConvertTo-JsonString $primaryIp
$allIpsEsc       = ConvertTo-JsonString $allIps
$kernelEsc       = ConvertTo-JsonString $kernelVersion
$osNameEsc       = ConvertTo-JsonString $osName
$defaultIfaceEsc = ConvertTo-JsonString $defaultInterface

$payload = @"
{
  "agent_id": "$agentIdEsc",
  "agent_version": "$agentVerEsc",
  "display_name": "$displayNameEsc",
  "hostname": "$hostnameEsc",
  "primary_ip": "$primaryIpEsc",
  "all_ips": "$allIpsEsc",
  "kernel": "$kernelEsc",
  "os": "$osNameEsc",
  "uptime_seconds": $uptimeSeconds,
  "timestamp_utc": "$timestampUtc",
  "delivery_mode": "live",
  "is_delayed": false,
  "queued_at_utc": "",
  "queue_depth": $queueDepth,
  "cpu": {
    "usage_percent": $cpuUsagePctStr,
    "load_avg_1": $loadAvgStr,
    "load_avg_5": $loadAvgStr,
    "load_avg_15": $loadAvgStr,
    "cores": $cpuCores
  },
  "memory": {
    "total_kb": $memTotalKb,
    "available_kb": $memAvailableKb,
    "used_kb": $memUsedKb,
    "used_percent": $memUsedPctStr
  },
  "swap": {
    "total_kb": $swapTotalKb,
    "free_kb": $swapFreeKb,
    "used_kb": $swapUsedKb,
    "used_percent": $swapUsedPctStr
  },
  "network": {
    "default_interface": "$defaultIfaceEsc",
    "interfaces": [$ifacesStr]
  },
  "filesystems": [$fsStr]
}
"@

# ---- Send ----
try {
    Send-Payload $payload
} catch {
    $queuedAt = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
    $delayed  = $payload `
                  -replace '"delivery_mode": "live"',  '"delivery_mode": "delayed"' `
                  -replace '"is_delayed": false',       '"is_delayed": true' `
                  -replace '"queued_at_utc": ""',       ('"queued_at_utc": "' + $queuedAt + '"')

    $ts  = [System.DateTime]::UtcNow.ToString('yyyyMMddHHmmss', $IC)
    $rnd = Get-Random -Maximum 9999
    $qf  = Join-Path $QueueDir "report-${ts}-${rnd}.json"

    [System.IO.File]::WriteAllText($qf, $delayed, [System.Text.Encoding]::UTF8)

    $newDepth = Get-QueueCount
    $delayed  = $delayed -replace ('"queue_depth": ' + $queueDepth), ('"queue_depth": ' + $newDepth)
    [System.IO.File]::WriteAllText($qf, $delayed, [System.Text.Encoding]::UTF8)

    Write-Error "Payload queued for retry: $qf"
    exit 1
}
