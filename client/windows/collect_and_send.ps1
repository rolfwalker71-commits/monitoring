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
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$IC          = [System.Globalization.CultureInfo]::InvariantCulture
$ConfigFile  = if ($env:CONFIG_FILE)        { $env:CONFIG_FILE }        else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$VersionFile = if ($env:AGENT_VERSION_FILE) { $env:AGENT_VERSION_FILE } else { 'C:\ProgramData\monitoring-agent\AGENT_VERSION' }
$QueueDir    = if ($env:AGENT_QUEUE_DIR)    { $env:AGENT_QUEUE_DIR }    else { 'C:\ProgramData\monitoring-agent\queue' }
$EmbeddedAgentVersion = '1.1.47'
$PriorityUpdateMinutes = if ($env:PRIORITY_UPDATE_CHECK_MINUTES) { [int]$env:PRIORITY_UPDATE_CHECK_MINUTES } else { 60 }
$PriorityUpdateStateFile = if ($env:PRIORITY_UPDATE_STATE_FILE) { $env:PRIORITY_UPDATE_STATE_FILE } else { 'C:\ProgramData\monitoring-agent\last_priority_update_check' }
$UpdateLogFile = if ($env:UPDATE_LOG_FILE) { $env:UPDATE_LOG_FILE } else { 'C:\ProgramData\monitoring-agent\monitoring-agent-update.log' }
$UpdateLogLines = if ($env:UPDATE_LOG_LINES) { [int]$env:UPDATE_LOG_LINES } else { 40 }
$EventErrorsSinceMinutes = if ($env:JOURNAL_ERRORS_SINCE_MINUTES) { [int]$env:JOURNAL_ERRORS_SINCE_MINUTES } else { 180 }
$EventErrorsLimit = if ($env:JOURNAL_ERRORS_LIMIT) { [int]$env:JOURNAL_ERRORS_LIMIT } else { 20 }
$TopProcessesLimit = if ($env:TOP_PROCESSES_LIMIT) { [int]$env:TOP_PROCESSES_LIMIT } else { 8 }
$ContainersLimit = if ($env:CONTAINERS_LIMIT) { [int]$env:CONTAINERS_LIMIT } else { 30 }

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
$SendJitterMaxSec = 300

if ($env:SEND_JITTER_MAX_SEC -match '^\d+$') {
    $SendJitterMaxSec = [int]$env:SEND_JITTER_MAX_SEC
} elseif ($cfg.ContainsKey('SEND_JITTER_MAX_SEC') -and ($cfg['SEND_JITTER_MAX_SEC'] -match '^\d+$')) {
    $SendJitterMaxSec = [int]$cfg['SEND_JITTER_MAX_SEC']
}

if ($SendJitterMaxSec -lt 0) {
    $SendJitterMaxSec = 0
}

if (-not $ServerUrl) {
    Write-Error 'SERVER_URL is not set in config'
    exit 1
}

if (-not (Test-Path $QueueDir)) {
    New-Item -ItemType Directory -Path $QueueDir -Force | Out-Null
}

# ---- Helpers ----

function Set-ConfigValue {
    param(
        [string]$Key,
        [string]$Value
    )

    $updated = $false
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $lines = @()
    foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8) {
        if ($line -match $pattern) {
            $lines += ($Key + '="' + $Value + '"')
            $updated = $true
        } else {
            $lines += $line
        }
    }
    if (-not $updated) {
        $lines += ($Key + '="' + $Value + '"')
    }
    [System.IO.File]::WriteAllLines($ConfigFile, $lines, [System.Text.Encoding]::UTF8)
}

function Set-AgentApiKey {
    param([string]$NextApiKey)

    if (-not $NextApiKey) {
        return $false
    }

    Set-ConfigValue -Key 'API_KEY' -Value $NextApiKey
    $script:cfg['API_KEY'] = $NextApiKey
    $script:ApiKey = $NextApiKey
    return $true
}

function ConvertTo-JsonString([string]$s) {
    if ($null -eq $s) {
        return ''
    }

    $clean = [regex]::Replace($s, '[\x00-\x08\x0B\x0C\x0E-\x1F]', {
        param($match)
        return ('\u{0:x4}' -f [int][char]$match.Value)
    })

    $clean `
        -replace '\\',   '\\' `
        -replace '"',    '\"' `
        -replace "`r`n", '\n' `
        -replace "`n",   '\n' `
        -replace "`r",   '\r' `
        -replace "`t",   '\t'
}

function Select-AgentVersion {
    param(
        [string]$EmbeddedVersion,
        [string]$FilePath
    )

    $fileVersion = ''
    if (Test-Path $FilePath) {
        $fileVersion = ((Get-Content $FilePath -TotalCount 1 -Encoding UTF8) -replace '\s', '')
    }
    if ($fileVersion) {
        return $fileVersion
    }
    $selectedVersion = [string]$EmbeddedVersion
    if ($selectedVersion) {
        return $selectedVersion
    }
    return 'unknown'
}

function Get-VersionFileValue {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        return ''
    }
    return ((Get-Content $FilePath -TotalCount 1 -Encoding UTF8) -replace '\s', '')
}

function Get-QueueCount {
    $files = @(Get-ChildItem -Path $QueueDir -Filter '*.json' -ErrorAction SilentlyContinue)
    return $files.Count
}

function Get-UpdateLogBlock {
    $logPathJson = ConvertTo-JsonString $UpdateLogFile
    $priorityMinutes = $PriorityUpdateMinutes
    $lastPriorityCheckUtc = ''
    $nextPriorityCheckUtc = ''
    $recurringUpdateHours = 6
    if ($cfg.ContainsKey('UPDATE_HOURS')) {
        try {
            $recurringUpdateHours = [int]$cfg['UPDATE_HOURS']
        } catch {
            $recurringUpdateHours = 6
        }
    }

    $lastUnix = 0L
    if (Test-Path $PriorityUpdateStateFile) {
        $raw = (Get-Content $PriorityUpdateStateFile -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue)
        if ($raw -match '^\d+$') {
            $lastUnix = [long]$raw
        }
    }
    if ($lastUnix -gt 0 -and $priorityMinutes -gt 0) {
        $lastPriorityCheckUtc = [DateTimeOffset]::FromUnixTimeSeconds($lastUnix).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
        $nextPriorityCheckUtc = [DateTimeOffset]::FromUnixTimeSeconds($lastUnix + ($priorityMinutes * 60)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
    }

    if (-not (Test-Path $UpdateLogFile)) {
        return '{"available":false,"path":"' + $logPathJson + '","line_count":0,"lines":[],"priority_check_minutes":' + $priorityMinutes + ',"last_priority_check_utc":"' + (ConvertTo-JsonString $lastPriorityCheckUtc) + '","next_priority_check_utc":"' + (ConvertTo-JsonString $nextPriorityCheckUtc) + '","recurring_update_hours":' + $recurringUpdateHours + ',"recurring_update_hint":"' + (ConvertTo-JsonString ("Windows-Fallback-Update standardmaessig alle {0} Stunden relativ zum Installationszeitpunkt" -f $recurringUpdateHours)) + '"}'
    }

    $lines = @(Get-Content -Path $UpdateLogFile -Tail $UpdateLogLines -Encoding UTF8 -ErrorAction SilentlyContinue)
    $encodedLines = @()
    foreach ($line in $lines) {
        $encodedLines += ('"' + (ConvertTo-JsonString ([string]$line)) + '"')
    }

    return '{"available":true,"path":"' + $logPathJson + '","line_count":' + $lines.Count + ',"lines":[' + ($encodedLines -join ',') + '],"priority_check_minutes":' + $priorityMinutes + ',"last_priority_check_utc":"' + (ConvertTo-JsonString $lastPriorityCheckUtc) + '","next_priority_check_utc":"' + (ConvertTo-JsonString $nextPriorityCheckUtc) + '","recurring_update_hours":' + $recurringUpdateHours + ',"recurring_update_hint":"' + (ConvertTo-JsonString ("Windows-Fallback-Update standardmaessig alle {0} Stunden relativ zum Installationszeitpunkt" -f $recurringUpdateHours)) + '"}'
}

function Get-AgentConfigBlock {
    $maskedKeys = @('API_KEY','PASSWORD','SECRET','TOKEN','PASS')
    $configPathJson = ConvertTo-JsonString $ConfigFile
    if (-not (Test-Path $ConfigFile)) {
        return '{"available":false,"path":"' + $configPathJson + '","entries":[]}'
    }
    $entries = @()
    foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8 -ErrorAction SilentlyContinue) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*#') { continue }
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?(.*?)"?\s*$') {
            $k = $Matches[1]
            $v = $Matches[2]
            $shouldMask = $false
            foreach ($mk in $maskedKeys) {
                if ($k -imatch $mk) { $shouldMask = $true; break }
            }
            if ($shouldMask) { $v = '***' }
            $entries += ('{"key":"' + (ConvertTo-JsonString $k) + '","value":"' + (ConvertTo-JsonString $v) + '"}')
        }
    }
    return '{"available":true,"path":"' + $configPathJson + '","entries":[' + ($entries -join ',') + ']}'
}

function Get-SapB1InfoBlock {
    # Reads C:\Program Files\SAP\SAP Business One DI API\Conf\InstallationConfigMSSQL.xml
    # and converts the Windows build format (e.g. "1000180 SP:00 PL:08")
    # to the standard format ("10.00.180 PL 8") used by the monitoring backend.
    $xmlPath = 'C:\Program Files\SAP\SAP Business One DI API\Conf\InstallationConfigMSSQL.xml'
    $empty = '{"server_components_version":{"version":"","raw_output":""}}'
    if (-not (Test-Path $xmlPath)) {
        return $empty
    }
    try {
        # Read raw content and regex-match the Version val attribute directly —
        # avoids PowerShell XML property navigation quirks.
        $raw = [System.IO.File]::ReadAllText($xmlPath, [System.Text.Encoding]::UTF8)
        if ($raw -match '<Version\s+val="(\d{7}\s+SP:\d+\s+PL:\d+)"') {
            $verVal   = $Matches[1]
            if ($verVal -match '^(\d{7})\s+SP:\d+\s+PL:(\d+)') {
                $winBuild = $Matches[1]
                $pl       = $Matches[2].TrimStart('0')
                if (-not $pl) { $pl = '0' }
                # 1000180 -> 10.00.180
                $build   = "$($winBuild.Substring(0,2)).$($winBuild.Substring(2,2)).$($winBuild.Substring(4,3))"
                $version = "$build PL $pl"
                $versionEsc = ConvertTo-JsonString $version
                $rawEsc     = ConvertTo-JsonString $verVal
                return "{`"server_components_version`":{`"version`":`"$versionEsc`",`"raw_output`":`"$rawEsc`"}}"
            }
        }
    } catch {
        # File unreadable — return empty block
    }
    return $empty
}

function Send-Payload([string]$body) {
    $uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-report'
    Invoke-ServerJsonPost -Uri $uri -Body $body | Out-Null
}

function Invoke-ServerJsonPost {
    param(
        [string]$Uri,
        [string]$Body
    )

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Encoding = [System.Text.Encoding]::UTF8
        $wc.Headers.Add('Content-Type', 'application/json; charset=utf-8')
        if ($ApiKey) { $wc.Headers.Add('X-Api-Key', $ApiKey) }
        return $wc.UploadString($Uri, 'POST', $Body)
    } catch {
        $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
        if (-not $curl) {
            throw
        }

        $tmpBody = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.json')
        try {
            [System.IO.File]::WriteAllText($tmpBody, $Body, [System.Text.Encoding]::UTF8)
            $args = @(
                '--silent',
                '--show-error',
                '--fail',
                '--ssl-no-revoke',
                '-X', 'POST',
                '-H', 'Content-Type: application/json; charset=utf-8'
            )
            if ($ApiKey) {
                $args += @('-H', ('X-Api-Key: ' + $ApiKey))
            }
            $args += @('--data-binary', ('@' + $tmpBody), $Uri)
            $result = & $curl.Source @args 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw ($result | Out-String).Trim()
            }
            return ($result | Out-String)
        } finally {
            if (Test-Path $tmpBody) {
                Remove-Item $tmpBody -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Invoke-ServerGet {
    param([string]$Uri)

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Encoding = [System.Text.Encoding]::UTF8
        if ($ApiKey) { $wc.Headers.Add('X-Api-Key', $ApiKey) }
        return $wc.DownloadString($Uri)
    } catch {
        $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
        if (-not $curl) {
            throw
        }

        $args = @(
            '--silent',
            '--show-error',
            '--fail',
            '--ssl-no-revoke'
        )
        if ($ApiKey) {
            $args += @('-H', ('X-Api-Key: ' + $ApiKey))
        }
        $args += @($Uri)
        $result = & $curl.Source @args 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($result | Out-String).Trim()
        }
        return ($result | Out-String)
    }
}

function Get-HttpExceptionSummary($exception) {
    if ($null -eq $exception) {
        return ''
    }

    $parts = @()
    if ($exception.Message) {
        $parts += [string]$exception.Message
    }

    $response = $null
    try { $response = $exception.Response } catch { }
    if ($response) {
        try {
            $statusCode = [int]$response.StatusCode
            $statusText = [string]$response.StatusDescription
            if ($statusText) {
                $parts += ("HTTP {0} {1}" -f $statusCode, $statusText)
            } else {
                $parts += ("HTTP {0}" -f $statusCode)
            }
        } catch { }

        try {
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                if ($body) {
                    $parts += ("Response: {0}" -f $body)
                }
            }
        } catch { }
    }

    return ($parts -join ' | ')
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

function Send-CommandResult {
    param(
        [int]$CommandId,
        [string]$Status,
        [string]$Message
    )

    $body = '{' +
      '"hostname":"' + (ConvertTo-JsonString $hostnameValue) + '",' +
      '"agent_id":"' + (ConvertTo-JsonString $agentId) + '",' +
      '"command_id":' + $CommandId + ',' +
      '"status":"' + (ConvertTo-JsonString $Status) + '",' +
      '"result":{"message":"' + (ConvertTo-JsonString $Message) + '"}' +
    '}'

    try {
        $uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-command-result'
        Invoke-ServerJsonPost -Uri $uri -Body $body | Out-Null
    } catch { }
}

function Invoke-AgentSelfUpdate {
    $selfUpdateScript = Join-Path (Split-Path $ConfigFile -Parent) 'self_update.ps1'
    if (-not (Test-Path $selfUpdateScript)) {
        $selfUpdateScript = 'C:\ProgramData\monitoring-agent\self_update.ps1'
    }

    if (Test-Path $selfUpdateScript) {
        try {
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $selfUpdateScript *>> $UpdateLogFile
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
        } catch { }
    }

    $tmpScript = $null
    try {
        if ($cfg.ContainsKey('RAW_BASE_URL') -and $cfg['RAW_BASE_URL']) {
            $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.ps1')
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile(($cfg['RAW_BASE_URL'].TrimEnd('/')) + '/client/windows/self_update.ps1', $tmpScript)
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmpScript *>> $UpdateLogFile
            return ($LASTEXITCODE -eq 0)
        }
    } catch {
        return $false
    } finally {
        if ($tmpScript -and (Test-Path $tmpScript)) {
            Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
        }
    }

    return $false
}

function Invoke-RemoteCommands {
    try {
        $uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-commands?hostname=' + [Uri]::EscapeDataString($hostnameValue) + '&agent_id=' + [Uri]::EscapeDataString($agentId) + '&limit=10'
        $raw = Invoke-ServerGet -Uri $uri
        if (-not $raw) { return }
        $data = $raw | ConvertFrom-Json
        $commands = @($data.commands)
        foreach ($cmd in $commands) {
            $cmdId = [int]$cmd.id
            $cmdType = [string]$cmd.command_type
            if ($cmdId -le 0) { continue }

            if ($cmdType -eq 'update-now') {
                if (Invoke-AgentSelfUpdate) {
                    Send-CommandResult -CommandId $cmdId -Status 'completed' -Message 'update command executed'
                } else {
                    Send-CommandResult -CommandId $cmdId -Status 'failed' -Message 'update command failed'
                }
                continue
            }

            if ($cmdType -eq 'set-api-key') {
                $nextApiKey = ''
                if ($cmd.command_payload -and $cmd.command_payload.api_key) {
                    $nextApiKey = [string]$cmd.command_payload.api_key
                }
                if (Set-AgentApiKey -NextApiKey $nextApiKey) {
                    Send-CommandResult -CommandId $cmdId -Status 'completed' -Message 'api key updated'
                } else {
                    Send-CommandResult -CommandId $cmdId -Status 'failed' -Message 'api key update failed'
                }
            }
        }
    } catch { }
}

function Invoke-PrioritySelfUpdate {
    if ($PriorityUpdateMinutes -le 0) {
        return
    }

    $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $lastUnix = 0L
    if (Test-Path $PriorityUpdateStateFile) {
        $raw = (Get-Content $PriorityUpdateStateFile -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue)
        if ($raw -match '^\d+$') {
            $lastUnix = [long]$raw
        }
    }

    if (($nowUnix - $lastUnix) -lt ($PriorityUpdateMinutes * 60)) {
        return
    }

    try {
        [System.IO.File]::WriteAllText($PriorityUpdateStateFile, "$nowUnix`n", [System.Text.Encoding]::UTF8)
    } catch { }

    Invoke-AgentSelfUpdate | Out-Null
}

function Get-SystemEventErrors {
    $entries = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = @(1,2)
            StartTime = (Get-Date).AddMinutes(-$EventErrorsSinceMinutes)
        } -MaxEvents $EventErrorsLimit -ErrorAction Stop

        foreach ($e in $events) {
            $entries += ('{"time_utc":"' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $IC) + '",' +
                         '"priority":"err",' +
                         '"unit":"' + (ConvertTo-JsonString $e.ProviderName) + '",' +
                         '"message":"' + (ConvertTo-JsonString (([string]$e.Message).Trim())) + '"}')
        }
    } catch { }
    return ($entries -join ',')
}

function Get-TopProcessEntries {
    $entries = @()
    try {
        $procs = Get-Process -ErrorAction Stop |
            Sort-Object -Property CPU -Descending |
            Select-Object -First $TopProcessesLimit
        $totalMem = [double](Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
        if ($totalMem -le 0) { $totalMem = 1 }
        foreach ($p in $procs) {
            $rssKb = [long]($p.WorkingSet64 / 1024)
            $memPct = (($p.WorkingSet64 / $totalMem) * 100)
            $cpuSeconds = if ($null -eq $p.CPU) { 0.0 } else { [double]$p.CPU }
            $entries += ('{"pid":' + $p.Id + ',' +
                         '"user":"-",' +
                         '"cpu_percent":' + $cpuSeconds.ToString('F2', $IC) + ',' +
                         '"memory_percent":' + $memPct.ToString('F2', $IC) + ',' +
                         '"rss_kb":' + $rssKb + ',' +
                         '"name":"' + (ConvertTo-JsonString $p.ProcessName) + '",' +
                         '"command":"' + (ConvertTo-JsonString $p.ProcessName) + '"}')
        }
    } catch { }
    return ($entries -join ',')
}

function Get-ContainerEntries {
    $entries = @()
    $available = $false
    try {
        $docker = Get-Command docker -ErrorAction Stop
        $null = & $docker.Path info 2>$null
        if ($LASTEXITCODE -eq 0) {
            $available = $true
            $lines = & $docker.Path ps -a --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}' 2>$null
            $lines = @($lines | Select-Object -First $ContainersLimit)
            foreach ($line in $lines) {
                if (-not $line) { continue }
                $parts = $line -split '\|', 4
                $name = if ($parts.Count -ge 1) { $parts[0] } else { '' }
                $image = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                $state = if ($parts.Count -ge 3) { $parts[2] } else { '' }
                $status = if ($parts.Count -ge 4) { $parts[3] } else { '' }
                $health = (& $docker.Path inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' $name 2>$null)
                $restart = (& $docker.Path inspect -f '{{.RestartCount}}' $name 2>$null)
                if (-not $health) { $health = 'n/a' }
                if (-not $restart -or $restart -notmatch '^\d+$') { $restart = '0' }
                $entries += ('{"name":"' + (ConvertTo-JsonString $name) + '",' +
                             '"image":"' + (ConvertTo-JsonString $image) + '",' +
                             '"state":"' + (ConvertTo-JsonString $state) + '",' +
                             '"status":"' + (ConvertTo-JsonString $status) + '",' +
                             '"health":"' + (ConvertTo-JsonString $health) + '",' +
                             '"restart_count":' + $restart + '}')
            }
        }
    } catch { }

    return @{
        available = $available
        entries = ($entries -join ',')
    }
}

# ---- Collect system info ----

$hostnameValue = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
if (-not $hostnameValue) { $hostnameValue = $env:COMPUTERNAME }

$osInfo      = Get-CimInstance -ClassName Win32_OperatingSystem
$cpuInfoList = @(Get-CimInstance -ClassName Win32_Processor)

# Agent identity
$agentId     = if ($cfg.ContainsKey('AGENT_ID')      -and $cfg['AGENT_ID'])      { $cfg['AGENT_ID'] }      else { $hostnameValue }
$displayName = if ($cfg.ContainsKey('DISPLAY_NAME')  -and $cfg['DISPLAY_NAME'])  { $cfg['DISPLAY_NAME'] }  else { $hostnameValue }

if ($SendJitterMaxSec -gt 0) {
    $jitterIdentity = "$hostnameValue$agentId"
    $hashProvider = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hashProvider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($jitterIdentity))
    } finally {
        $hashProvider.Dispose()
    }
    $jitterSec = [int]([System.BitConverter]::ToUInt32($hash, 0) % ($SendJitterMaxSec + 1))
    if ($jitterSec -gt 0) {
        Write-Host ("Applying deterministic send jitter: {0}s (max {1}s)" -f $jitterSec, $SendJitterMaxSec)
        Start-Sleep -Seconds $jitterSec
    }
}

$agentVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile

# Timestamps / uptime
$timestampUtc  = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
$uptimeSeconds = [long]($osInfo.LocalDateTime - $osInfo.LastBootUpTime).TotalSeconds

# OS / kernel
$osName        = $osInfo.Caption.Trim()
$kernelVersion = $osInfo.Version   # e.g. "10.0.19045"

# IPs / default interface
$primaryIp        = ''
$defaultInterface = ''
$defaultGateway   = ''
$dnsServers       = @()
try {
    $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } |
                Select-Object -First 1
    $defaultInterface = $defRoute.InterfaceAlias
    $defaultGateway = [string]$defRoute.NextHop
    $primaryIp = (Get-NetIPAddress -InterfaceIndex $defRoute.InterfaceIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress |
                 Where-Object { $_ -ne '127.0.0.1' } | Select-Object -First 1
    $dnsServers = @((Get-DnsClientServerAddress -InterfaceIndex $defRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).
        ServerAddresses | Where-Object { $_ } | Select-Object -Unique)
    if (-not $primaryIp) { $primaryIp = '' }
} catch { }

$allIps = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue) |
           Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ' '

$dnsServerEntries = @()
foreach ($dns in $dnsServers) {
    $dnsServerEntries += ('"' + (ConvertTo-JsonString ([string]$dns)) + '"')
}
$dnsServersJson = $dnsServerEntries -join ','

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

$eventErrorsStr = Get-SystemEventErrors
$topProcStr = Get-TopProcessEntries
$containerData = Get-ContainerEntries
$containersStr = [string]$containerData.entries
$dockerAvailable = if ($containerData.available) { 'true' } else { 'false' }
$updateLogJson  = Get-UpdateLogBlock
$agentConfigJson = Get-AgentConfigBlock
$sapB1Json      = Get-SapB1InfoBlock
$largeFilesJson = '{"enabled":false,"status":"unsupported","filesystems":[]}'

Invoke-RemoteCommands
Invoke-PrioritySelfUpdate

# A self-update can replace AGENT_VERSION during this run.
# Re-read it so the outgoing payload reflects the current installed version.
$agentVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile
$versionFileValue = Get-VersionFileValue -FilePath $VersionFile
$scriptPath = ''
if ($PSCommandPath) {
    $scriptPath = $PSCommandPath
} elseif ($MyInvocation.MyCommand.Path) {
    $scriptPath = $MyInvocation.MyCommand.Path
}

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
$defaultGwEsc    = ConvertTo-JsonString $defaultGateway
$scriptPathEsc   = ConvertTo-JsonString $scriptPath
$embeddedVerEsc  = ConvertTo-JsonString $EmbeddedAgentVersion
$fileVerEsc      = ConvertTo-JsonString $versionFileValue
$versionFilePathEsc = ConvertTo-JsonString $VersionFile

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
    "agent_runtime": {
        "script_path": "$scriptPathEsc",
        "embedded_version": "$embeddedVerEsc",
        "version_file_value": "$fileVerEsc",
        "version_file_path": "$versionFilePathEsc",
        "selected_version": "$agentVerEsc"
    },
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
        "default_gateway": "$defaultGwEsc",
        "dns_servers": [$dnsServersJson],
    "interfaces": [$ifacesStr]
  },
    "filesystems": [$fsStr],
    "journal_errors": {
        "since_minutes": $EventErrorsSinceMinutes,
        "entries": [$eventErrorsStr]
    },
    "top_processes": {
        "entries": [$topProcStr]
    },
    "containers": {
        "runtime": "docker",
        "available": $dockerAvailable,
        "entries": [$containersStr]
    },
    "agent_update": $updateLogJson,
    "agent_config": $agentConfigJson,
    "sap_business_one": $sapB1Json,
    "large_files": $largeFilesJson
}
"@

# ---- Send ----
try {
    Send-Payload $payload
} catch {
    $sendErrorSummary = Get-HttpExceptionSummary $_.Exception
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

    if ($sendErrorSummary) {
        Write-Error "Send failed: $sendErrorSummary"
    }
    Write-Error "Payload queued for retry: $qf"
    exit 1
}
