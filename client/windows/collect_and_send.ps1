#Requires -Version 5.1
<#
.SYNOPSIS
    Collects system metrics and sends them to the monitoring server.
    Mirrors the Linux collect_and_send.sh payload format exactly.

.PARAMETER NoJitter
    Skip startup jitter sleep (useful for manual tests).

.PARAMETER JitterMaxSec
    Override maximum jitter delay for this run (in seconds).

.PARAMETER DebugPayload
    Print JSON payload to stdout instead of sending it (useful for debugging).
#>
[CmdletBinding()]
param(
    [switch]$NoJitter,
    [int]$JitterMaxSec = 0,
    [switch]$DebugPayload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Global crash trap: catches any unhandled terminating error ----
# Writes to stdout (captured by scheduled task log) and to a persistent crash file.
trap {
    $crashMsg = "COLLECT_CRASH $(([System.DateTime]::UtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ')): $($_.Exception.Message)"
    try { Write-Host $crashMsg } catch { }
    try {
        $crashFile = 'C:\ProgramData\monitoring-agent\last-collect-crash.txt'
        [System.IO.File]::WriteAllText($crashFile, "$crashMsg`n$($_.ScriptStackTrace)`n", [System.Text.Encoding]::UTF8)
    } catch { }
    break
}

# Enable TLS 1.2 for older Windows versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$IC          = [System.Globalization.CultureInfo]::InvariantCulture
$ConfigFile  = if ($env:CONFIG_FILE)        { $env:CONFIG_FILE }        else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$VersionFile = if ($env:AGENT_VERSION_FILE) { $env:AGENT_VERSION_FILE } else { 'C:\ProgramData\monitoring-agent\AGENT_VERSION' }
$QueueDir    = if ($env:AGENT_QUEUE_DIR)    { $env:AGENT_QUEUE_DIR }    else { 'C:\ProgramData\monitoring-agent\queue' }
$PayloadArchiveDir = if ($env:PAYLOAD_ARCHIVE_DIR) { $env:PAYLOAD_ARCHIVE_DIR } else { 'C:\ProgramData\monitoring-agent\payload-history' }
$PayloadArchiveKeep = if ($env:PAYLOAD_ARCHIVE_KEEP -match '^\d+$') { [int]$env:PAYLOAD_ARCHIVE_KEEP } else { 4 }
$EmbeddedAgentVersion = '1.4.87'
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

# ---- Helpers ----

function Ensure-HarvestSqlConfig {
    <#
    .SYNOPSIS
    Auto-provisions default Harvest SQL credentials if missing.
    Idempotent: only adds if all three parameters are absent.
    #>
    $needsUpdate = $false
    
    if (-not ($cfg.ContainsKey('HARVEST_SQL_SERVER') -and $cfg['HARVEST_SQL_SERVER'])) {
        $needsUpdate = $true
    }
    if (-not ($cfg.ContainsKey('HARVEST_SQL_USER') -and $cfg['HARVEST_SQL_USER'])) {
        $needsUpdate = $true
    }
    if (-not ($cfg.ContainsKey('HARVEST_SQL_PASSWORD') -and $cfg['HARVEST_SQL_PASSWORD'])) {
        $needsUpdate = $true
    }
    
    if ($needsUpdate) {
        Set-ConfigValue -Key 'HARVEST_SQL_SERVER' -Value 'localhost'
        Set-ConfigValue -Key 'HARVEST_SQL_USER' -Value 'harvest'
        Set-ConfigValue -Key 'HARVEST_SQL_PASSWORD' -Value '0djKUt&xbLK0AYr'
        Set-ConfigValue -Key 'ENABLE_SAP_SCAN' -Value '1'
        
        # Reload config so harvest functions can use new values
        $global:cfg = @{}
        foreach ($line in Get-Content -Path $ConfigFile -Encoding UTF8) {
            if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
                $global:cfg[$Matches[1]] = $Matches[2]
            } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
                $global:cfg[$Matches[1]] = $Matches[2]
            }
        }
    }
}

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

# Auto-provision Harvest SQL config if missing (idempotent)
Ensure-HarvestSqlConfig

$ServerUrl = $cfg['SERVER_URL']
$ApiKey    = if ($cfg.ContainsKey('API_KEY') -and $cfg['API_KEY']) { $cfg['API_KEY'] } elseif ($cfg.ContainsKey('X_API_KEY')) { $cfg['X_API_KEY'] } else { '' }
$SendJitterMaxSec = 300

if ($JitterMaxSec -gt 0) {
    # Command-line parameter takes precedence
    $SendJitterMaxSec = $JitterMaxSec
} elseif ($env:SEND_JITTER_MAX_SEC -match '^\d+$') {
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
        return '{"available":false,"path":"' + $logPathJson + '","line_count":0,"lines":[],"last_crash":"","priority_check_minutes":' + $priorityMinutes + ',"last_priority_check_utc":"' + (ConvertTo-JsonString $lastPriorityCheckUtc) + '","next_priority_check_utc":"' + (ConvertTo-JsonString $nextPriorityCheckUtc) + '","recurring_update_hours":' + $recurringUpdateHours + ',"recurring_update_hint":"' + (ConvertTo-JsonString ("Windows-Fallback-Update standardmaessig alle {0} Stunden relativ zum Installationszeitpunkt" -f $recurringUpdateHours)) + '"}'
    }

    $lines = @(Get-Content -Path $UpdateLogFile -Tail $UpdateLogLines -Encoding UTF8 -ErrorAction SilentlyContinue)
    $encodedLines = @()
    foreach ($line in $lines) {
        $encodedLines += ('"' + (ConvertTo-JsonString ([string]$line)) + '"')
    }

    $lastCrash = ''
    $crashFile = 'C:\ProgramData\monitoring-agent\last-collect-crash.txt'
    if (Test-Path $crashFile) {
        try {
            $lastCrash = [System.IO.File]::ReadAllText($crashFile, [System.Text.Encoding]::UTF8).Trim()
        } catch { }
    }

    return '{"available":true,"path":"' + $logPathJson + '","line_count":' + $lines.Count + ',"lines":[' + ($encodedLines -join ',') + '],"last_crash":"' + (ConvertTo-JsonString $lastCrash) + '","priority_check_minutes":' + $priorityMinutes + ',"last_priority_check_utc":"' + (ConvertTo-JsonString $lastPriorityCheckUtc) + '","next_priority_check_utc":"' + (ConvertTo-JsonString $nextPriorityCheckUtc) + '","recurring_update_hours":' + $recurringUpdateHours + ',"recurring_update_hint":"' + (ConvertTo-JsonString ("Windows-Fallback-Update standardmaessig alle {0} Stunden relativ zum Installationszeitpunkt" -f $recurringUpdateHours)) + '"}'
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

function Get-SqlServerInfoBlock {
    # Discovers local SQL Server instances via Registry, then connects via Windows Auth
    # (no SA or password needed) to collect version, service status, database list,
    # sizes and last backup timestamps from msdb.
    $instancesJson = @()
    $regRoot = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (-not (Test-Path $regRoot)) {
        return '{"available":false,"instances":[]}'
    }
    try {
        $instanceMap = Get-ItemProperty -Path $regRoot -ErrorAction Stop
        foreach ($prop in $instanceMap.PSObject.Properties) {
            if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
            $instanceName = $prop.Name   # e.g. MSSQLSERVER or SQLEXPRESS
            $serviceKey   = $prop.Value  # e.g. MSSQL$SQLEXPRESS

            # Version from Registry — works even when service is stopped
            $version = ''
            try {
                $verPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$serviceKey\MSSQLServer\CurrentVersion"
                $version = (Get-ItemProperty -Path $verPath -ErrorAction SilentlyContinue).CurrentVersion
                if (-not $version) { $version = '' }
            } catch { $version = '' }

            # Edition from Registry
            $edition = ''
            try {
                $setupPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$serviceKey\Setup"
                $edition = (Get-ItemProperty -Path $setupPath -ErrorAction SilentlyContinue).Edition
                if (-not $edition) { $edition = '' }
            } catch { $edition = '' }

            # Service status
            $svcName = if ($instanceName -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$instanceName" }
            $svcStatus = 'unknown'
            try { $svcStatus = (Get-Service -Name $svcName -ErrorAction SilentlyContinue).Status.ToString() } catch {}

            $serverInst = if ($instanceName -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$instanceName" }

            $databases = @()
            $connError = ''
            $sqlSystemUser = ''
            $sqlOriginalLogin = ''
            $sqlSuserSname = ''
            $masterFilesRows = 0
            try {
                # Database=master ensures sys.master_files is visible without USE statements
                $cs = "Server=$serverInst;Database=master;Integrated Security=true;Connection Timeout=5;TrustServerCertificate=true"
                $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
                $conn.Open()

                # Capture effective SQL auth context seen by this process/task account.
                $ctxCmd = $conn.CreateCommand()
                $ctxCmd.CommandTimeout = 10
                $ctxCmd.CommandText = @"
SELECT
    SYSTEM_USER,
    ORIGINAL_LOGIN(),
    SUSER_SNAME(),
    (SELECT COUNT(*) FROM sys.master_files) AS master_files_rows
"@
                $ctxRdr = $ctxCmd.ExecuteReader()
                if ($ctxRdr.Read()) {
                    $sqlSystemUser = [string]$ctxRdr[0]
                    $sqlOriginalLogin = [string]$ctxRdr[1]
                    $sqlSuserSname = [string]$ctxRdr[2]
                    $masterFilesRows = [int]$ctxRdr[3]
                }
                $ctxRdr.Close()

                # Database list + sizes (all databases incl. system DBs except tempdb)
                # size is in 8KB pages; MB = pages / 128
                $cmd = $conn.CreateCommand()
                $cmd.CommandTimeout = 10
                $cmd.CommandText = @"
SELECT d.name, d.state_desc, d.recovery_model_desc,
    COALESCE(SUM(CASE WHEN mf.type=0 THEN CAST(mf.size AS bigint) ELSE 0 END) / 128, 0) AS data_mb,
    COALESCE(SUM(CASE WHEN mf.type=1 THEN CAST(mf.size AS bigint) ELSE 0 END) / 128, 0) AS log_mb
FROM sys.databases d
LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
WHERE d.name <> 'tempdb'
GROUP BY d.name, d.state_desc, d.recovery_model_desc
ORDER BY
    CASE WHEN d.name IN ('master','model','msdb') THEN 1 ELSE 0 END,
    d.name
"@
                $rdr = $cmd.ExecuteReader()
                $dbRows = @()
                while ($rdr.Read()) {
                    $dbRows += @{
                        name           = [string]$rdr[0]
                        state          = [string]$rdr[1]
                        recovery_model = [string]$rdr[2]
                        data_mb        = [long]$rdr[3]
                        log_mb         = [long]$rdr[4]
                    }
                }
                $rdr.Close()

                # Last backup per database (Full=D, Differential=I, Log=L)
                # Uses full msdb.dbo.backupset qualifier — no USE needed
                $bkCmd = $conn.CreateCommand()
                $bkCmd.CommandTimeout = 10
                $bkCmd.CommandText = @"
SELECT database_name, [type], MAX(backup_finish_date) AS last_backup
FROM msdb.dbo.backupset
GROUP BY database_name, [type]
"@
                $bkRdr = $bkCmd.ExecuteReader()
                $backups = @{}
                while ($bkRdr.Read()) {
                    $n  = [string]$bkRdr[0]
                    $t  = [string]$bkRdr[1]
                    $dt = $bkRdr[2]
                    if (-not $backups.ContainsKey($n)) { $backups[$n] = @{} }
                    $backups[$n][$t] = if ($dt -is [DateTime]) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $IC) } else { '' }
                }
                $bkRdr.Close()
                $conn.Close()

                foreach ($db in $dbRows) {
                    $bk = if ($backups.ContainsKey($db.name)) { $backups[$db.name] } else { @{} }
                    $isSystem = $db.name -in @('master','model','msdb')
                    $isSystemText = if ($isSystem) { 'true' } else { 'false' }
                    $lastFullBackup = if ($bk.ContainsKey('D')) { ConvertTo-JsonString $bk['D'] } else { '' }
                    $lastDiffBackup = if ($bk.ContainsKey('I')) { ConvertTo-JsonString $bk['I'] } else { '' }
                    $lastLogBackup = if ($bk.ContainsKey('L')) { ConvertTo-JsonString $bk['L'] } else { '' }
                    $dbJson  = '{"name":' + (ConvertTo-JsonString $db.name | ForEach-Object { '"' + $_ + '"' }) +
                               ',"instance_name":"' + (ConvertTo-JsonString $instanceName) + '"' +
                               ',"system_db":' + $isSystemText +
                               ',"state":"'          + (ConvertTo-JsonString $db.state)           + '"' +
                               ',"recovery_model":"' + (ConvertTo-JsonString $db.recovery_model)  + '"' +
                               ',"data_mb":'         + $db.data_mb +
                               ',"log_mb":'          + $db.log_mb +
                               ',"last_full_backup":"'  + $lastFullBackup + '"' +
                               ',"last_diff_backup":"'  + $lastDiffBackup + '"' +
                               ',"last_log_backup":"'   + $lastLogBackup + '"' +
                               '}'
                    $databases += $dbJson
                }
            } catch {
                $connError = ConvertTo-JsonString ($_.Exception.Message -replace '[\r\n]+',' ')
            }

            $instJson = '{"name":"'           + (ConvertTo-JsonString $instanceName) + '"' +
                        ',"version":"'        + (ConvertTo-JsonString $version)      + '"' +
                        ',"edition":"'        + (ConvertTo-JsonString $edition)      + '"' +
                        ',"service_status":"' + (ConvertTo-JsonString $svcStatus)    + '"' +
                        ',"sql_system_user":"' + (ConvertTo-JsonString $sqlSystemUser) + '"' +
                        ',"sql_original_login":"' + (ConvertTo-JsonString $sqlOriginalLogin) + '"' +
                        ',"sql_suser_sname":"' + (ConvertTo-JsonString $sqlSuserSname) + '"' +
                        ',"master_files_rows":' + $masterFilesRows +
                        ',"connection_error":"' + $connError                         + '"' +
                        ',"databases":['      + ($databases -join ',')               + ']}' 
            $instancesJson += $instJson
        }
    } catch {
        return '{"available":false,"instances":[],"error":"' + (ConvertTo-JsonString ($_.Exception.Message -replace '[\r\n]+',' ')) + '"}'
    }
    return '{"available":true,"instances":[' + ($instancesJson -join ',') + ']}'
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

function Get-HarvestHealthStatus {
    $status = @{
        harvest_enabled = $false
        user_exists = $false
        can_connect = $false
        databases_accessible = @()
        extensions_available = $false
        extensions_rows = @()
        extensions_error = ''
        sari_addons_available = $false
        sari_addons_source_db = ''
        sari_addons_rows = @()
        sari_addons_error = ''
        diagnostics = ''
        error = ''
    }

    # Check if harvest is enabled
    if (-not ($cfg.ContainsKey('ENABLE_SAP_SCAN') -and $cfg['ENABLE_SAP_SCAN'] -eq '1')) {
        $status.diagnostics = 'Harvest scanning disabled in config'
        return $status
    }

    $status.harvest_enabled = $true

    $harvestServer = if ($cfg.ContainsKey('HARVEST_SQL_SERVER')) { $cfg['HARVEST_SQL_SERVER'] } else { '' }
    $harvestUser = if ($cfg.ContainsKey('HARVEST_SQL_USER')) { $cfg['HARVEST_SQL_USER'] } else { '' }
    $harvestPassword = if ($cfg.ContainsKey('HARVEST_SQL_PASSWORD')) { $cfg['HARVEST_SQL_PASSWORD'] } else { '' }

    if (-not $harvestServer -or -not $harvestUser -or -not $harvestPassword) {
        $status.diagnostics = 'Harvest credentials not fully configured'
        return $status
    }

    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$harvestServer;Database=master;User ID=$harvestUser;Password=$harvestPassword;TrustServerCertificate=True;Connection Timeout=10;"
        $conn.Open()

        # Test user exists by checking login
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT SUSER_SNAME()"
        $currentUser = $cmd.ExecuteScalar()
        $status.user_exists = $null -ne $currentUser

        # Test access across all online non-system DBs using HAS_DBACCESS.
        $dbListCmd = $conn.CreateCommand()
        $dbListCmd.CommandText = "SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND database_id > 4 ORDER BY name"
        $dbCandidates = @()
        $dbReader = $dbListCmd.ExecuteReader()
        try {
            while ($dbReader.Read()) {
                $dbName = [string]$dbReader['name']
                if ($dbName) {
                    $dbCandidates += $dbName
                }
            }
        } finally {
            $dbReader.Close()
        }

        foreach ($dbName in $dbCandidates) {
            try {
                $safeDb = $dbName.Replace("'", "''")
                $testCmd = $conn.CreateCommand()
                $testCmd.CommandText = "SELECT HAS_DBACCESS(N'$safeDb')"
                $testCmd.CommandTimeout = 5
                $hasAccessRaw = $testCmd.ExecuteScalar()
                $hasAccess = 0
                if ($null -ne $hasAccessRaw) {
                    $hasAccess = [int]$hasAccessRaw
                }
                if ($hasAccess -eq 1) {
                    $status.databases_accessible += $dbName
                }
            } catch {
                # DB probe failed
            }
        }

        $status.can_connect = $true

        # Read SAP B1 extensions from SLDModel.SLDData for frontend display.
        try {
            $extCmd = $conn.CreateCommand()
            $extCmd.CommandText = "SELECT e.AddOnName, e.Version FROM [SLDModel.SLDData].[dbo].[Extensions] AS e INNER JOIN [SLDModel.SLDData].[dbo].[ExtensionDeployments] AS ed ON ed.[Extension_Id] = e.[Id]"
            $extCmd.CommandTimeout = 10
            $extReader = $extCmd.ExecuteReader()
            try {
                while ($extReader.Read()) {
                    $status.extensions_rows += @{
                        AddOnName = [string]$extReader['AddOnName']
                        Version = [string]$extReader['Version']
                    }
                }
                $status.extensions_available = $true
            } finally {
                $extReader.Close()
            }
        } catch {
            $status.extensions_error = $_.Exception.Message
        }

        # Read lightweight add-ons from SARI with DB fallback: SBO-COMMON, SBOCOMMON.
        $sariDbCandidates = @('SBO-COMMON', 'SBOCOMMON')
        $sariErrors = @()
        foreach ($sariDb in $sariDbCandidates) {
            try {
                $safeDbName = $sariDb.Replace(']', ']]')
                $sariCmd = $conn.CreateCommand()
                $sariCmd.CommandText = "SELECT AName, AddOnVer FROM [$safeDbName].[dbo].[SARI] ORDER BY AName"
                $sariCmd.CommandTimeout = 10
                $sariReader = $sariCmd.ExecuteReader()
                try {
                    while ($sariReader.Read()) {
                        $status.sari_addons_rows += @{
                            AName = [string]$sariReader['AName']
                            AddOnVer = [string]$sariReader['AddOnVer']
                        }
                    }
                    $status.sari_addons_available = $true
                    $status.sari_addons_source_db = $sariDb
                    break
                } finally {
                    $sariReader.Close()
                }
            } catch {
                $sariErrors += ($sariDb + ': ' + $_.Exception.Message)
            }
        }
        if (-not $status.sari_addons_available -and $sariErrors.Count -gt 0) {
            $status.sari_addons_error = ($sariErrors -join ' | ')
        }

        $status.diagnostics = "Connected as $currentUser on $harvestServer; accessible DBs: $($status.databases_accessible -join ', ')"

        $conn.Close()
    } catch {
        $status.error = $_.Exception.Message
        $status.diagnostics = "Connection failed: $($_.Exception.Message)"
    }

    return $status
}

function Get-SapB1PayloadBlock {
    $b1Block = Get-SapB1InfoBlock
    $harvestStatus = Get-HarvestHealthStatus

    $dbItems = @($harvestStatus.databases_accessible | ForEach-Object { '"' + (ConvertTo-JsonString $_) + '"' })
    $harvDbsJson = ($dbItems -join ',')
    $harvErrorEsc = ConvertTo-JsonString $harvestStatus.error
    $harvDiagsEsc = ConvertTo-JsonString $harvestStatus.diagnostics
    $extensionsRowsJson = @(
        $harvestStatus.extensions_rows | ForEach-Object {
            '{' +
            '"AddOnName":"' + (ConvertTo-JsonString ([string]$_.AddOnName)) + '",' +
            '"Version":"' + (ConvertTo-JsonString ([string]$_.Version)) + '"' +
            '}'
        }
    ) -join ','
    $extensionsErrorEsc = ConvertTo-JsonString $harvestStatus.extensions_error
    $sariRowsJson = @(
        $harvestStatus.sari_addons_rows | ForEach-Object {
            '{' +
            '"AName":"' + (ConvertTo-JsonString ([string]$_.AName)) + '",' +
            '"AddOnVer":"' + (ConvertTo-JsonString ([string]$_.AddOnVer)) + '"' +
            '}'
        }
    ) -join ','
    $sariErrorEsc = ConvertTo-JsonString $harvestStatus.sari_addons_error
    $sariSourceDbEsc = ConvertTo-JsonString $harvestStatus.sari_addons_source_db

    $harvJson = "{`"harvest_enabled`":$(if($harvestStatus.harvest_enabled){'true'}else{'false'}),`"user_exists`":$(if($harvestStatus.user_exists){'true'}else{'false'}),`"can_connect`":$(if($harvestStatus.can_connect){'true'}else{'false'}),`"databases_accessible`":[${harvDbsJson}],`"error`":`"$harvErrorEsc`",`"diagnostics`":`"$harvDiagsEsc`"}"
    $extensionsJson = "{`"available`":$(if($harvestStatus.extensions_available){'true'}else{'false'}),`"rows`":[$extensionsRowsJson],`"error`":`"$extensionsErrorEsc`"}"
    $sariAddonsJson = "{`"available`":$(if($harvestStatus.sari_addons_available){'true'}else{'false'}),`"source_db`":`"$sariSourceDbEsc`",`"rows`":[${sariRowsJson}],`"error`":`"$sariErrorEsc`"}"

    if ($b1Block.EndsWith('}')) {
        return $b1Block.Substring(0, $b1Block.Length - 1) + ",`"harvest_status`":$harvJson,`"extensions`":$extensionsJson,`"sari_addons`":$sariAddonsJson}"
    }
    return $b1Block
}

function Send-Payload([string]$body) {
    Save-PayloadSnapshot -Body $body
    $uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-report'
    Invoke-ServerJsonPost -Uri $uri -Body $body | Out-Null
}

function Save-PayloadSnapshot {
    param([string]$Body)

    try {
        if ($PayloadArchiveKeep -lt 0) {
            return
        }

        [System.IO.Directory]::CreateDirectory($PayloadArchiveDir) | Out-Null
        $stamp = [System.DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ', $IC)
        $path = Join-Path $PayloadArchiveDir ("payload-{0}-{1}.json" -f $stamp, (Get-Random -Maximum 10000))
        [System.IO.File]::WriteAllText($path, $Body, [System.Text.Encoding]::UTF8)

        $files = @(Get-ChildItem -Path $PayloadArchiveDir -Filter 'payload-*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending)
        if ($files.Count -gt $PayloadArchiveKeep) {
            $files | Select-Object -Skip $PayloadArchiveKeep | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning ("Payload snapshot could not be written: " + $_.Exception.Message)
    }
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

function Get-UpdateFailureHint {
    try {
        if (-not (Test-Path $UpdateLogFile)) {
            return ''
        }

        $lines = @(Get-Content -Path $UpdateLogFile -Tail 50 -Encoding UTF8 -ErrorAction SilentlyContinue)
        if ($lines.Count -eq 0) {
            return ''
        }

        for ($idx = $lines.Count - 1; $idx -ge 0; $idx--) {
            $line = [string]$lines[$idx]
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            if ($line -match 'failed|error|exception|blocked|invalid|unsupported|abort|not found|cannot') {
                return $line.Trim()
            }
        }

        return ([string]$lines[$lines.Count - 1]).Trim()
    } catch {
        return ''
    }
}

function New-UpdateResult {
    param(
        [bool]$Ok,
        [string]$Message
    )

    return @{ ok = $Ok; message = [string]$Message }
}

function Should-TreatUpdateFailureAsSoftSuccess {
    param([string]$FailureMessage)

    $message = [string]$FailureMessage
    if (-not $message) {
        return $false
    }

    $looksLikeSourceReachabilityIssue = $message -match 'download|remote version is empty|no self-update source|timed out|name could not be resolved|unable to connect|could not|connection|proxy|forbidden|not found|404|503|502'
    if (-not $looksLikeSourceReachabilityIssue) {
        return $false
    }

    $localVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile
    return ($localVersion -and $localVersion -ne 'unknown')
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
                return (New-UpdateResult -Ok $true -Message 'update command executed')
            }
            $hint = Get-UpdateFailureHint
            $msg = "self_update.ps1 exited with code $LASTEXITCODE"
            if ($hint) {
                $msg = "$msg | $hint"
            }
            return (New-UpdateResult -Ok $false -Message $msg)
        } catch {
            $msg = 'self_update.ps1 execution failed'
            if ($_.Exception -and $_.Exception.Message) {
                $msg = "$msg | $($_.Exception.Message)"
            }
            return (New-UpdateResult -Ok $false -Message $msg)
        }
    }

    $tmpScript = $null
    try {
        $updateBases = Get-UpdateBaseCandidates
        if ($updateBases.Count -gt 0) {
            $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.ps1')
            $downloaded = $false
            foreach ($updateBase in $updateBases) {
                try {
                    $wc = New-Object System.Net.WebClient
                    $wc.DownloadFile(($updateBase.TrimEnd('/')) + '/client/windows/self_update.ps1', $tmpScript)
                    $downloaded = $true
                    break
                } catch {
                    continue
                }
            }
            if (-not $downloaded) {
                throw 'could not download remote self_update.ps1 from any update source candidate'
            }
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmpScript *>> $UpdateLogFile
            if ($LASTEXITCODE -eq 0) {
                return (New-UpdateResult -Ok $true -Message 'update command executed (remote updater)')
            }
            $hint = Get-UpdateFailureHint
            $msg = "remote self_update.ps1 exited with code $LASTEXITCODE"
            if ($hint) {
                $msg = "$msg | $hint"
            }
            return (New-UpdateResult -Ok $false -Message $msg)
        }
    } catch {
        $msg = 'remote self_update.ps1 download/execute failed'
        if ($_.Exception -and $_.Exception.Message) {
            $msg = "$msg | $($_.Exception.Message)"
        }
        return (New-UpdateResult -Ok $false -Message $msg)
    } finally {
        if ($tmpScript -and (Test-Path $tmpScript)) {
            Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
        }
    }

    return (New-UpdateResult -Ok $false -Message 'no self-update source available (local script missing and no update base configured)')
}

function Get-UpdateBaseCandidates {
    $candidates = New-Object System.Collections.Generic.List[string]

    function Add-UniqueCandidate {
        param([string]$Value)
        if (-not $Value) { return }
        $normalized = $Value.Trim().TrimEnd('/')
        if (-not $normalized) { return }
        foreach ($existing in $candidates) {
            if ($existing -ieq $normalized) { return }
        }
        $candidates.Add($normalized) | Out-Null
    }

    Add-UniqueCandidate 'https://infoboard.ang-schweiz.ch/updates'
    Add-UniqueCandidate 'https://infoboard.an-group.work/updates'
    Add-UniqueCandidate 'https://monitoring.rolfwalker.ch/updates'

    if ($cfg.ContainsKey('UPDATE_BASE_URL') -and $cfg['UPDATE_BASE_URL']) {
        Add-UniqueCandidate $cfg['UPDATE_BASE_URL']
    }
    if ($cfg.ContainsKey('SERVER_URL') -and $cfg['SERVER_URL']) {
        Add-UniqueCandidate (($cfg['SERVER_URL']).TrimEnd('/') + '/updates')
    }
    if ($cfg.ContainsKey('RAW_BASE_URL') -and $cfg['RAW_BASE_URL']) {
        Add-UniqueCandidate $cfg['RAW_BASE_URL']
    }

    return $candidates
}

function Get-UpdateBaseUrl {
    $candidates = Get-UpdateBaseCandidates
    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }
    return ''
}

function Write-UpdateLog {
    param([string]$Message)

    try {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
        Add-Content -Path $UpdateLogFile -Value ("[{0}] {1}" -f $stamp, $Message) -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Best-effort logging only.
    }
}

function Test-PowerShellScriptContent {
    param([string]$Path)

    try {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if (-not $text) { return $false }
        $text = $text -replace "`0", ''
        $textNormalized = $text -replace '^[\uFEFF]+', ''
        $leadingChunk = $textNormalized
        if ($leadingChunk.Length -gt 2048) {
            $leadingChunk = $leadingChunk.Substring(0, 2048)
        }
        $htmlGuardPattern = '<!' + 'DOCTYPE\s+' + 'html|<' + 'html\b|<' + 'head\b|<' + 'body\b'
        if ($leadingChunk -match '^\s*(' + $htmlGuardPattern + ')') { return $false }
        return ($textNormalized -match '(?m)^#Requires\s+-Version\s+5\.1' -or $textNormalized -match '(?m)^Set-StrictMode\s+-Version\s+Latest' -or $textNormalized -match '(?m)^\[CmdletBinding\(\)\]')
    } catch {
        return $false
    }
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
            $null = & $curl.Source '--silent' '--show-error' '--fail' '--location' '--output' $Destination $Url 2>&1
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch { }
    }

    return $false
}

function Sync-CoreScriptsBestEffort {
    $base = Get-UpdateBaseUrl
    if (-not $base) {
        Write-UpdateLog 'Core sync skipped: no update base URL configured.'
        return
    }

    $installDir = if ($cfg.ContainsKey('INSTALL_DIR') -and $cfg['INSTALL_DIR']) { $cfg['INSTALL_DIR'] } else { Split-Path -Parent $ConfigFile }
    if (-not $installDir) {
        Write-UpdateLog 'Core sync skipped: install directory could not be resolved.'
        return
    }

    Write-UpdateLog ("Core sync started (base={0}, install_dir={1})." -f $base, $installDir)

    $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $items = @(
        @{ rel = 'client/windows/collect_and_send.ps1'; target = Join-Path $installDir 'collect_and_send.ps1'; isScript = $true },
        @{ rel = 'client/windows/self_update.ps1'; target = Join-Path $installDir 'self_update.ps1'; isScript = $true },
        @{ rel = 'client/windows/setup_harvest_sql_user.ps1'; target = Join-Path $installDir 'setup_harvest_sql_user.ps1'; isScript = $true },
        @{ rel = 'client/windows/collect_and_scan_sap_tables.ps1'; target = Join-Path $installDir 'collect_and_scan_sap_tables.ps1'; isScript = $true },
        @{ rel = 'AGENT_VERSION'; target = $VersionFile; isScript = $false }
    )

    foreach ($item in $items) {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            $url = "{0}/{1}?cb={2}" -f $base, $item.rel, $cacheBust
            if (-not (Download-FileBestEffort -Url $url -Destination $tmp)) {
                Write-UpdateLog ("Core sync download failed: {0} ({1})." -f $item.rel, $url)
                continue
            }

            if ($item.isScript -and -not (Test-PowerShellScriptContent -Path $tmp)) {
                Write-UpdateLog ("Core sync rejected invalid script content: {0}." -f $item.rel)
                continue
            }

            $copied = $false
            try {
                Copy-Item $tmp $item.target -Force -ErrorAction Stop
                $copied = $true
            } catch {
                Write-UpdateLog ("Core sync copy failed: {0} -> {1} ({2})." -f $item.rel, $item.target, $_.Exception.Message)
            }

            if (-not $copied) {
                try {
                    [System.IO.File]::Copy($tmp, $item.target, $true)
                    $copied = $true
                    Write-UpdateLog ("Core sync fallback copy succeeded: {0} -> {1}." -f $item.rel, $item.target)
                } catch {
                    Write-UpdateLog ("Core sync fallback copy failed: {0} -> {1} ({2})." -f $item.rel, $item.target, $_.Exception.Message)
                }
            }

            if (-not $copied -and $item.rel -eq 'client/windows/collect_and_send.ps1') {
                $pendingTarget = $item.target + '.pending'
                try {
                    Copy-Item $tmp $pendingTarget -Force -ErrorAction Stop
                    Write-UpdateLog ("Core sync staged pending collect update: {0}." -f $pendingTarget)
                } catch {
                    Write-UpdateLog ("Core sync pending staging failed: {0} ({1})." -f $pendingTarget, $_.Exception.Message)
                }
            }

            if ($copied) {
                Write-UpdateLog ("Core sync updated: {0}." -f $item.rel)
            }
        } catch {
            Write-UpdateLog ("Core sync unexpected error for {0}: {1}." -f $item.rel, $_.Exception.Message)
        } finally {
            if (Test-Path $tmp) {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-UpdateLog 'Core sync completed.'
}

function Apply-PendingCoreScriptUpdate {
    $installDir = if ($cfg.ContainsKey('INSTALL_DIR') -and $cfg['INSTALL_DIR']) { $cfg['INSTALL_DIR'] } else { Split-Path -Parent $ConfigFile }
    if (-not $installDir) { return }

    $target = Join-Path $installDir 'collect_and_send.ps1'
    $pending = $target + '.pending'
    if (-not (Test-Path $pending)) { return }

    try {
        Copy-Item $pending $target -Force -ErrorAction Stop
        Remove-Item $pending -Force -ErrorAction SilentlyContinue
        Write-UpdateLog ("Applied pending collect update: {0}." -f $target)
    } catch {
        Write-UpdateLog ("Failed to apply pending collect update: {0} ({1})." -f $target, $_.Exception.Message)
    }
}

function Ensure-OptionalSapScanScript {
    $installDir = if ($cfg.ContainsKey('INSTALL_DIR') -and $cfg['INSTALL_DIR']) { $cfg['INSTALL_DIR'] } else { Split-Path -Parent $ConfigFile }
    if (-not $installDir) { return }

    $targetScript = Join-Path $installDir 'collect_and_scan_sap_tables.ps1'
    if (Test-Path $targetScript) {
        return
    }

    $updateBases = Get-UpdateBaseCandidates
    if ($updateBases.Count -eq 0) {
        return
    }

    $tmpScript = $null
    try {
        $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.ps1')
        $downloaded = $false
        foreach ($updateBase in $updateBases) {
            try {
                $uri = ($updateBase.TrimEnd('/')) + '/client/windows/collect_and_scan_sap_tables.ps1'
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($uri, $tmpScript)
                $downloaded = $true
                break
            } catch {
                continue
            }
        }
        if (-not $downloaded) {
            return
        }

        # Basic guard against HTML/proxy responses.
        $text = [System.IO.File]::ReadAllText($tmpScript, [System.Text.Encoding]::UTF8)
        $text = $text -replace "`0", ''
        $textNormalized = $text -replace '^[\uFEFF]+', ''
        $leadingChunk = $textNormalized
        if ($leadingChunk.Length -gt 2048) {
            $leadingChunk = $leadingChunk.Substring(0, 2048)
        }
        $htmlGuardPattern = '<!' + 'DOCTYPE\s+' + 'html|<' + 'html\b|<' + 'head\b|<' + 'body\b'
        if ($leadingChunk -match '^\s*(' + $htmlGuardPattern + ')') {
            throw 'Downloaded collect_and_scan_sap_tables.ps1 appears to be HTML content.'
        }

        Copy-Item $tmpScript $targetScript -Force
    } catch {
        # Optional bootstrap only; never block normal collect.
    } finally {
        if ($tmpScript -and (Test-Path $tmpScript)) {
            Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
        }
    }
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
                $updateResult = Invoke-AgentSelfUpdate
                $isOk = $false
                $resultMessage = 'update command failed'
                if ($updateResult -is [System.Collections.IDictionary]) {
                    $isOk = [bool]$updateResult['ok']
                    $candidateMessage = [string]$updateResult['message']
                    if ($candidateMessage) {
                        $resultMessage = $candidateMessage
                    }
                }
                if ($isOk) {
                    Send-CommandResult -CommandId $cmdId -Status 'completed' -Message $resultMessage
                } else {
                    if (Should-TreatUpdateFailureAsSoftSuccess -FailureMessage $resultMessage) {
                        $localVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile
                        $softMessage = "update source unreachable; agent stays on $localVersion"
                        if ($resultMessage) {
                            $softMessage = "$softMessage | $resultMessage"
                        }
                        Send-CommandResult -CommandId $cmdId -Status 'completed' -Message $softMessage
                    } else {
                        Send-CommandResult -CommandId $cmdId -Status 'failed' -Message $resultMessage
                    }
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

function Get-SapLicenseInfo {
    $licenseInfo = @{
        available = $false
        hardware_key = ""
        instno = ""
        expiration = ""
        system_nr = ""
        customer_name = ""
        customer_no = ""
        file_mtime_utc = ""
        focus_license_types = @()
    }
    
    try {
        # Try multiple possible locations (with fallback paths)
        $licensePaths = @(
            'C:\ANG\Lizenzen\B01.txt',
            'C:\ANG\Lizenz\B01.txt',
            'C:\ANG\B01.txt',
            'C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenz\B01.txt',
            'C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenzen\B01.txt'
        )
        
        $licensePath = $null
        foreach ($path in $licensePaths) {
            if (Test-Path $path) {
                $licensePath = $path
                break
            }
        }
        
        if (-not $licensePath) {
            return $licenseInfo
        }

        try {
            $fileInfo = Get-Item -LiteralPath $licensePath -ErrorAction Stop
            $licenseInfo.file_mtime_utc = $fileInfo.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
        } catch { }
        
        $content = [System.IO.File]::ReadAllText($licensePath, [System.Text.Encoding]::UTF8)
        if (-not $content) {
            return $licenseInfo
        }
        
        # Try to extract from block format first, otherwise use whole content
        $blockContent = $content
        if ($content -match '-----\s*Begin SAP License\s*-----([^-]*?)-----\s*End SAP License\s*-----') {
            $blockContent = $Matches[1]
        }
        
        # Extract license fields from content (works for both block and plain key=value format)
        if ($blockContent -match 'HARDWARE-KEY\s*=\s*([^\r\n]+)') {
            $licenseInfo.hardware_key = $Matches[1].Trim()
        }
        if ($blockContent -match 'INSTNO\s*=\s*([^\r\n]+)') {
            $licenseInfo.instno = $Matches[1].Trim()
        }
        if ($blockContent -match 'EXPIRATION\s*=\s*([^\r\n]+)') {
            $licenseInfo.expiration = $Matches[1].Trim()
        }
        if ($blockContent -match 'SYSTEM-NR\s*=\s*([^\r\n]+)') {
            $licenseInfo.system_nr = $Matches[1].Trim()
        }
        if ($blockContent -match 'CUSTOMER-NAME\s*=\s*([^\r\n]+)') {
            $licenseInfo.customer_name = $Matches[1].Trim()
        }
        if ($blockContent -match 'CUSTOMER-NO\s*=\s*([^\r\n]+)') {
            $licenseInfo.customer_no = $Matches[1].Trim()
        }

        # Extract and aggregate ALL license types with their counts
        $countsByType = @{}
        $currentProductName = $null
        foreach ($line in ($content -split "`r?`n")) {
            if ($line -match '^\s*SWPRODUCTNAME\s*=\s*(.+?)\s*$') {
                $currentProductName = $Matches[1].Trim()
                continue
            }
            if ($line -match '^\s*SWPRODUCTLIMIT\s*=\s*(.+?)\s*$') {
                if ($currentProductName) {
                    $countValue = 0
                    [void][int]::TryParse($Matches[1].Trim(), [ref]$countValue)
                    if ($countsByType.ContainsKey($currentProductName)) {
                        $countsByType[$currentProductName] += $countValue
                    } else {
                        $countsByType[$currentProductName] = $countValue
                    }
                }
                $currentProductName = $null
            }
        }
        foreach ($licenseType in ($countsByType.Keys | Sort-Object)) {
            $licenseInfo.focus_license_types += @{
                license_type = [string]$licenseType
                count = [int]$countsByType[$licenseType]
            }
        }
        
        if ($licenseInfo.hardware_key -or $licenseInfo.instno) {
            $licenseInfo.available = $true
        }
    } catch {
        # Silently ignore any license read errors
    }
    
    return $licenseInfo
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

Apply-PendingCoreScriptUpdate
Sync-CoreScriptsBestEffort

$hostnameValue = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
if (-not $hostnameValue) { $hostnameValue = $env:COMPUTERNAME }

$osInfo      = Get-CimInstance -ClassName Win32_OperatingSystem
$cpuInfoList = @(Get-CimInstance -ClassName Win32_Processor)

# Agent identity
$agentId     = if ($cfg.ContainsKey('AGENT_ID')      -and $cfg['AGENT_ID'])      { $cfg['AGENT_ID'] }      else { $hostnameValue }
$displayName = if ($cfg.ContainsKey('DISPLAY_NAME')  -and $cfg['DISPLAY_NAME'])  { $cfg['DISPLAY_NAME'] }  else { $hostnameValue }
$hostUidValue = if ($cfg.ContainsKey('HOST_UID') -and $cfg['HOST_UID']) { [string]$cfg['HOST_UID'] } else { '' }
if (-not $hostUidValue) {
    $machineGuid = ''
    try {
        $machineGuid = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop).MachineGuid
    } catch {
        $machineGuid = ''
    }
    $machineGuid = ($machineGuid -replace '\s+', '').Trim()

    if ($machineGuid) {
        $hostUidValue = "$hostnameValue::mid:$machineGuid"
    } elseif ($agentId) {
        $hostUidValue = "$hostnameValue::agent:$agentId"
    } else {
        $hostUidValue = $hostnameValue
    }
}

if (-not $NoJitter -and $SendJitterMaxSec -gt 0) {
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

# CPU cores and model name
$cpuCores = ($cpuInfoList | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
if (-not $cpuCores -or $cpuCores -lt 1) { $cpuCores = 1 }
$cpuModelName = if ($cpuInfoList.Count -gt 0 -and $cpuInfoList[0].Name) { $cpuInfoList[0].Name } else { 'unknown' }

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
$updateLogJson   = Get-UpdateLogBlock
$agentConfigJson = Get-AgentConfigBlock
$sapB1Json       = Get-SapB1PayloadBlock
$sqlServerJson   = Get-SqlServerInfoBlock
$largeFilesJson  = '{"enabled":false,"status":"unsupported","filesystems":[]}'
$licenseInfo     = Get-SapLicenseInfo

Invoke-RemoteCommands
Invoke-PrioritySelfUpdate
Ensure-OptionalSapScanScript

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
$hostUidEsc      = ConvertTo-JsonString $hostUidValue
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
$licenseAvailableStr = if ($licenseInfo.available) { 'true' } else { 'false' }
$hardwareKeyEsc = ConvertTo-JsonString $licenseInfo.hardware_key
$instnoEsc = ConvertTo-JsonString $licenseInfo.instno
$expirationEsc = ConvertTo-JsonString $licenseInfo.expiration
$systemNrEsc = ConvertTo-JsonString $licenseInfo.system_nr
$customerNameEsc = ConvertTo-JsonString $licenseInfo.customer_name
$customerNoEsc = ConvertTo-JsonString $licenseInfo.customer_no
$licenseFileMtimeUtcEsc = ConvertTo-JsonString $licenseInfo.file_mtime_utc
$focusLicenseTypeEntries = @()
foreach ($focusType in @($licenseInfo.focus_license_types)) {
    $focusTypeNameEsc = ConvertTo-JsonString ([string]$focusType.license_type)
    $focusTypeCount = 0
    try {
        $focusTypeCount = [int]$focusType.count
    } catch {
        $focusTypeCount = 0
    }
    $focusLicenseTypeEntries += ('{"license_type":"' + $focusTypeNameEsc + '","count":' + $focusTypeCount + '}')
}
$focusLicenseTypesJson = '[' + ($focusLicenseTypeEntries -join ',') + ']'

$payload = @"
{
  "agent_id": "$agentIdEsc",
  "agent_version": "$agentVerEsc",
  "display_name": "$displayNameEsc",
  "hostname": "$hostnameEsc",
    "host_uid": "$hostUidEsc",
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
        "cores": $cpuCores,
        "model_name": "${cpuModelName}"
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
    "sql_server_info": $sqlServerJson,
    "large_files": $largeFilesJson,
    "sap_license": {
        "available": $licenseAvailableStr,
        "hardware_key": "$hardwareKeyEsc",
        "instno": "$instnoEsc",
        "expiration": "$expirationEsc",
        "system_nr": "$systemNrEsc",
        "customer_name": "$customerNameEsc",
        "customer_no": "$customerNoEsc",
        "file_mtime_utc": "$licenseFileMtimeUtcEsc",
        "focus_license_types": $focusLicenseTypesJson
    }
}
"@

# ---- Debug output or Send ----
if ($DebugPayload) {
    Write-Host "=== DEBUG PAYLOAD ===" 
    Write-Host $payload
    exit 0
}

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
