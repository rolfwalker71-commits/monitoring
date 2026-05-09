#Requires -Version 5.1
<#
.SYNOPSIS
    Temporary SAP B1 table scan collector.
    Reads SELECT * from SBOCOMMON.dbo.SARI and SLDModel.SLDData.dbo.Extensions
    and sends the result as payload to the monitoring server.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$IC = [System.Globalization.CultureInfo]::InvariantCulture
$ConfigFile = if ($env:CONFIG_FILE) { $env:CONFIG_FILE } else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$VersionFile = if ($env:AGENT_VERSION_FILE) { $env:AGENT_VERSION_FILE } else { 'C:\ProgramData\monitoring-agent\AGENT_VERSION' }
$EmbeddedAgentVersion = '1.1.167'

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
$ApiKey = if ($cfg.ContainsKey('API_KEY')) { $cfg['API_KEY'] } else { '' }
if (-not $ServerUrl) {
    Write-Error 'SERVER_URL is not set in config'
    exit 1
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
    if ($fileVersion) { return $fileVersion }
    if ($EmbeddedVersion) { return [string]$EmbeddedVersion }
    return 'unknown'
}

function Invoke-ServerJsonPost {
    param(
        [string]$Uri,
        [string]$Body
    )

    $wc = New-Object System.Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::UTF8
    $wc.Headers.Add('Content-Type', 'application/json; charset=utf-8')
    if ($ApiKey) { $wc.Headers.Add('X-Api-Key', $ApiKey) }
    return $wc.UploadString($Uri, 'POST', $Body)
}

function Get-SqlConnection {
    param(
        [string]$Server,
        [string]$Database,
        [string]$User,
        [string]$Password
    )

    $conn = New-Object System.Data.SqlClient.SqlConnection
    $conn.ConnectionString = "Server=$Server;Database=$Database;User ID=$User;Password=$Password;TrustServerCertificate=True;Connection Timeout=15;"
    return $conn
}

function Invoke-SqlTable {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [int]$TimeoutSec = 120
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = $TimeoutSec
    $da = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $dt = New-Object System.Data.DataTable
    [void]$da.Fill($dt)
    return $dt
}

function Convert-DataTableRowsToObjectArray {
    param([System.Data.DataTable]$DataTable)

    $rows = @()
    if ($null -eq $DataTable) {
        return $rows
    }
    foreach ($row in $DataTable.Rows) {
        $obj = [ordered]@{}
        foreach ($col in $DataTable.Columns) {
            $name = [string]$col.ColumnName
            $val = $row[$name]
            if ($val -is [System.DBNull]) {
                $obj[$name] = $null
            } else {
                $obj[$name] = [string]$val
            }
        }
        $rows += [pscustomobject]$obj
    }
    return $rows
}

function Get-TableScanResult {
    param(
        [string]$SqlServer,
        [string]$Database,
        [string]$Schema,
        [string]$Table,
        [string]$SqlUser,
        [string]$SqlPassword
    )

    $result = [ordered]@{
        available = $false
        database = $Database
        schema = $Schema
        table = $Table
        row_count = 0
        error = ''
        rows = @()
    }

    $conn = $null
    try {
        $conn = Get-SqlConnection -Server $SqlServer -Database $Database -User $SqlUser -Password $SqlPassword
        $conn.Open()

        $safeSchema = $Schema.Replace(']', ']]')
        $safeTable = $Table.Replace(']', ']]')
        $query = "SELECT * FROM [$safeSchema].[$safeTable];"
        $dt = Invoke-SqlTable -Connection $conn -Query $query -TimeoutSec 300
        $rows = Convert-DataTableRowsToObjectArray -DataTable $dt

        $result.available = $true
        $result.rows = $rows
        $result.row_count = @($rows).Count
    } catch {
        $result.error = ($_.Exception.Message -replace '[\r\n]+', ' ')
    } finally {
        if ($conn) {
            $conn.Dispose()
        }
    }

    return [pscustomobject]$result
}

# Collector settings (temporary scan)
$SqlServerInstance = if ($cfg.ContainsKey('HARVEST_SQL_SERVER') -and $cfg['HARVEST_SQL_SERVER']) { $cfg['HARVEST_SQL_SERVER'] } else { '.' }
$HarvestSqlUser = if ($cfg.ContainsKey('HARVEST_SQL_USER') -and $cfg['HARVEST_SQL_USER']) { $cfg['HARVEST_SQL_USER'] } else { 'harvest' }
$HarvestSqlPassword = if ($cfg.ContainsKey('HARVEST_SQL_PASSWORD') -and $cfg['HARVEST_SQL_PASSWORD']) { $cfg['HARVEST_SQL_PASSWORD'] } else { '0djKUt&xbLK0AYr' }

$hostnameValue = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
if (-not $hostnameValue) { $hostnameValue = $env:COMPUTERNAME }
$agentId = if ($cfg.ContainsKey('AGENT_ID') -and $cfg['AGENT_ID']) { $cfg['AGENT_ID'] } else { $hostnameValue }
$displayName = if ($cfg.ContainsKey('DISPLAY_NAME') -and $cfg['DISPLAY_NAME']) { $cfg['DISPLAY_NAME'] } else { $hostnameValue }
$agentVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile

$sariResult = Get-TableScanResult -SqlServer $SqlServerInstance -Database 'SBOCOMMON' -Schema 'dbo' -Table 'SARI' -SqlUser $HarvestSqlUser -SqlPassword $HarvestSqlPassword
$extensionsResult = Get-TableScanResult -SqlServer $SqlServerInstance -Database 'SLDModel.SLDData' -Schema 'dbo' -Table 'Extensions' -SqlUser $HarvestSqlUser -SqlPassword $HarvestSqlPassword

$payloadObj = [ordered]@{
    agent_id = $agentId
    agent_version = $agentVersion
    display_name = $displayName
    hostname = $hostnameValue
    timestamp_utc = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $IC)
    delivery_mode = 'live'
    is_delayed = $false
    queued_at_utc = ''
    sap_business_one = [ordered]@{
        table_scan = [ordered]@{
            sbo_common_sari = $sariResult
            sld_extensions = $extensionsResult
        }
    }
}

$payloadJson = $payloadObj | ConvertTo-Json -Depth 20 -Compress
$uri = ($ServerUrl.TrimEnd('/')) + '/api/v1/agent-report'

try {
    Invoke-ServerJsonPost -Uri $uri -Body $payloadJson | Out-Null
    Write-Host "SAP table scan sent. SBOCOMMON.dbo.SARI rows: $($sariResult.row_count), SLDModel.SLDData.dbo.Extensions rows: $($extensionsResult.row_count)"
} catch {
    Write-Error ("Failed to send SAP table scan payload: " + $_.Exception.Message)
    exit 1
}
