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
$EmbeddedAgentVersion = '1.4.42'

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

function Get-SqlServerCandidates {
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($cfg.ContainsKey('HARVEST_SQL_SERVER') -and $cfg['HARVEST_SQL_SERVER']) {
        $parts = [string]$cfg['HARVEST_SQL_SERVER'] -split '[,;]'
        foreach ($part in $parts) {
            $v = ([string]$part).Trim()
            if ($v -and -not $candidates.Contains($v)) {
                $candidates.Add($v)
            }
        }
    }

    if ($candidates.Count -eq 0) {
        foreach ($base in @('.', 'localhost')) {
            if (-not $candidates.Contains($base)) {
                $candidates.Add($base)
            }
        }

        $regPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        try {
            if (Test-Path $regPath) {
                $instanceMap = Get-ItemProperty -Path $regPath -ErrorAction Stop
                foreach ($prop in $instanceMap.PSObject.Properties) {
                    if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                    $instanceName = [string]$prop.Name
                    if (-not $instanceName) { continue }

                    if ($instanceName -ieq 'MSSQLSERVER') {
                        foreach ($base in @('.', 'localhost', $env:COMPUTERNAME)) {
                            if ($base -and -not $candidates.Contains($base)) {
                                $candidates.Add($base)
                            }
                        }
                    } else {
                        foreach ($base in @('.', 'localhost', $env:COMPUTERNAME)) {
                            if (-not $base) { continue }
                            $name = "$base\$instanceName"
                            if (-not $candidates.Contains($name)) {
                                $candidates.Add($name)
                            }
                        }
                    }
                }
            }
        } catch {
            # Ignore registry discovery errors and keep defaults.
        }
    }

    return @($candidates)
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
    Write-Output -NoEnumerate $dt
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

function Normalize-ScanRows {
    param($Rows)

    if ($null -eq $Rows) {
        return @()
    }

    if ($Rows -is [System.Array]) {
        return @($Rows)
    }

    if (($Rows -is [System.Collections.IEnumerable]) -and -not ($Rows -is [string])) {
        # Some PowerShell collection wrappers expose a `value` + `Count` shape.
        $hasValueProp = $Rows.PSObject.Properties.Name -contains 'value'
        $hasCountProp = $Rows.PSObject.Properties.Name -contains 'Count'
        if ($hasValueProp -and $hasCountProp) {
            $inner = $Rows.value
            if ($null -eq $inner) {
                return @()
            }
            if (($inner -is [System.Collections.IEnumerable]) -and -not ($inner -is [string])) {
                return @($inner)
            }
            return @($inner)
        }
        return @($Rows)
    }

    return @($Rows)
}

function Get-TableScanResult {
    param(
        [string]$SqlServer,
        [string]$Database,
        [string]$Schema,
        [string]$Table,
        [string[]]$PreferredColumns,
        [string]$SqlUser,
        [string]$SqlPassword
    )

    $result = [ordered]@{
        available = $false
        sql_server = $SqlServer
        database = $Database
        schema = $Schema
        table = $Table
        columns = @()
        column_count = 0
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
        $safeSchemaLiteral = $Schema.Replace("'", "''")
        $safeTableLiteral = $Table.Replace("'", "''")

        $columnsQuery = "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '$safeSchemaLiteral' AND TABLE_NAME = '$safeTableLiteral' ORDER BY ORDINAL_POSITION;"
        $columnsDt = Invoke-SqlTable -Connection $conn -Query $columnsQuery -TimeoutSec 120
        $columns = @()
        if ($columnsDt) {
            foreach ($colRow in $columnsDt.Rows) {
                $colName = [string]$colRow['COLUMN_NAME']
                if ($colName) {
                    $columns += $colName
                }
            }
        }

        $selectedColumns = @()
        if ($PreferredColumns -and $PreferredColumns.Count -gt 0) {
            foreach ($preferred in $PreferredColumns) {
                $match = $columns | Where-Object { $_ -ieq $preferred } | Select-Object -First 1
                if ($match -and -not ($selectedColumns -contains $match)) {
                    $selectedColumns += $match
                }
            }
        }
        if ($selectedColumns.Count -eq 0) {
            $selectedColumns = @($columns | Select-Object -First 8)
        }

        $countQuery = "SELECT COUNT(*) AS cnt FROM [$safeSchema].[$safeTable];"
        $countDt = Invoke-SqlTable -Connection $conn -Query $countQuery -TimeoutSec 120
        $rowCount = 0
        if ($countDt -and $countDt.Rows.Count -gt 0) {
            try {
                $rowCount = [int]$countDt.Rows[0]['cnt']
            } catch {
                $rowCount = 0
            }
        }

        $rows = @()
        if ($rowCount -gt 0) {
            $selectList = if ($selectedColumns.Count -gt 0) {
                ($selectedColumns | ForEach-Object { '[' + ($_.Replace(']', ']]')) + ']' }) -join ', '
            } else {
                '*'
            }
            $query = "SELECT TOP (1) $selectList FROM [$safeSchema].[$safeTable];"
            $dt = Invoke-SqlTable -Connection $conn -Query $query -TimeoutSec 300
            $rows = Convert-DataTableRowsToObjectArray -DataTable $dt
        }

        $result.available = $true
        $result.columns = @($selectedColumns)
        $result.column_count = $selectedColumns.Count
        $result.rows = Normalize-ScanRows -Rows $rows
        $result.row_count = $rowCount
    } catch {
        $result.error = ($_.Exception.Message -replace '[\r\n]+', ' ')
    } finally {
        if ($conn) {
            $conn.Dispose()
        }
    }

    return [pscustomobject]$result
}

function Get-FirstAvailableTableScanResult {
    param(
        [string[]]$SqlServers,
        [string[]]$Databases,
        [string]$Schema,
        [string]$Table,
        [string[]]$PreferredColumns,
        [string]$SqlUser,
        [string]$SqlPassword
    )

    $errors = @()
    $firstEmpty = $null
    foreach ($serverName in $SqlServers) {
        foreach ($dbName in $Databases) {
            $result = Get-TableScanResult -SqlServer $serverName -Database $dbName -Schema $Schema -Table $Table -PreferredColumns $PreferredColumns -SqlUser $SqlUser -SqlPassword $SqlPassword
            if ($result.available -eq $true) {
                if ([int]$result.row_count -gt 0) {
                    return $result
                }
                if ($null -eq $firstEmpty) {
                    $firstEmpty = $result
                }
                continue
            }
            if ($result.error) {
                $errors += ("{0}/{1}: {2}" -f $serverName, $dbName, $result.error)
            }
        }
    }

    if ($firstEmpty -ne $null) {
        $firstEmpty.error = if (@($errors).Count -gt 0) {
            ('No rows in scanned table. Attempts: ' + ($errors -join ' | '))
        } else {
            'No rows in scanned table.'
        }
        return $firstEmpty
    }

    $fallbackDb = if (@($Databases).Count -gt 0) { $Databases[0] } else { '' }
    $fallbackServer = if (@($SqlServers).Count -gt 0) { $SqlServers[0] } else { '' }
    $fallback = [ordered]@{
        available = $false
        sql_server = $fallbackServer
        database = $fallbackDb
        schema = $Schema
        table = $Table
        columns = @()
        column_count = 0
        row_count = 0
        error = if (@($errors).Count -gt 0) { ($errors -join ' | ') } else { 'No matching database candidate available.' }
        rows = @()
    }
    return [pscustomobject]$fallback
}

# Collector settings (temporary scan)
$SqlServerCandidates = Get-SqlServerCandidates
$HarvestSqlUser = if ($cfg.ContainsKey('HARVEST_SQL_USER') -and $cfg['HARVEST_SQL_USER']) { $cfg['HARVEST_SQL_USER'] } else { 'harvest' }
$HarvestSqlPassword = if ($cfg.ContainsKey('HARVEST_SQL_PASSWORD') -and $cfg['HARVEST_SQL_PASSWORD']) { $cfg['HARVEST_SQL_PASSWORD'] } else { '0djKUt&xbLK0AYr' }

$hostnameValue = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
if (-not $hostnameValue) { $hostnameValue = $env:COMPUTERNAME }
$agentId = if ($cfg.ContainsKey('AGENT_ID') -and $cfg['AGENT_ID']) { $cfg['AGENT_ID'] } else { $hostnameValue }
$displayName = if ($cfg.ContainsKey('DISPLAY_NAME') -and $cfg['DISPLAY_NAME']) { $cfg['DISPLAY_NAME'] } else { $hostnameValue }
$agentVersion = Select-AgentVersion -EmbeddedVersion $EmbeddedAgentVersion -FilePath $VersionFile

$sariDbCandidates = @('SBO-COMMON', 'SBOCOMMON')
$extensionsDbCandidates = @('SLDModel.SLDData', 'SLDMODEL.SLDDATA')
$sariPreferredColumns = @('AddOnId', 'NameSpace', 'AName', 'AddOnVer', 'ClientType', 'UpgChkSumX')
$extensionsPreferredColumns = @('Id', 'Name', 'Version', 'Vendor', 'Type', 'Status', 'ClientType', 'LastUpdated')
$sariResult = Get-FirstAvailableTableScanResult -SqlServers $SqlServerCandidates -Databases $sariDbCandidates -Schema 'dbo' -Table 'SARI' -PreferredColumns $sariPreferredColumns -SqlUser $HarvestSqlUser -SqlPassword $HarvestSqlPassword
$extensionsResult = Get-FirstAvailableTableScanResult -SqlServers $SqlServerCandidates -Databases $extensionsDbCandidates -Schema 'dbo' -Table 'Extensions' -PreferredColumns $extensionsPreferredColumns -SqlUser $HarvestSqlUser -SqlPassword $HarvestSqlPassword

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
    Write-Host "SAP table scan sent. $($sariResult.sql_server)/$($sariResult.database).dbo.SARI rows: $($sariResult.row_count), $($extensionsResult.sql_server)/$($extensionsResult.database).dbo.Extensions rows: $($extensionsResult.row_count)"
    if ($sariResult.error) {
        Write-Host "SARI scan info: $($sariResult.error)" -ForegroundColor Yellow
    }
    if ($extensionsResult.error) {
        Write-Host "Extensions scan info: $($extensionsResult.error)" -ForegroundColor Yellow
    }
} catch {
    Write-Error ("Failed to send SAP table scan payload: " + $_.Exception.Message)
    exit 1
}
