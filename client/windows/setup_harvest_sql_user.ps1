#Requires -Version 5.1
<#
.SYNOPSIS
    Sets up SQL harvest user for SAP B1 monitoring.
    Creates login, grants permissions, and updates agent.conf.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Legacy compatibility marker for older updater validators.
# Find-SqlServers

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigFile = if ($env:CONFIG_FILE) { $env:CONFIG_FILE } else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$HarvestUser = 'harvest'
$HarvestPassword = '0djKUt&xbLK0AYr'
$SetupAdminUser = ''
$SetupAdminPassword = ''

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

if ($cfg.ContainsKey('HARVEST_SETUP_SQL_ADMIN_USER') -and $cfg['HARVEST_SETUP_SQL_ADMIN_USER']) {
    $SetupAdminUser = [string]$cfg['HARVEST_SETUP_SQL_ADMIN_USER']
}
if ($cfg.ContainsKey('HARVEST_SETUP_SQL_ADMIN_PASSWORD') -and $cfg['HARVEST_SETUP_SQL_ADMIN_PASSWORD']) {
    $SetupAdminPassword = [string]$cfg['HARVEST_SETUP_SQL_ADMIN_PASSWORD']
}

function Get-SqlConnection {
    param(
        [string]$Server,
        [string]$Database = 'master',
        [string]$User = '',
        [string]$Password = ''
    )
    $conn = New-Object System.Data.SqlClient.SqlConnection
    if ($User) {
        $conn.ConnectionString = "Server=$Server;Database=$Database;User ID=$User;Password=$Password;TrustServerCertificate=True;Connection Timeout=15;"
    } else {
        $conn.ConnectionString = "Server=$Server;Database=$Database;Integrated Security=true;TrustServerCertificate=True;Connection Timeout=15;"
    }
    return $conn
}

function Invoke-SqlNonQuery {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [int]$TimeoutSec = 30
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = $TimeoutSec
    return $cmd.ExecuteNonQuery()
}

function Invoke-SqlScalar {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [int]$TimeoutSec = 30
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = $TimeoutSec
    return $cmd.ExecuteScalar()
}

function Invoke-SqlQuery {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [int]$TimeoutSec = 30
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = $TimeoutSec
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $table = New-Object System.Data.DataTable
    [void]$adapter.Fill($table)
    return ,$table
}

function Get-SqlServerCandidates {
    $candidates = New-Object System.Collections.Generic.List[string]
    $hasConfiguredCandidates = $false

    if ($cfg.ContainsKey('HARVEST_SQL_SERVER') -and $cfg['HARVEST_SQL_SERVER']) {
        $parts = [string]$cfg['HARVEST_SQL_SERVER'] -split '[,;]'
        foreach ($part in $parts) {
            $v = ([string]$part).Trim()
            if ($v -and -not $candidates.Contains($v)) {
                $candidates.Add($v)
                $hasConfiguredCandidates = $true
            }
        }
    }

    $computerName = [string]$env:COMPUTERNAME
    $genericLocalAliases = @('.', 'localhost', '(local)', $computerName) | Where-Object { $_ }
    $genericLocalSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($alias in $genericLocalAliases) {
        [void]$genericLocalSet.Add([string]$alias)
    }

    $shouldDiscoverLocalInstances = $false
    if (-not $hasConfiguredCandidates) {
        $shouldDiscoverLocalInstances = $true
    } else {
        # If only generic local aliases are configured (e.g. localhost), still auto-discover named instances.
        $onlyGenericLocalConfigured = $true
        foreach ($candidate in $candidates) {
            $cand = [string]$candidate
            if ($cand.Contains('\')) {
                $onlyGenericLocalConfigured = $false
                break
            }
            if (-not $genericLocalSet.Contains($cand)) {
                $onlyGenericLocalConfigured = $false
                break
            }
        }
        $shouldDiscoverLocalInstances = $onlyGenericLocalConfigured
    }

    if (-not $hasConfiguredCandidates) {
        foreach ($base in @('.', 'localhost', $env:COMPUTERNAME)) {
            if ($base -and -not $candidates.Contains($base)) {
                $candidates.Add($base)
            }
        }
    }

    if ($shouldDiscoverLocalInstances) {
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
            # Ignore registry discovery errors
        }
    }

    return @($candidates)
}

function Setup-HarvestUser {
    param(
        [string]$SqlServer,
        [string]$HarvestUser,
        [string]$HarvestPassword
    )

    $result = @{
        success = $false
        server = $SqlServer
        user_created = $false
        user_exists = $false
        permissions_granted = $false
        accessible_databases = @()
        warnings = @()
        admin_connection = ''
        error = ''
    }

    $conn = $null
    try {
        # Connect as admin (integrated auth first, optional SQL admin fallback)
        $adminAttempts = @(@{ Label = 'Integrated Security'; User = ''; Password = '' })
        if ($SetupAdminUser -and $SetupAdminPassword) {
            $adminAttempts += @{ Label = "SQL Login ($SetupAdminUser)"; User = $SetupAdminUser; Password = $SetupAdminPassword }
        }

        $adminConnectErrors = New-Object System.Collections.Generic.List[string]
        foreach ($attempt in $adminAttempts) {
            try {
                if ($conn) { $conn.Dispose(); $conn = $null }
                $conn = Get-SqlConnection -Server $SqlServer -Database 'master' -User ([string]$attempt.User) -Password ([string]$attempt.Password)
                $conn.Open()
                $result.admin_connection = [string]$attempt.Label
                break
            } catch {
                $adminConnectErrors.Add("$($attempt.Label): $($_.Exception.Message)")
            }
        }

        if (-not $conn -or $conn.State -ne [System.Data.ConnectionState]::Open) {
            $hint = ""
            if (-not ($SetupAdminUser -and $SetupAdminPassword)) {
                $hint = " Hint: Configure HARVEST_SETUP_SQL_ADMIN_USER/HARVEST_SETUP_SQL_ADMIN_PASSWORD in agent.conf for SQL-auth setup fallback."
            }
            $result.error = "No admin connection possible. $($adminConnectErrors -join ' | ')$hint"
            return $result
        }

        # Check if login exists
        $loginExists = Invoke-SqlScalar -Connection $conn -Query "SELECT COUNT(*) FROM sys.server_principals WHERE name = '$HarvestUser'"
        $result.user_exists = [int]$loginExists -gt 0

        if (-not $result.user_exists) {
            # Create login with SQL auth
            $escapedPwd = $HarvestPassword.Replace("'", "''")
            try {
                [void](Invoke-SqlNonQuery -Connection $conn -Query "CREATE LOGIN [$HarvestUser] WITH PASSWORD = N'$escapedPwd'")
                $result.user_created = $true
                $result.user_exists = $true
            } catch {
                $result.error = "Failed to create login [$HarvestUser] on $SqlServer using $($result.admin_connection): $($_.Exception.Message)"
                return $result
            }
        }

        # Grant server-level permissions (best effort; continue if grantor lacks rights)
        $serverGrantOk = $true
        foreach ($grantQuery in @(
            "GRANT VIEW SERVER STATE TO [$HarvestUser]",
            "GRANT VIEW ANY DEFINITION TO [$HarvestUser]"
        )) {
            try {
                [void](Invoke-SqlNonQuery -Connection $conn -Query $grantQuery)
            } catch {
                $serverGrantOk = $false
                $result.warnings += "Server grant skipped: $($_.Exception.Message)"
            }
        }

        # Grant database-level read rights for all online non-system databases (best effort).
        $dbGrantFailures = 0
        $targetDbs = Invoke-SqlQuery -Connection $conn -Query "SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND database_id > 4 ORDER BY name"
        foreach ($dbRow in @($targetDbs.Rows)) {
            $dbName = [string]$dbRow['name']
            if (-not $dbName) { continue }
            $safeDbName = $dbName.Replace(']', ']]')
            try {
                [void](Invoke-SqlNonQuery -Connection $conn -Query "USE [$safeDbName]; IF USER_ID(N'$HarvestUser') IS NULL CREATE USER [$HarvestUser] FOR LOGIN [$HarvestUser]; ALTER ROLE [db_datareader] ADD MEMBER [$HarvestUser];")
            } catch {
                $dbGrantFailures += 1
                $result.warnings += "Database grant skipped for [$dbName]: $($_.Exception.Message)"
            }
        }

        $result.permissions_granted = $serverGrantOk -and ($dbGrantFailures -eq 0)

        # Find accessible databases
        $conn.Close()
        $conn = Get-SqlConnection -Server $SqlServer -Database 'master' -User $HarvestUser -Password $HarvestPassword
        $conn.Open()

        $dbRows = Invoke-SqlQuery -Connection $conn -Query "SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND HAS_DBACCESS(name) = 1 ORDER BY name"
        foreach ($row in @($dbRows.Rows)) {
            $dbName = [string]$row['name']
            if ($dbName -and $dbName -notin @('master', 'tempdb', 'model', 'msdb')) {
                $result.accessible_databases += $dbName
            }
        }

        $result.success = $true
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($conn) {
            $conn.Dispose()
        }
    }

    return $result
}

function Update-ConfigFile {
    param(
        [string]$ConfigPath,
        [string]$SqlServer,
        [string]$HarvestUser,
        [string]$HarvestPassword
    )

    $lines = @(Get-Content -Path $ConfigPath -Encoding UTF8)
    $updated = @{}

    # Parse existing
    foreach ($line in $lines) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
            $updated[$Matches[1]] = $Matches[2]
        } elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
            $updated[$Matches[1]] = $Matches[2]
        }
    }

    # Update harvest settings
    $updated['HARVEST_SQL_SERVER'] = $SqlServer
    $updated['HARVEST_SQL_USER'] = $HarvestUser
    $updated['HARVEST_SQL_PASSWORD'] = $HarvestPassword
    $updated['ENABLE_SAP_SCAN'] = '1'

    # Rebuild file
    $newLines = @()
    $processed = @{}

    foreach ($line in $lines) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=') {
            $key = $Matches[1]
            if ($key -in @('HARVEST_SQL_SERVER', 'HARVEST_SQL_USER', 'HARVEST_SQL_PASSWORD', 'ENABLE_SAP_SCAN')) {
                if (-not $processed.ContainsKey($key)) {
                    $newLines += "$key=`"$($updated[$key])`""
                    $processed[$key] = $true
                }
            } else {
                $newLines += $line
                $processed[$key] = $true
            }
        } else {
            $newLines += $line
        }
    }

    # Add missing harvest settings
    foreach ($key in @('HARVEST_SQL_SERVER', 'HARVEST_SQL_USER', 'HARVEST_SQL_PASSWORD', 'ENABLE_SAP_SCAN')) {
        if (-not $processed.ContainsKey($key)) {
            $newLines += "$key=`"$($updated[$key])`""
        }
    }

    Set-Content -Path $ConfigPath -Value $newLines -Encoding UTF8
}

# Main execution
Write-Host "Setting up SQL harvest user for SAP B1 monitoring..."

$serverCandidates = Get-SqlServerCandidates
Write-Host "SQL Server candidates: $($serverCandidates -join ', ')"

$setupResults = @()
$successResult = $null

foreach ($server in $serverCandidates) {
    Write-Host "Attempting setup on: $server"
    $attemptStart = Get-Date
    $result = Setup-HarvestUser -SqlServer $server -HarvestUser $HarvestUser -HarvestPassword $HarvestPassword
    $setupResults += $result
    $attemptSeconds = [math]::Round(((Get-Date) - $attemptStart).TotalSeconds, 1)

    if ($result.success) {
        $successResult = $result
        Write-Host "[OK] Setup successful on $server (${attemptSeconds}s)"
        if ($result.user_created) {
            Write-Host "   - User created"
        } else {
            Write-Host "   - User already exists"
        }
        if ($result.permissions_granted) {
            Write-Host "   - Permissions granted"
        } else {
            Write-Host "   - Permissions partially granted (best effort)"
        }
        if ($result.admin_connection) {
            Write-Host "   - Admin connection: $($result.admin_connection)"
        }
        foreach ($w in @($result.warnings)) {
            Write-Host "   - Warning: $w"
        }
        Write-Host "   - Accessible databases: $($result.accessible_databases -join ', ')"
        break
    } else {
        foreach ($w in @($result.warnings)) {
            Write-Host "   - Warning: $w"
        }
        Write-Host "[ERROR] Setup failed on $server (${attemptSeconds}s): $($result.error)"
    }
}

if ($successResult) {
    Write-Host "Updating agent.conf with harvest settings..."
    Update-ConfigFile -ConfigPath $ConfigFile -SqlServer $successResult.server -HarvestUser $HarvestUser -HarvestPassword $HarvestPassword
    Write-Host "[OK] agent.conf updated"
    Write-Host "Setup complete on server: $($successResult.server)"
    exit 0
} else {
    Write-Host "[ERROR] Harvest user setup failed on all servers"
    exit 1
}
