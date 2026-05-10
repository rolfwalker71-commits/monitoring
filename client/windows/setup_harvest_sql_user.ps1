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

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigFile = if ($env:CONFIG_FILE) { $env:CONFIG_FILE } else { 'C:\ProgramData\monitoring-agent\agent.conf' }
$HarvestUser = 'harvest'
$HarvestPassword = '0djKUt&xbLK0AYr'

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
        error = ''
    }

    $conn = $null
    try {
        # Connect as admin (integrated auth)
        $conn = Get-SqlConnection -Server $SqlServer -Database 'master'
        $conn.Open()

        # Check if login exists
        $loginExists = Invoke-SqlScalar -Connection $conn -Query "SELECT COUNT(*) FROM sys.syslogins WHERE name = '$HarvestUser'"
        $result.user_exists = [int]$loginExists -gt 0

        if (-not $result.user_exists) {
            # Create login with SQL auth
            $escapedPwd = $HarvestPassword.Replace("'", "''")
            Invoke-SqlNonQuery -Connection $conn -Query "CREATE LOGIN [$HarvestUser] WITH PASSWORD = N'$escapedPwd'"
            $result.user_created = $true
        }

        # Grant server-level permissions
        Invoke-SqlNonQuery -Connection $conn -Query "GRANT VIEW SERVER STATE TO [$HarvestUser]"
        Invoke-SqlNonQuery -Connection $conn -Query "GRANT VIEW ANY DEFINITION TO [$HarvestUser]"
        $result.permissions_granted = $true

        # Find accessible databases
        $conn.Close()
        $conn = Get-SqlConnection -Server $SqlServer -Database 'master' -User $HarvestUser -Password $HarvestPassword
        $conn.Open()

        $dbRows = $conn.Execute("SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' ORDER BY name").Rows
        foreach ($row in $dbRows) {
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
    $result = Setup-HarvestUser -SqlServer $server -HarvestUser $HarvestUser -HarvestPassword $HarvestPassword
    $setupResults += $result

    if ($result.success) {
        $successResult = $result
        Write-Host "✅ Setup successful on $server"
        if ($result.user_created) {
            Write-Host "   - User created"
        } else {
            Write-Host "   - User already exists"
        }
        if ($result.permissions_granted) {
            Write-Host "   - Permissions granted"
        }
        Write-Host "   - Accessible databases: $($result.accessible_databases -join ', ')"
        break
    } else {
        Write-Host "❌ Setup failed on $server : $($result.error)"
    }
}

if ($successResult) {
    Write-Host "Updating agent.conf with harvest settings..."
    Update-ConfigFile -ConfigPath $ConfigFile -SqlServer $successResult.server -HarvestUser $HarvestUser -HarvestPassword $HarvestPassword
    Write-Host "✅ agent.conf updated"
    Write-Host "Setup complete on server: $($successResult.server)"
    exit 0
} else {
    Write-Host "❌ Harvest user setup failed on all servers"
    exit 1
}
