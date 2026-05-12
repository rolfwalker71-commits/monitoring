# Windows Agent – Technical Documentation

Complete technical reference for `collect_and_send.ps1` – the monitoring agent for Windows systems (HANA, SAP B1, SQL Server).

---

## Architecture Overview

```mermaid
graph TB
    subgraph Scheduler["Windows Scheduler<br/>Task Scheduler"]
        S1["Daily@04:00 UTC<br/>+ optional repeat<br/>every N minutes"]
    end
    
    subgraph Agent["collect_and_send.ps1"]
        A1["Initialize<br/>Set-StrictMode, TLS 1.2"]
        A2["Load Config<br/>agent.conf parsing"]
        A3["Ensure Harvest<br/>SQL credentials"]
        A4["Data Collection<br/>All metrics"]
        A5["JSON Assembly<br/>Payload creation"]
        A6["Send Report<br/>HTTP POST"]
    end
    
    subgraph Collection["Metrics Sources"]
        M1["System<br/>CPU, RAM, Uptime"]
        M2["Drives<br/>Letter, Usage %"]
        M3["SQL Server<br/>Databases, Size"]
        M4["HANA<br/>Databases, State"]
        M5["SAP B1<br/>Version, Tables"]
        M6["Processes<br/>Top 8 by CPU"]
        M7["Services<br/>Running status"]
        M8["Event Log<br/>Errors, Warnings"]
    end
    
    subgraph Network["Network"]
        N1["System.Net.WebClient<br/>POST x-api-key"]
    end
    
    subgraph Server["Monitoring Server"]
        S2["receiver.py:8080"]
    end
    
    subgraph Disk["Disk Storage"]
        D1["C:\ProgramData\<br/>monitoring-agent\"]
        D2["queue/"]
        D3["agent.conf"]
        D4["crash log"]
    end
    
    Scheduler --> A1
    A1 --> A2
    A2 --> A3
    A3 --> A4
    A4 --> M1 & M2 & M3 & M4 & M5 & M6 & M7 & M8
    M1 --> A5
    M2 --> A5
    M3 --> A5
    M4 --> A5
    M5 --> A5
    M6 --> A5
    M7 --> A5
    M8 --> A5
    A5 --> A6
    A6 --> N1
    N1 --> S2
    A6 --> D1
    A4 --> D4
```

---

## Execution Flow

```mermaid
sequenceDiagram
    participant Scheduler as Task Scheduler
    participant Script as collect_and_send.ps1
    participant Config as Config Parser
    participant Collect as Data Collector
    participant Network as WebClient
    participant Server as Server:8080
    
    Scheduler->>Script: Execute as SYSTEM<br/>(elevated)
    
    Script->>Script: Set-StrictMode -Version Latest
    Script->>Script: $ErrorActionPreference = 'Stop'
    Script->>Script: Trap: catch unhandled errors
    Script->>Script: Enable TLS 1.2
    Script->>Script: Set security protocol
    
    Script->>Config: Parse agent.conf<br/>regex: KEY="value"
    Config-->>Script: $cfg hash table
    
    Script->>Script: Ensure-HarvestSqlConfig()<br/>Create default credentials if needed
    
    Script->>Collect: Collect-System()
    Collect-->>Script: {os_version, ram_mb, cpu_cores}
    
    Script->>Collect: Collect-Drives()
    Collect-->>Script: [{letter, used_gb, total_gb}]
    
    Script->>Collect: Collect-SqlServer()
    Collect-->>Script: {databases, size_mb}
    
    Script->>Collect: Collect-Hana()
    Collect-->>Script: {version, databases}
    
    Script->>Collect: Collect-SapB1()
    Collect-->>Script: {version, table_count}
    
    Script->>Collect: Collect-Processes()
    Collect-->>Script: [top 8 by CPU%]
    
    Script->>Collect: Collect-EventLog()
    Collect-->>Script: [recent errors]
    
    Script->>Script: Build JSON payload
    
    Script->>Network: $client.UploadString()<br/>POST + x-api-key
    Network->>Server: HTTP 200 OK
    
    Script->>Script: Trap: on error → crash log
```

---

## Configuration System

### Config File Format

**Location:** `C:\ProgramData\monitoring-agent\agent.conf`

```powershell
# Server connection
SERVER_URL="https://monitoring.example.com"
X_API_KEY="secret-key-here"
TLS_INSECURE="0"

# System identification
AGENT_ID="win-sap01"
ENABLE_WIN_AUTH="0"

# SQL Server (local or remote)
HARVEST_SQL_SERVER="localhost"
HARVEST_SQL_USER="harvest"
HARVEST_SQL_PASSWORD="0djKUt&xbLK0AYr"
HARVEST_SQL_DB="Harvest"
ENABLE_SQL_MONITORING="1"

# SAP B1 (Windows installer)
SAP_B1_INSTALL_PATH="C:\Program Files\SAP\SAPBusinessOne\"
SAP_REGISTRY_PATH="HKLM:\Software\SAP\SAPBusinessOne\Setup\"
ENABLE_SAP_SCAN="1"

# HANA (if on same machine)
HANA_INSTANCE_NUMBER="00"
HANA_ADMIN_USER="SYSTEM"
HANA_ADMIN_PASSWORD="..."
ENABLE_HANA="1"

# Collection behavior
TOP_PROCESSES_LIMIT=8
EVENT_LOG_HOURS=24
EVENT_LOG_LIMIT=50
```

### Config Parsing

```powershell
# Pattern: KEY="value" or KEY=value
if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*?)"\s*$') {
    $cfg[$Matches[1]] = $Matches[2]  # Quoted value
} elseif ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)\s*$') {
    $cfg[$Matches[1]] = $Matches[2]  # Unquoted value
}
```

---

## Auto-Configuration: Harvest SQL Setup

```mermaid
graph LR
    A["Script startup"] --> B["Check:<br/>HARVEST_SQL_SERVER<br/>HARVEST_SQL_USER<br/>HARVEST_SQL_PASSWORD"]
    B --> C{All three<br/>present?}
    C -->|no| D["Call:<br/>Ensure-HarvestSqlConfig()"]
    D --> E["Write defaults:<br/>localhost<br/>harvest<br/>0djKUt..."]
    E --> F["Reload config"]
    F --> G["Proceed with<br/>SQL collection"]
    C -->|yes| G
```

**Idempotent Behavior:**
- Only adds credentials if ALL three are missing
- If only one is set, preserves existing values
- Never overwrites user-provided credentials

---

## Data Collection Modules

### System Metrics (`Collect-System`)

```mermaid
graph LR
    WMI["Win32_ComputerSystemProduct<br/>Win32_OperatingSystem<br/>Win32_Processor"]
    --> PARSE["Extract:<br/>- Windows version<br/>- Build number<br/>- RAM MB<br/>- CPU cores<br/>- Uptime"]
    --> JSON["Return<br/>{system: {...}}"]
```

**Fields:**
- `os_version`: e.g., "Windows Server 2019"
- `build_number`: e.g., "17763"
- `ram_mb`: Total RAM
- `cpu_cores`: Logical processor count
- `uptime_seconds`: Time since last boot

---

### Drive Monitoring (`Collect-Drives`)

```mermaid
graph TB
    A["Get-Volume or<br/>Get-PSDrive"] --> B["Iterate C: D: E: ..."]
    B --> C["For each drive:<br/>Get size and usage"]
    C --> D{Volume<br/>available?}
    D -->|yes| E["Calculate:<br/>- used_gb<br/>- total_gb<br/>- usage_pct"]
    D -->|no| F["Skip"]
    E --> JSON["Emit:<br/>{drives: [...]}"]
    F --> JSON
```

**Error Handling:**
- USB/external drives not always available
- CD-ROM drives excluded
- Network shares optional (configurable)

---

### SQL Server Collection (`Collect-SqlServer`)

```mermaid
graph TB
    subgraph Connect["Connection"]
        C1["Build connection string"]
        C2["Integrated auth or<br/>SQL user/password"]
        C3["SMO or<br/>System.Data.SqlClient"]
    end
    
    subgraph Query["Query Databases"]
        Q1["SELECT name, size, state<br/>FROM sys.databases"]
        Q2["Query each database:<br/>SELECT SUM(size) FROM sys.database_files"]
    end
    
    subgraph Parse["Data Parse"]
        P1["Convert pages to MB<br/>(8KB per page)"]
        P2["Classify state<br/>(ONLINE, OFFLINE, etc)"]
    end
    
    Connect --> Query
    Query --> Parse
    Parse --> JSON["Emit:<br/>{sql_server: {...}}"]
```

**Fields:**
- `version`: e.g., "2019 Enterprise"
- `databases`: Array of `{name, size_mb, state}`
- `connection_string`: Used for connection (masked in logs)

**Error Handling:**
- Server offline: `{sql_server: null}`
- Permission denied: `{sql_server: {error: "access denied"}}`
- Query timeout: Returns partial data

---

### HANA Collection (`Collect-Hana`)

```mermaid
graph TB
    subgraph Discover["Discovery"]
        D1["Check registry:<br/>HKLM:\SAP\HANA\..."]
        D2["Get instance number<br/>Host name"]
    end
    
    subgraph Connect["Connect"]
        C1["hdbsql or<br/>SAP DB connector"]
        C2["Connect to<br/>localhost:3<br/>NN15 (NN=instance)"]
    end
    
    subgraph Query["Query"]
        Q1["SELECT version<br/>SELECT database, size<br/>SELECT backup status"]
    end
    
    Discover --> Connect
    Connect --> Query
    Query --> JSON["Emit:<br/>{hana: {...}}"]
```

**Configuration:**
```powershell
$hanaInstanceNumber = $cfg['HANA_INSTANCE_NUMBER']  # e.g., "00"
$hanaPort = 3 * 10 * $hanaInstanceNumber + 13  # 00 → 13, 01 → 43
# Connection: localhost:30013
```

---

### SAP B1 Collection (`Collect-SapB1`)

```mermaid
graph TB
    subgraph Registry["Registry Lookup"]
        R1["HKLM:\Software\SAP\<br/>SAPBusinessOne\Setup"]
        R2["Extract:<br/>- installation path<br/>- version"]
    end
    
    subgraph Version["Version Detection"]
        V1["Read B1Version<br/>or config file"]
        V2["Parse version string"]
    end
    
    subgraph Database["Database Query"]
        DB1["Query Harvest/B1 DB<br/>SELECT COUNT(*)"]
        DB2["SELECT SUM(size)"]
    end
    
    Registry --> Version
    Registry --> Database
    Version --> JSON["Emit:<br/>{sap_b1: {...}}"]
    Database --> JSON
```

**Error Handling:**
- B1 not installed: `{sap_b1: null}`
- Registry key missing: Uses fallback paths
- DB query fails: `{sap_b1: {error: "query failed"}}`

---

### Process & Event Log Collection

```mermaid
graph LR
    PROC["Get-Process | Sort CPU<br/>Select -First 8"] --> PROCPARSE["Extract:<br/>PID, name, cpu%, ram%"]
    
    EVENT["Get-EventLog System<br/>-Since -(24 hours)<br/>-EntryType Error"] --> EVENTPARSE["Extract:<br/>timestamp, message<br/>limit 50"]
    
    PROCPARSE --> JSON["Emit:<br/>{processes, event_log}"]
    EVENTPARSE --> JSON
```

---

## JSON Payload Structure

**Example Windows Report:**

```json
{
  "hostname": "SAP-PROD-WIN01",
  "agent_version": "1.4.73",
  "collected_at_utc": "2026-05-12T14:32:45Z",
  "system": {
    "os_version": "Windows Server 2019",
    "build_number": "17763",
    "ram_mb": 65536,
    "cpu_cores": 32,
    "uptime_seconds": 2592000
  },
  "drives": [
    {
      "letter": "C:",
      "used_gb": 450,
      "total_gb": 1000,
      "usage_pct": 45.0
    },
    {
      "letter": "D:",
      "used_gb": 3200,
      "total_gb": 4000,
      "usage_pct": 80.0
    }
  ],
  "sql_server": {
    "version": "2019 Enterprise",
    "databases": [
      {
        "name": "SAPHanaResources",
        "size_mb": 8192,
        "state": "ONLINE"
      },
      {
        "name": "Harvest",
        "size_mb": 4096,
        "state": "ONLINE"
      }
    ]
  },
  "hana": {
    "version": "2.0.70.00.1654321875",
    "databases": [
      {
        "name": "SYSTEMDB",
        "size_mb": 32768,
        "state": "OK"
      }
    ],
    "backups": {
      "latest_complete": "2026-05-12T02:00:00Z"
    }
  },
  "sap_b1": {
    "version": "10.00.251 PL 15 HF 1",
    "table_count": 156,
    "database_size_mb": 5120
  },
  "processes": [
    {
      "pid": 4321,
      "name": "sap_db_process.exe",
      "cpu_percent": 18.5,
      "ram_mb": 2048
    }
  ],
  "event_log": {
    "errors_last_24h": [
      {
        "timestamp": "2026-05-12T11:30:00Z",
        "source": "DISK",
        "event_id": 7001,
        "message": "The Disk was not able to..."
      }
    ]
  }
}
```

---

## Error Handling & Resilience

### Global Crash Trap

```powershell
trap {
    $crashMsg = "COLLECT_CRASH $(([System.DateTime]::UtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ')): $($_.Exception.Message)"
    
    # Log to stdout (captured by Task Scheduler)
    Write-Host $crashMsg
    
    # Persist to file
    $crashFile = 'C:\ProgramData\monitoring-agent\last-collect-crash.txt'
    [System.IO.File]::WriteAllText($crashFile, "$crashMsg`n$($_.ScriptStackTrace)`n", [System.Text.Encoding]::UTF8)
    
    break
}
```

**Crash Log Inspection:**
```powershell
Get-Content 'C:\ProgramData\monitoring-agent\last-collect-crash.txt'
```

---

### Graceful Degradation Pattern

```mermaid
graph TB
    TRY["try {<br/>  Collect-SapB1<br/>}"] --> CATCH["catch {<br/>  Log error<br/>  Set sap_b1=null<br/>}"]
    CATCH --> FINALLY["finally {<br/>  Collect continues<br/>  Other modules<br/>  proceed normally<br/>}"]
    FINALLY --> EMIT["Emit partial payload"]
```

**Example:**
```powershell
try {
    $sapB1Data = Collect-SapB1
} catch {
    Write-Warning "SAP B1 collection failed: $_"
    $sapB1Data = $null
}

# Continue collecting HANA, SQL, etc.
# Report includes: sap_b1: null, hana: {...}, sql_server: {...}
```

---

## Secure Credential Handling

### Password Storage

**In Config File:**
```powershell
HARVEST_SQL_PASSWORD="0djKUt&xbLK0AYr"
HANA_ADMIN_PASSWORD="..."
```

**Risks:**
- Plain text in config file
- Visible in running process memory
- Included in crash logs (if not filtered)

**Mitigation:**
1. Store `agent.conf` with restrictive ACL (`SYSTEM` + `Administrators` only)
2. Never log `$cfg` hash table directly
3. Filter passwords in crash logs:
   ```powershell
   $crashMsg = $crashMsg -replace $cfg['.*PASSWORD.*'], "[REDACTED]"
   ```

### Credential Handling for SQL/HANA

```powershell
# Load from config
$sqlPassword = $cfg['HARVEST_SQL_PASSWORD']

# Create connection (in memory only)
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = "Server=$server;User Id=$user;Password=$sqlPassword;..."

# Use connection
$connection.Open()

# Dispose (clears sensitive data)
$connection.Dispose()
$sqlPassword = $null  # Explicit cleanup
```

---

## Task Scheduler Integration

### Scheduled Task Setup

```powershell
# Create task running every 5 minutes (10 PM - 6 AM)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -WindowStyle Hidden -File C:\Program Files\monitoring-agent\collect_and_send.ps1'

$trigger = @()
$trigger += New-ScheduledTaskTrigger -Daily -At "22:00"  # Start at 10 PM
$trigger += New-ScheduledTaskTrigger -Once -At "22:00" -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Hours 8)

Register-ScheduledTask -TaskName 'MonitoringAgent' `
    -Action $action `
    -Trigger $trigger `
    -Principal (New-ScheduledTaskPrincipal -UserID "SYSTEM" -RunLevel Highest)
```

### Log Inspection

```powershell
# Task Scheduler history
Get-ScheduledTaskInfo -TaskName 'MonitoringAgent'

# Last run result
$lastTask = Get-ScheduledTask -TaskName 'MonitoringAgent'
$lastTask.State  # Running, Ready, Disabled
```

---

## Network & Security

### TLS Configuration

```powershell
# Enforce TLS 1.2 (older Windows versions default to TLS 1.0)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disable certificate revocation check (if needed)
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

# Disable 100-Continue (improves compatibility)
[Net.ServicePointManager]::Expect100Continue = $false
```

### HTTP POST with API Key

```powershell
$client = New-Object System.Net.WebClient

$headers = @{
    'X-Api-Key' = $cfg['X_API_KEY']
    'Content-Type' = 'application/json'
}

$client.Headers.Add('X-Api-Key', $cfg['X_API_KEY'])

$jsonData = ConvertTo-Json -InputObject $payload -Depth 10 -Compress

$response = $client.UploadString($cfg['SERVER_URL'], "POST", $jsonData)
```

**Timeout Handling:**
```powershell
$client.UploadStringAsync() with timeout wrapper
# OR
Use Invoke-WebRequest with -TimeoutSec
```

---

## Testing & Debugging

### Manual Test Run

```powershell
# Run in current session (with output)
& 'C:\Program Files\monitoring-agent\collect_and_send.ps1' -Verbose

# Run as SYSTEM (via Task Scheduler)
schtasks /run /tn "MonitoringAgent" /i

# Check output
Get-ScheduledTaskInfo -TaskName 'MonitoringAgent' | Select LastRunResult, LastRunTime
```

### Debugging Steps

```powershell
# 1. Check config is readable
Get-Content 'C:\ProgramData\monitoring-agent\agent.conf'

# 2. Verify credentials
$cfg = @{}
$pwd = (Get-Content 'C:\ProgramData\monitoring-agent\agent.conf' | % { ... })
Write-Host "SQL Server: $($cfg['HARVEST_SQL_SERVER'])"
Write-Host "User: $($cfg['HARVEST_SQL_USER'])"

# 3. Test SQL connection
$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = "Server=$($cfg['HARVEST_SQL_SERVER']);User Id=$($cfg['HARVEST_SQL_USER']);Password=$($cfg['HARVEST_SQL_PASSWORD']);"
$conn.Open()
Write-Host "SQL: Connected"
$conn.Close()

# 4. Enable verbose output
$VerbosePreference = 'Continue'
& '.\collect_and_send.ps1'
```

### Check Last Crash

```powershell
$crashLog = Get-Content 'C:\ProgramData\monitoring-agent\last-collect-crash.txt' -ErrorAction SilentlyContinue
if ($crashLog) {
    Write-Host "Last crash:"
    $crashLog
} else {
    Write-Host "No crashes recorded"
}
```

---

## Performance Characteristics

| Operation | Typical Time | Timeout | Notes |
|-----------|--------------|---------|-------|
| System metrics | 100-200ms | N/A | WMI queries |
| Drives enumeration | 50-100ms | N/A | Fast I/O |
| SQL Server connection | 500ms-2s | 30s | Network if remote |
| SQL database query | 1-5s | 30s | Per database |
| HANA connection | 1-3s | 20s | Registry + socket |
| HANA query | 2-10s | 20s | Full database list |
| SAP B1 registry lookup | 50-100ms | N/A | Fast |
| SAP B1 DB query | 2-8s | 20s | SQL to Harvest |
| Event log scan | 500ms-2s | N/A | System event log |
| Process collection | 100-200ms | N/A | Get-Process |
| JSON serialization | 100-500ms | N/A | ConvertTo-Json |
| **Total typical** | **10-40s** | N/A | 5-min interval |

---

## Troubleshooting

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| Task runs but no reports sent | Check crash log | `Get-Content C:\ProgramData\monitoring-agent\last-collect-crash.txt` |
| "Access denied" on config file | Permission issue | Run as SYSTEM; verify ACL on `agent.conf` |
| SQL connection fails | Auth or network | Verify `HARVEST_SQL_SERVER`, credentials in `agent.conf` |
| HANA not found | Registry lookup failed | Check instance number in config |
| High CPU on collection | SAP B1 or HANA query slow | Disable `ENABLE_SAP_SCAN` temporarily |
| Event log import very large | Too many events | Reduce `EVENT_LOG_HOURS` or `EVENT_LOG_LIMIT` |
| `last-collect-crash.txt` contains timeout | Slow network or component | Increase timeout or run at different time |

---

## Version Management

### Embedded Version

Located in script header:
```powershell
$EmbeddedAgentVersion = '1.4.73'
```

Updated with `bulk_update_agents.ps1` when new release is deployed.

### Version Check

```powershell
# In payload
"agent_version": "1.4.73"

# Server can:
- Compare against AGENT_VERSION file
- Suggest update if outdated
- Log version mismatch for auditing
```

---

## Production Deployment Checklist

- [ ] Config file created with correct `SERVER_URL` and `X_API_KEY`
- [ ] SQL Server credentials configured (or auto-provisioned)
- [ ] HANA instance number correct (if applicable)
- [ ] SAP B1 installation path verified
- [ ] Scheduled task created and tested
- [ ] First report received on server
- [ ] Crash log checked (should be empty)
- [ ] Event Viewer shows no errors in Task Scheduler logs
- [ ] Network firewall allows outbound HTTPS to server
- [ ] Performance acceptable (<40 seconds per cycle)
