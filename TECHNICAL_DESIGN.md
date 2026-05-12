# Monitoring – Technical Design & Architecture

Detaillierte technische Dokumentation mit Architektur-Diagrammen, Datenflüssen und Prozessabläufen.

---

## System Architecture

```mermaid
graph TB
    subgraph Agent["Agent (Linux/Windows)"]
        A1["collect_and_send.sh/.ps1<br/>5-min Cron"]
        A2["Metrics Collection<br/>CPU, RAM, Filesystems<br/>SAP B1, HANA, etc."]
        A3["JSON Payload<br/>POST /api/v1/agent-report"]
    end
    
    subgraph Server["Server (receiver.py)<br/>Port 8080"]
        S1["HTTP Request Handler<br/>ThreadingHTTPServer"]
        S2["Alert Engine<br/>Threshold Evaluation"]
        S3["Changelog Tracker<br/>Config Changes<br/>DB Lifecycle"]
        S4["Email / Telegram<br/>Notification Engine"]
    end
    
    subgraph Database["SQLite Database"]
        DB1["reports<br/>(Raw agent data)"]
        DB2["alerts<br/>(Alert state machine)"]
        DB3["alerts_debounce<br/>(Re-trigger prevention)"]
        DB4["host_config_changes<br/>(Config deltas)"]
        DB5["database_lifecycle<br/>(DB create/delete events)"]
        DB6["filesystem_visibility<br/>(User display prefs)"]
        DB7["filesystem_blacklist_patterns<br/>(Glob patterns to ignore)"]
    end
    
    subgraph Frontend["Web Dashboard (app.js)"]
        UI1["Single-Page App<br/>(Vanilla JS)"]
        UI2["Progressive Web App<br/>(Service Worker offline)"]
        UI3["REST API Consumption"]
    end
    
    A1 --> A2
    A2 --> A3
    A3 --> S1
    S1 --> S2
    S1 --> S3
    S2 --> S4
    
    S2 --> DB2
    S2 --> DB3
    S3 --> DB4
    S3 --> DB5
    
    A1 -.->|every 5 min| DB1
    DB1 -.->|read on demand| UI3
    DB2 -.->|read| UI3
    DB4 -.->|read| UI3
    DB5 -.->|read| UI3
    
    UI1 --> UI2
    UI2 --> UI3
```

---

## Report Ingestion Flow

```mermaid
sequenceDiagram
    actor Agent
    participant Server as receiver.py
    participant DB as SQLite
    participant Engine as Alert Engine
    participant Notifier as Telegram/Email
    
    Agent->>Server: POST /api/v1/agent-report<br/>{hostname, filesystems, cpu, ram...}
    
    Server->>DB: INSERT INTO reports<br/>(received_at_utc, payload_json)
    Server->>Engine: evaluate_severity_for_report()
    
    loop For each filesystem
        Engine->>Engine: Check blacklist patterns
        alt Is blacklisted?
            Engine->>Engine: Skip alert (fn:match)
        else Is muted?
            Engine->>Engine: Skip (user-muted)
        else Is threshold exceeded?
            Engine->>DB: Check alerts_debounce
            alt Within debounce window?
                Engine->>Engine: Increment hit count
            else Hits >= consecutive_hits?
                Engine->>DB: INSERT/UPDATE alerts<br/>status=open/warning/critical
                Engine->>Notifier: Send notification
            end
        else Threshold OK?
            alt Alert exists & status=open?
                Engine->>DB: UPDATE alerts<br/>status=resolved
            end
        end
    end
    
    Server-->>Agent: HTTP 200 OK
```

---

## Filesystem Blacklist Processing

```mermaid
graph LR
    A["Filesystem<br/>Mountpoint"] --> B["Pattern<br/>Check<br/>fnmatch"]
    B -->|matches any<br/>blacklist pattern| C["SKIP<br/>Alert"]
    B -->|no match| D["Continue normal<br/>alert processing"]
    C --> E["Remove from<br/>Trend Charts"]
    C --> F["Remove from<br/>Summaries"]
    D --> G["Evaluate<br/>Thresholds"]
    G --> H["Create/Update<br/>Alert"]
```

**Blacklist Patterns Checked At:**
1. Alert creation/update (`update_alerts_for_report()`)
2. Analysis trend data collection (`/api/v1/analysis`)
3. Large files collection (implicit via trend filtering)
4. Startup initialization (`resolve_open_blacklisted_alerts()`)

---

## Config Changelog Capture

```mermaid
sequenceDiagram
    participant Agent
    participant Server as receiver.py
    participant Detection as Config Delta<br/>Detector
    participant DB as host_config_changes
    participant UI as Dashboard
    
    Agent->>Server: POST with new SAP Release<br/>sap_release=10.00.251
    
    Server->>Detection: _track_host_config_changes()<br/>compare: old vs new
    
    Detection->>Detection: _is_significant_change()?<br/>(skip noise)
    
    alt Change is significant
        Detection->>DB: INSERT INTO host_config_changes<br/>(hostname, field_key, old_value, new_value,<br/>detected_at_utc, display_name)
        
        DB-->>UI: GET /api/v1/host-changelog<br/>[for host view]
        UI->>UI: Render SAP Release row<br/>+ resolve Feature Pack<br/>via SAP_B1_VERSION_MAP
    else Change is noise
        Detection->>Detection: Skip
    end
```

---

## Database Lifecycle Tracking

```mermaid
graph TB
    subgraph Process["Backfill Process"]
        B1["Scan reports<br/>older than N days"]
        B2["Extract database lists<br/>from each report"]
        B3["Track state changes<br/>per hostname"]
        B4["Detect:<br/>DB created<br/>DB deleted"]
        B5["INSERT with<br/>UNIQUE constraint<br/>deduplication"]
    end
    
    subgraph Storage["database_lifecycle Table"]
        S1["id"]
        S2["hostname"]
        S3["database_name"]
        S4["action<br/>(create/delete)"]
        S5["triggered_at_utc"]
        S6["reason"]
    end
    
    subgraph Query["Query Layer"]
        Q1["GET /api/v1/<br/>database-lifecycle"]
        Q2["Per-host paginated<br/>display"]
    end
    
    B1 --> B2
    B2 --> B3
    B3 --> B4
    B4 --> B5
    B5 --> Storage
    Storage --> Query
```

**Unique Constraint:**
```sql
UNIQUE(hostname, database_name, action, report_id)
```
Ensures idempotent backfill: running backfill multiple times doesn't create duplicates.

---

## Alert State Machine

```mermaid
stateDiagram-v2
    [*] --> open: Threshold<br/>exceeded
    
    open --> acknowledged: User<br/>acknowledges
    acknowledged --> acknowledged: Alert<br/>reminder sent<br/>(no spam)
    
    open --> muted: User<br/>mutes<br/>mountpoint
    muted --> [*]: User<br/>unmutes
    
    open --> resolved: Threshold<br/>drops below<br/>limit
    acknowledged --> resolved: Threshold<br/>drops
    
    resolved --> open: Threshold<br/>exceeded<br/>again
    
    resolved --> closed: User<br/>manually<br/>closes
    closed --> [*]: Final state
```

**Key Properties:**
- `status`: `open`, `acknowledged`, `muted`, `resolved`, `closed`
- `last_seen_at_utc`: Updated each report
- `resolved_at_utc`: Set when status → `resolved`
- `muted_until_utc`: For time-based muting (if implemented)

---

## SAP Feature Pack Resolution Pipeline

```mermaid
graph LR
    A["Raw SAP Release<br/>10.00.251 PL15 HF1"] --> B["Extract Build#<br/>10.00.251"]
    B --> C["Lookup in<br/>SAP_B1_VERSION_MAP"]
    C --> D{Match<br/>Found?}
    D -->|Yes| E["Return Feature Pack<br/>FP 2601 HF1"]
    D -->|No| F["Return original<br/>release text"]
    E --> G["Display in<br/>Changelog<br/>(bold + brackets)<br/>10.00.251<br/><strong>FP 2601 HF1</strong>"]
    F --> G
```

**Map Structure (JavaScript):**
```javascript
SAP_B1_VERSION_MAP = new Map([
  ["10.00.251", { featurePack: "FP 2601 HF1", patchLevel: "PL 15", releaseDate: "May 2026" }],
  ["10.00.320", { featurePack: "FP 2602", patchLevel: "PL 22", releaseDate: "Feb 2026" }],
  ...
])
```

**Feature Pack Display Locations:**
1. Global Changelog (Admin view) – v1.4.106+
2. Host Config Changelog (sidebar) – v1.4.110+
3. Host Overview (detail card) – via existing chip rendering

---

## Filesystem Visibility Management

```mermaid
graph TB
    subgraph UserAction["User Interaction"]
        U1["Open Filesystem<br/>Focus Modal"]
        U2["Select/deselect<br/>mountpoints"]
        U3["Save preferences"]
    end
    
    subgraph Storage["Database"]
        S1["filesystem_visibility<br/>table"]
    end
    
    subgraph Rendering["Chart Rendering"]
        R1["Load trends"]
        R2["Filter by<br/>hidden list"]
        R3["Render only<br/>visible charts"]
    end
    
    U1 --> U2
    U2 --> U3
    U3 -->|POST /api/v1/<br/>filesystem-visibility| S1
    
    R1 --> R2
    S1 -->|SELECT WHERE<br/>username, hostname| R2
    R2 --> R3
```

---

## Email Notification Architecture

```mermaid
sequenceDiagram
    participant Scheduler as Alert Scheduler
    participant Server as receiver.py
    participant OAuth as Microsoft OAuth
    participant Graph as Microsoft Graph API
    participant Recipient as User Email
    
    Scheduler->>Server: Time to send daily digest?<br/>(08:05 configured time)
    Server->>Server: Collect alerts<br/>from last 24h
    Server->>OAuth: Load stored token<br/>(refresh if needed)
    OAuth-->>Server: Valid access_token
    Server->>Server: Build HTML email<br/>with header + table
    Server->>Graph: POST /me/sendMail<br/>{subject, body, recipients}
    Graph-->>Server: 202 Accepted
    Graph->>Recipient: Deliver email
    Server->>Server: Log send event
```

---

## Dashboard Data Flow (SPA Pattern)

```mermaid
graph LR
    UI["UI Component<br/>Host Changelog Tab"] 
    --> Fetch["fetch('/api/v1/<br/>host-changelog<br/>?hostname=...')"]
    --> Server["GET /api/v1/<br/>host-changelog"]
    --> Query["SELECT FROM<br/>host_config_changes<br/>WHERE hostname=..."]
    --> Render["renderChangelogRows()<br/>map items"]
    --> Display["Display:<br/>Field | Old | New<br/>+ Feature Pack<br/>+ Timestamp"]
    --> Browser["Browser<br/>renders HTML"]
```

**Cache Strategy:**
- Client-side: Cache per `state.selectedHost`
- Server-side: Query dynamic (no server cache – always fresh)

---

## Blacklist Enforcement Lifecycle

**On Server Startup:**
```
init_db() 
  └─ CREATE TABLE filesystem_blacklist_patterns
  
resolve_open_blacklisted_alerts()
  └─ SELECT alerts WHERE status='open'
  └─ FOR EACH: check if mountpoint matches blacklist
  └─ UPDATE status='resolved' if match
```

**On Report Ingestion:**
```
update_alerts_for_report()
  └─ FOR EACH filesystem in report
  └─ is_filesystem_blacklisted(mountpoint, blacklist_patterns)
  └─ IF match: skip alert creation + resolve any existing open alert
  └─ ELSE: continue normal threshold evaluation
```

**On Trend Analysis:**
```
/api/v1/analysis
  └─ Load blacklist_patterns
  └─ FOR EACH filesystem in trend rows
  └─ IF matches pattern: filter out (don't include in response)
  └─ Result: blacklisted FS never appear in charts or UI
```

---

## Storage Efficiency

### Reports Table (append-only)
- Indexed on: `hostname`, `received_at_utc`
- Retention: Configurable (default: keep 90 days)
- Size: ~2-5MB per host per month (depending on metrics volume)

### Alerts Table (mutable)
- One row per `(hostname, mountpoint)` tuple
- Status machine: `open` → `resolved` → `closed`
- Indexed on: `hostname`, `status`, `last_seen_at_utc`
- Size: Grows linearly with unique host×mountpoint pairs

### Config Changes Table (append-only, deduplicated)
- Indexed on: `hostname`, `detected_at_utc`
- Retention: Full history (no deletion)
- Unique constraint prevents exact duplicates
- Size: ~1KB per change event

### Database Lifecycle Table (append-only, deduplicated)
- Indexed on: `hostname`, `database_name`, `action`
- UNIQUE constraint: `(hostname, database_name, action, report_id)`
- Size: Minimal (~500 bytes per DB create/delete event)

---

## Performance Considerations

| Operation | Complexity | Typical Time |
|-----------|-----------|--------------|
| Report ingestion + alert eval | O(filesystems) | <100ms |
| Trend analysis query (24h) | O(reports) | 200-500ms |
| Changelog query (1 month) | O(config_changes) | 50-100ms |
| Database lifecycle backfill | O(reports × DBs per report) | 1-5s per backfill run |
| Blacklist pattern matching (fnmatch) | O(patterns) | <1ms per mountpoint |

**Optimization:**
- WAL mode for concurrent read access
- Indexes on frequently filtered columns
- Pagination (limit 100) for large result sets

---

## Security

### API Authentication
- **Agent Reports**: X-Api-Key header validation
- **Web UI**: Session token + OAuth (Microsoft) for email delegation

### Data Isolation
- Per-user changelog filters (not enforced – consider implementing per future requirements)
- Admin-only access to: SAP version map, user management, OAuth config

### Filesystem Patterns
- User-controlled blacklist patterns could theoretically be exploited for DoS via complex regex
- **Mitigation**: Use `fnmatch` (not regex) – simple glob patterns only
