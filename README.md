# Monitoring – Server & Agent

Zentrales Monitoring-System für Linux- und Windows-Hosts, betrieben als selbst-gehosteter Web-Service auf einer Synology NAS.

**Produktiv:** `https://monitoring.rolfwalker.ch`

---

## Architektur

```
Agent (Linux / Windows)
        |
        | POST /api/v1/agent-report (X-Api-Key)
        |
        v
receiver.py  ← ThreadingHTTPServer auf Port 8080
        |
        v
  SQLite (monitoring.db, WAL-Modus)
        |
        v
  Web-Dashboard (Vanilla JS / CSS / HTML)
```

- **Agent** läuft per Cron/Scheduled Task (Standard: alle 15 Minuten) und sendet ein JSON-Paket mit System-Metriken an den Server; zusätzliche Startverzögerung durch Jitter ist separat (max. 300 Sekunden).
- **Server** (`receiver.py`) nimmt Daten entgegen, wertet Schwellwerte aus, schreibt Alerts in die DB und stellt eine REST-API sowie ein Web-Dashboard bereit.
- **Dashboard** (`app.js`) ist eine Single-Page-App (PWA) ohne Framework. Läuft offline-fähig per Service Worker.

---

## Agent

### Gesammelte Metriken

| Kategorie         | Inhalt                                                       |
|-------------------|--------------------------------------------------------------|
| System            | Hostname, IPs, OS, Uptime, Agent-Version                     |
| Filesysteme       | Mountpoints, Füllstand in % (konfigurierbar welche angezeigt)|
| CPU               | Gesamtauslastung                                             |
| RAM               | Gesamt, belegt, frei (%)                                     |
| Swap              | Gesamt, belegt, frei (%)                                     |
| Netzwerk          | Interface, TX/RX-Bytes                                       |
| Journal           | Fehler/Warn-Ereignisse der letzten Stunde                    |
| Prozesse          | Top-Prozesse nach CPU/RAM                                    |
| Container         | Docker/Podman Status (Name, State, Image)                    |
| SAP Business One  | Build-Version, Feature Pack, Patch Level                     |
| HANA              | SID, Version, Branch, AddOns (Lightweight + Legacy)          |
| Backup-Status     | Letzter Backup-Zeitstempel (konfigurierbar per Pfad)         |
| Update-Log        | Letzte Zeilen des lokalen Self-Update-Logs                   |

### Versionen

- Linux-Agent: `client/linux/collect_and_send.sh`
- Windows-Agent: `client/windows/collect_and_send.ps1`

### Installation

**Linux (per curl):**

```bash
curl -sSL https://monitoring.rolfwalker.ch/updates/client/linux/install_agent.sh | bash
```

**Windows (PowerShell als Admin):**

```powershell
irm https://monitoring.rolfwalker.ch/updates/client/windows/install_agent.ps1 | iex
```

**Windows repair/bootstrap für bestehende Hosts:**

```powershell
& .\bootstrap_agent.ps1 -ServerUrl https://monitoring.rolfwalker.ch -DisableJitter
```

Der Wrapper zieht die aktuellen Windows-Skripte von `/updates`, repariert eine bestehende Installation in place und schaltet Jitter nur für diesen Lauf aus.

### Self-Update

Agents prüfen selbständig (alle ~6 Stunden, plus bei jedem Sammellauf wenn die Version veraltet ist) die vom Server bereitgestellten Pakete unter `/updates` und aktualisieren sich automatisch. Die aktuelle Agent-Version steht in `AGENT_VERSION`.

### Server-Deploy bei privatem Repo

Das Agent-Update selbst bleibt funktionsfaehig, weil Agenten nur noch von deinem Monitoring-Server unter `/updates` laden. Wenn das GitHub-Repo privat ist, betrifft das nur den Server-Deploy per `pull-server-only.sh`.

`pull-server-only.sh` unterstützt dafür jetzt GitHub-Tokens über diese Variablen:

```bash
export MONITORING_GITHUB_TOKEN=ghp_xxx
# alternativ: export GITHUB_TOKEN=ghp_xxx
sudo ./pull-server-only.sh
```

Alternativ kann `MONITORING_GITHUB_TOKEN` dauerhaft in der serverseitigen `monitoring.env` hinterlegt werden. Das Skript liest diese Datei beim Deploy ein und spiegelt danach die aktuellen Pakete wieder nach `/updates` für die Agenten.

### Remote-Befehle (Command Queue)

Der Server kann über die Web-UI Befehle für einzelne oder alle Hosts enqueuen. Der Agent pollt beim nächsten Sammellauf `GET /api/v1/agent-commands` und führt den Befehl aus. Ergebnis wird per `POST /api/v1/agent-command-result` zurückgemeldet.

Verfügbare Befehle:
- `update-now` — sofortiger Self-Update-Lauf
- `set-api-key` — neuen API-Key setzen (Payload: `api_key`)

---

## Alert-Prozess

### Schwellwerte

Globale Schwellwerte (in %) werden in den Alarm-Settings gesetzt:
- `warning_threshold_percent` (Standard: 80 %)
- `critical_threshold_percent` (Standard: 90 %)

Jeder eingehende Agent-Report wird gegen diese Werte ausgewertet. Pro Mountpoint wird ein Alert-Datensatz geführt.

### Alert-Lifecycle

```
Filesystem-Füllstand überschreitet Schwellwert
        ↓
  [open]  ←────────────────────────────────────────────────────┐
    |                                                           │ Re-open
    ├──→ [acknowledged]  (Benutzer bestätigt, Kenntnis genommen)│
    │         ↓ (Füllstand sinkt wieder unter Schwelle)         │
    └──→ [resolved]  ←────────────────────────────────────────--┘
              |
              └──→ [closed]  (manuell durch Benutzer)
```

| Status         | Beschreibung                                                  |
|----------------|---------------------------------------------------------------|
| `open`         | Schwelle überschritten, noch keine Aktion                     |
| `acknowledged` | Benutzer hat zur Kenntnis genommen (kein weiterer Alert-Spam) |
| `muted`        | Mountpoint/Host stummgeschaltet (keine Alerts bis Unmute)     |
| `resolved`     | Füllstand ist wieder unter die Schwelle gesunken              |
| `closed`       | Manuell von Benutzer geschlossen (kein Auto-Reopen)           |

- **Mute**: Per `POST /api/v1/alert-mute` → gilt bis manuelles Unmute.
- **Acknowledge**: Per `POST /api/v1/alert-ack` → unterdrückt Benachrichtigungs-Spam, Alert bleibt sichtbar.
- **Close**: Per `POST /api/v1/alert-close` → verhindert automatisches Re-Open.

### Alert-Benachrichtigungen

| Kanal      | Konfiguration                         | Empfänger           |
|------------|---------------------------------------|---------------------|
| Telegram   | Bot-Token + Chat-ID in Alarm-Settings | Globale Telegram-Gruppe |
| E-Mail     | Microsoft OAuth (Delegated Auth)      | Pro User konfigurierbar |

Benutzer können in den Einstellungen pro Host festlegen, ob sie Alerts per Mail und/oder Telegram erhalten.

---

## Kunden-Benachrichtigung

Für jeden Host kann ein **externer E-Mail-Empfänger** (z. B. Endkunde) konfiguriert werden. Wenn ein Filesystem-Alert für einen bestimmten Mountpoint auf diesem Host ausgelöst wird, erhält der Kunde automatisch eine E-Mail.

Konfiguration pro Host (Admin-Bereich):
- `customer_alert_emails` — Empfänger-Adressen (kommagetrennt)
- `customer_alert_mountpoints` — Welche Mountpoints betroffen (leer = alle)
- `customer_alert_min_severity` — Mindestschwere: `warning` oder `critical`

Test-Mail: `POST /api/v1/customer-alert/test`

---

## KI-Analyse

Für einzelne Metriken (z. B. `swap_percent`, `cpu_percent`) kann eine KI-gestützte Ursachenanalyse angefordert werden (`POST /api/v1/ai-troubleshoot`). Das Ergebnis wird gecacht, um API-Kosten zu reduzieren.

---

## Benachrichtigungskanäle

### Telegram (global)

Konfiguriert in Admin → Alarm-Einstellungen:
- `telegram_bot_token`
- `telegram_chat_id`

Testversand: `POST /api/v1/alarm-test`

### Microsoft OAuth / E-Mail

Admin konfiguriert eine OAuth2-App-Registrierung in Azure AD (Client ID, Tenant ID, Client Secret). Benutzer autorisieren ihren Account einmalig über `GET /api/v1/oauth/microsoft/start` → Callback unter `/oauth/microsoft/callback`.

Danach können folgende Test-Mails ausgelöst werden:
- `POST /api/v1/mail-test` — generische Test-Mail
- `POST /api/v1/mail-test/trends` — Trend-Zusammenfassung
- `POST /api/v1/mail-test/alerts` — Alert-Zusammenfassung
- `POST /api/v1/mail-test/backup` — Backup-Status-Mail

---

## SAP Business One Version Map

Der Server pflegt eine interne Zuordnungstabelle von SAP B1 Build-Nummern zu Feature Pack und Patch Level. Diese kann im Admin-Bereich via `GET/POST /api/v1/sap-b1-version-map` verwaltet werden.

Im Host-Detail wird die Build-Version automatisch aufgelöst und als Chip angezeigt (z. B. `FP 2208 · PL 08`).

---

## Backup & Restore

Der Server bietet eine eingebaute Backup-Funktion für die SQLite-Datenbank:

| Endpoint                            | Beschreibung                               |
|-------------------------------------|--------------------------------------------|
| `GET /api/v1/backup/database/start` | Backup starten                             |
| `GET /api/v1/backup/database/status`| Backup-Fortschritt pollen                  |
| `GET /api/v1/backup/database/download` | Fertiges Backup herunterladen           |
| `GET /api/v1/backup/database`       | Liste vorhandener Backups                  |
| `POST /api/v1/restore/database`     | Backup hochladen und einspielen            |
| `GET /api/v1/backup-status-overview`| Backup-Status aller Hosts (aus Metriken)   |

---

## Benutzer & Rollen

| Rolle   | Rechte                                                          |
|---------|-----------------------------------------------------------------|
| Admin   | Alles: Hosts löschen, Benutzer verwalten, OAuth, Backup, SAP-Map|
| User    | Dashboard lesen, eigene Alert-Subscriptions, eigenes Profil     |

Login: `POST /api/v1/web-login` (Formular oder JSON)  
Passwort ändern: `POST /api/v1/change-password`  
Benutzerverwaltung (Admin): `GET/POST /api/v1/web-users`

---

## Export

| Endpoint                      | Format | Inhalt                  |
|-------------------------------|--------|-------------------------|
| `GET /api/v1/export/alerts.csv` | CSV    | Alert-Liste (gefiltert) |
| `GET /api/v1/export/reports.json` | JSON | Report-Liste pro Host   |

---

## Server starten

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 receiver.py --host 0.0.0.0 --port 8080
```

**Produktivbetrieb** (als Dienst, z. B. Synology Task Scheduler):
```bash
/home/rolf/Tools/Monitoring/.venv/bin/python3 /home/rolf/Tools/Monitoring/server/receiver.py
```

---

## Dashboard-Funktionen

| Tab / Bereich        | Inhalt                                                        |
|----------------------|---------------------------------------------------------------|
| Übersicht (global)   | Alle Hosts, letzter Kontakt, Füllstände, Alert-Badges         |
| Trends               | Kritische Trends über konfigurierbaren Zeitraum               |
| Inaktive Hosts       | Hosts ohne Meldung innerhalb Schwellwert                      |
| Alerts               | Globale Alert-Liste mit Filter und Export                     |
| Einzel-Host          | Detail-Ansicht mit Tabs: Übersicht, Journal, Prozesse, SAP B1, Container, Verzeichnisse, Agent |
| Benachrichtigung     | Kunden-Alert-Konfiguration pro Host (Admin)                   |
| Admin-Bereich        | Alarm-Settings, OAuth, Benutzer, Backup/Restore, SAP-Map      |

Die App ist als **Progressive Web App (PWA)** ausgeliefert und kann auf Mobilgeräten installiert werden.

---

## Audit Trail & Changelog

### Database Lifecycle Tracking (v1.4.92+)

Der Server erfasst automatisch, wann Datenbanken auf HANA-Systemen erstellt oder gelöscht werden:

- **Globale DB-Historik**: Alle Datenbanken pro Mandant und Datum
- **Host-spezifische DB-Historie**: Datenbanken pro einzelnem Host mit Zeitpunkte
- **Backfill-Funktion**: Historische Daten aus alten Reports nachträglich einspeisen (`POST /api/v1/host-config-changes/backfill`)
- **Greenfield-Rebuild beim Start**: Beim normalen Serverstart wird einmalig automatisch ein Rebuild aus den letzten 18 Tagen gestartet. Der Server löscht dann die vorhandenen Changelog-Tabellen, baut sie neu auf und merkt sich den Abschluss, damit der Lauf nicht erneut ausgeführt wird. Optional kann die Tageszahl per `--rebuild-changelog-days` oder `MONITORING_REBUILD_CHANGELOG_DAYS` überschrieben werden.

### Config Changelog (v1.4.93+)

Alle Konfigurationsänderungen werden im Changelog erfasst und pro Host abrufbar:

- **Globales Changelog** (Admin): Alle Konfigurationsänderungen aller Hosts mit Gruppierung nach Datum
- **Host-Changelog** (Host-Detailansicht): Nur Änderungen des aktuellen Hosts
- **SAP Feature Pack Display** (v1.4.106+): Bei SAP Release-Änderungen wird das Feature Pack automatisch aufgelöst und angezeigt (z. B. `10.00.251 **(FP 2601 HF1)**)
- **Changelog-Betreff**: Kompakte Tabellenform mit minimalen Spaltenbreiten für maximale Lesbarkeit

### Filesystem Blacklist (v1.4.99+)

Mountpoints können mit Glob-Pattern-Matching (fnmatch) in die Blacklist aufgenommen werden:

- **Automatische Anwendung**: Alle blacklisted Filesysteme werden automatisch aus Alerts, Trend-Charts und Summaries entfernt
- **On-Startup Resolution** (v1.4.105): Offene Alerts für blacklisted Mountpoints werden beim Server-Start automatisch als gelöst markiert
- **Beispiel-Patterns**:
  - `/hana/shared/.snapshot` — verhindert NetApp-Snapshot-Verzeichnis
  - `/mnt/snapshots/*` — alle Unterverzeichnisse von `/mnt/snapshots`

---

## Documentation

- **[TECHNICAL_DESIGN.md](TECHNICAL_DESIGN.md)** – Server architecture, data flows, alert state machine, database lifecycle tracking, and blacklist enforcement mechanisms with Mermaid diagrams
- **[AGENT_LINUX_TECHNICAL.md](AGENT_LINUX_TECHNICAL.md)** – Comprehensive reference for `collect_and_send.sh`: metrics collection, jitter mechanism, locking, large files scanning, SAP B1 and HANA integration
- **[AGENT_WINDOWS_TECHNICAL.md](AGENT_WINDOWS_TECHNICAL.md)** – Complete guide for `collect_and_send.ps1`: WMI/SMO data collection, SQL Server integration, HANA querying, crash handling, and Task Scheduler setup
- **[agent-deployment-guide.html](agent-deployment-guide.html)** – Practical deployment guide for Linux and Windows agents with install/update commands, parameters, license file paths, and current HANA/SAP payload sources
- **[docs/processes/index.html](docs/processes/index.html)** – HTML-Startseite fuer alle Prozessdokumente (mit Mermaid-Rendering)
- **[docs/processes/monitoring-cheat-sheet-comic.html](docs/processes/monitoring-cheat-sheet-comic.html)** – Grafisches Cheat-Sheet im Comicstil fuer Kernprozesse, Agent-Skripte, Parameter und Debug-Routen
- **[docs/processes/monitoring-cheat-sheet-a4.html](docs/processes/monitoring-cheat-sheet-a4.html)** – Druckfreundliche A4-Version des Ops-Cheat-Sheets fuer Ausdruck und Einsatzmappe
- **[docs/processes/alerting-mail-oauth-comic.html](docs/processes/alerting-mail-oauth-comic.html)** – Comicartige Schnellreferenz fuer Alert-Lifecycle, Mail-Routing, OAuth und Reminder/Digests
- **[docs/processes/mailversand-prozess.html](docs/processes/mailversand-prozess.html)** – Mailversand mit OAuth/Graph, Instant-Alerts, Reminder und Scheduled Digests
- **[docs/processes/alert-handling-gesamtprozess.html](docs/processes/alert-handling-gesamtprozess.html)** – Voller Alert-Lifecycle inklusive Debounce, Mute/Ack/Close und Eskalation
- **[docs/processes/backfill-prozess.html](docs/processes/backfill-prozess.html)** – Historische Rekonstruktion fuer Host-Config und Database-Lifecycle
- **[docs/processes/datenholung-prozess.html](docs/processes/datenholung-prozess.html)** – Datenannahme von Agenten (Reports, Commands, Resultate)
- **[docs/processes/db-schreiben-prozess.html](docs/processes/db-schreiben-prozess.html)** – Persistenzpipeline vom Report bis zu Alerts, Lifecycle und Mail-Triggern
- **[docs/processes/remote-command-lifecycle.html](docs/processes/remote-command-lifecycle.html)** – Queue, Auslieferung, TTL und Rueckmeldung von Agent-Commands
- **[docs/processes/oauth-lifecycle.html](docs/processes/oauth-lifecycle.html)** – OAuth Connect, Callback, Token-Refresh und Disconnect
- **[docs/processes/alert-routing-matrix.html](docs/processes/alert-routing-matrix.html)** – Routing-Matrix fuer Mail/Telegram je Schweregrad und Subscription
- **[docs/processes/datenaufbewahrung-pruning.html](docs/processes/datenaufbewahrung-pruning.html)** – Report-Retention, Pruning und Konsistenzwirkung
- **[docs/processes/backup-restore-prozess.html](docs/processes/backup-restore-prozess.html)** – DB-Backup Jobs, Download und Restore-Absicherung
- **[docs/processes/agent-self-update-e2e.html](docs/processes/agent-self-update-e2e.html)** – Linux/Windows Self-Update und Bootstrap-Ablauf
- **[docs/processes/api-key-grace-mode.html](docs/processes/api-key-grace-mode.html)** – API-Key-Pruefung und Grace-Mode fuer bekannte Hosts
- **[docs/processes/visibility-blacklist-auswirkungen.html](docs/processes/visibility-blacklist-auswirkungen.html)** – Auswirkungen von Visibility/Blacklist auf Alerts und Trends

---

## Versioning

- Applikations-Version: `BUILD_VERSION` (semantisch, aktuell: **1.5.23**)
- Agent-Version: `AGENT_VERSION` (separat versioniert, aktuell: **1.5.23**)
- API-Spec: `openapi.yaml` (OpenAPI 3.0.3, Version folgt BUILD_VERSION)

### Recent Releases (v1.4.99+)

| Version | Datum | Änderung |
|---------|-------|----------|
| 1.6.127 | 17.05.2026 | Report header: add a subtle background shadow/halo behind the centered OS logo for softer separation |
| 1.6.126 | 17.05.2026 | Report header: reduce centered OS logo size by roughly 30% for a less dominant visual footprint |
| 1.6.125 | 17.05.2026 | Report header polish: push second-row chips further to the right edge and reduce centered OS logo size for better balance |
| 1.6.124 | 17.05.2026 | Report header: remove auto-refresh countdown and last-refresh timestamp indicators from the title tools row |
| 1.6.123 | 17.05.2026 | Report header: shift complete second row to the right and add a large centered OS PNG logo spanning both header rows |
| 1.6.122 | 17.05.2026 | Host cards: render SAP/HANA/SID chips in a slightly darker blue palette for better contrast |
| 1.6.121 | 17.05.2026 | Host cards: hide left status bar when report state is green; unify SAP/HANA/SID chip style with identical, slightly larger bold typography |
| 1.6.120 | 17.05.2026 | Host cards: reduce green bias by using one unified pastel color for SAP/HANA/SID row and separate pastel colors for Prod/Test row; align Prod/Test chip typography and sizing |
| 1.6.119 | 17.05.2026 | Host card ordering: sort primarily alphabetically by customer_name (empty customer names last), then by host display/hostname |
| 1.6.118 | 17.05.2026 | Report header layout: move selected-host control chips (API, report count, visibility, favorite) from top title row to second meta row for cleaner spacing |
| 1.6.117 | 17.05.2026 | Host cards: align top-right OS icon and bottom-right country flag vertically with their corresponding content rows for a cleaner visual balance |
| 1.6.116 | 17.05.2026 | Host metadata: add host-level Umgebung dropdown (Prod./Test) and render environment chip below SAP/HANA/SID chips (Prod.=greenish, Test=yellowish) |
| 1.6.115 | 17.05.2026 | Host cards: reduce customer-name chip font size from 16px to 14px to further reduce visual dominance |
| 1.6.114 | 17.05.2026 | Host cards: reduce customer-name chip typography from 22px to 16px for less dominant visual weight |
| 1.6.113 | 17.05.2026 | Host Config Changelog: remove synthetic SAP AddOn "init" events so 24h view shows only real version deltas (fixes false recent changes with old values) |
| 1.6.112 | 17.05.2026 | Host cards: unblock customer-name chip scaling by excluding value chips from generic span font override; increase customer chip text to 22px |
| 1.6.111 | 17.05.2026 | Host cards: replace "AGENT ALT" text chip with a tiny circular red indicator dot aligned with the customer row |
| 1.6.110 | 17.05.2026 | Host cards: replace top red agent frame with a very small, subtle "AGENT ALT" badge in the customer row (only shown when agent status is red) |
| 1.6.109 | 17.05.2026 | Host cards: replace inline agent status dot with top-edge red bar shown only for red agent-status (outdated), freeing space for long hostnames |
| 1.6.108 | 17.05.2026 | Host card tooltips now include explicit color/threshold logic for left status bar, right alert bar visibility rule, and agent-dot version comparison logic |
| 1.6.107 | 17.05.2026 | Host card tooltips: left status bar now shows last-report age, right alert bar shows alert count, and agent status dot shows host-reported AGENT_VERSION |
| 1.6.106 | 17.05.2026 | Host cards: remove in-card alert chip and indicate open alerts with a right-side red vertical bar only |
| 1.6.105 | 17.05.2026 | Host card: fix agent-version dot rendering as circle (add display:inline-block), restore correct dot element |
| 1.6.104 | 17.05.2026 | Host cards: move last-report status dot inline into hostname/IP row, remove separate "Report vor…" text line entirely |
| 1.6.103 | 17.05.2026 | Host cards: restore last-report traffic-light dot (green/orange/red) as second meta row, remove paperclip emoji, change customer name chip to light blue (20px), apply subtle radial gradient to cards matching login mask style |
| 1.6.102 | 17.05.2026 | Further compact host cards: remove the "Report vor" row and hide agent version text, keep only a small status dot in the top meta row, and increase customer name chip typography for better readability |
| 1.6.101 | 17.05.2026 | Refine host card compact layout: remove bottom host-label row, move agent-version status indicator into the upper meta row, and repurpose the left card stripe to show last-report recency status (green/orange/red/gray) while keeping report-age text in-row |
| 1.6.100 | 17.05.2026 | Apply the unified Outlook-safe branded mail header to remaining test/info HTML mails as well (Host Alert subscription test, Customer Alert test, OAuth test mail, and Backup test mail), including improved logo-to-title spacing everywhere |
| 1.6.99  | 17.05.2026 | Unify all branded HTML mail headers with one Outlook-friendly table layout and increase logo-to-title spacing for consistent rendering across Trend Digest, Alert Digest, and Instant Alert mails |
| 1.6.98  | 17.05.2026 | Host cards: replace fixed last-seen timestamp with traffic-light recency indicator (green/orange/red + relative age text) and add an agent-version status dot (green/red/gray) before the version while keeping the original text color |
| 1.6.57  | 16.05.2026 | Fix SAP B1 terminal version table readability by enforcing dark terminal row backgrounds and higher-contrast column colors (prevents global zebra table styles from washing out text) |
| 1.6.56  | 16.05.2026 | Add live session remaining-time badge in header and harden session keepalive flow (cookie-based refresh endpoint, session expiry returned by /api/v1/session, login/focus/visibility refresh watchdog) |
| 1.6.55  | 16.05.2026 | Change web inactivity timeout from 60 to 30 minutes (sliding timeout) and make it configurable via MONITORING_WEB_SESSION_INACTIVITY_MINUTES |
| 1.6.54  | 16.05.2026 | Fix web session timeout behavior: authenticated requests now refresh session activity/expiry server-side, so active usage and regular dashboard refreshes no longer cause unexpected 401 logouts |
| 1.6.53  | 16.05.2026 | Refine Systemübersicht AddOn mode filtering: in AddOn > Kunde > OS view the search input now acts as an AddOn-name filter (with mode-specific placeholder and stats label), while default Land > OS > Host keeps broad search |
| 1.6.52  | 16.05.2026 | Add a Systemübersicht sort-mode toggle in the existing view: keep default Land/OS/Host grouping and provide an optional AddOn/Kunde/OS grouping on demand |
| 1.6.51  | 16.05.2026 | Refine Systemübersicht AddOn search behavior: when the search term matches AddOn names/versions, show only matching AddOns in the host AddOn lists instead of the full list |
| 1.6.50  | 16.05.2026 | Extend Systemübersicht search to include SQL/HANA AddOn names and versions, and update the search placeholder to reflect AddOn lookup |
| 1.6.49  | 16.05.2026 | Add a Host-Interessen guard label that shows which user's preferences are currently loaded, making user-context mismatches immediately visible |
| 1.6.48  | 16.05.2026 | Fix host-interest preferences leaking across user switches by resetting user-scoped state on auth transitions and reloading preferences per logged-in user |
| 1.6.47  | 16.05.2026 | Finalize SQL terminal code snippet alignment by switching to an explicit newline string (removes indentation artifacts between lines) |
| 1.6.46  | 16.05.2026 | Fix visual alignment of the SQL grant code snippet in terminal view by removing unintended indentation and tidying related CSS |
| 1.6.45  | 16.05.2026 | Refresh OpenAPI spec: add missing admin endpoints (login events, database stats, database vacuum), mark public/no-username-password endpoints clearly, and update API doc versioning |
| 1.6.44  | 16.05.2026 | Add a terminal-style SQL backup hint with the required sa-run grant snippet when DB sizes are missing in the SQL overview |
| 1.6.43  | 16.05.2026 | Add a subtle SQL/HANA license hint in the Lizenzinfos block that clarifies the required filename B01.txt and the searched paths on Windows and Linux |
| 1.6.42  | 16.05.2026 | Replace inline Nur-Admin chips with orange admin-only tab styling and an in-app legend for admin-exclusive sections |
| 1.6.41  | 16.05.2026 | Add direct host-interest mode control to the sidebar so saved interesting hosts can be applied immediately from the host list |
| 1.6.40  | 16.05.2026 | Switch report retention to 6 weeks (42 days), correct default agent interval docs to 15 minutes, and add Admin DB maintenance panel with live database stats plus manual VACUUM and visible before/after effect |
| 1.6.39  | 16.05.2026 | Improve SAP B1 Version-Referenztabelle rendering with a true terminal-themed HTML table (clean columns, sticky header, better readability) |
| 1.6.38  | 16.05.2026 | Stabilize web login by self-healing a missing login-audit table and expand terminal keyword coloring with granular token classes across all terminal cards (including SAP/HANA sections) |
| 1.6.37  | 16.05.2026 | Render Root Crontab and cron.d excerpts in the same dark terminal style as Agent Update Log and agent.conf |
| 1.6.36  | 16.05.2026 | Add real outer spacing around terminal-style Agent Update Log and agent.conf blocks by wrapping them in a padded shell; keeps visible left/right/bottom gap inside the collapsible cards |
| 1.6.35  | 16.05.2026 | Increase visible left/right/bottom padding in the Agent Update Log viewer and render agent.conf in the same terminal-style block for consistent readability |
| 1.6.34  | 16.05.2026 | Add extra left/right/bottom padding inside the Agent Update Log viewer for improved readability |
| 1.6.33  | 16.05.2026 | Enlarge emoji/text in the three top status chips and render their numeric counts in IBM Plex Mono for clearer telemetry styling |
| 1.6.32  | 16.05.2026 | Ensure the three left status chips in the top action row use the same visual height as the three right icon buttons |
| 1.6.31  | 16.05.2026 | Top action row refinement: align first three status chips to the left, keep icon buttons right-aligned, and increase those three chip heights to match the adjacent action buttons |
| 1.6.30  | 16.05.2026 | Reduce global button height to 24px while keeping chips slimmer at 20px; applies to primary/secondary controls, overview country filter, and system overview toggle |
| 1.6.29  | 16.05.2026 | Fix Systemübersicht regression after chip refactor: repair broken country-flag CSS block (flags visible again, no oversized AT card) and reduce global chip target height to 20px |
| 1.6.28  | 16.05.2026 | Slim down chip heights globally (including System Overview country filter chips and AddOns toggle) for a more compact UI |
| 1.6.27  | 16.05.2026 | Add unsaved-changes guard for SAP B1 Version Map editor: confirm before leaving admin tab and browser warning on reload/close until changes are saved |
| 1.6.26  | 16.05.2026 | Fix SAP B1 Version Map persistence UX: reload map after successful auth and refresh admin editor from server to avoid stale pre-login defaults |
| 1.6.25  | 16.05.2026 | Enhance hover effects on all button components: increase box-shadow intensity, deeper background colors, and improved visual feedback |
| 1.6.20  | 16.05.2026 | Reposition host-card alert info chip to the metadata row (right-aligned) and remove it from the footer row to reduce unnecessary line wraps and card height growth |
| 1.6.19  | 16.05.2026 | Tighten top-header vertical spacing further, increase gap between "System Health Dashboard" and the version line, and normalize logout chip height to match the other top-header chips |
| 1.6.18  | 16.05.2026 | Update all outgoing mail templates to match header branding: "System Health Dashboard" in one line and replace second-line "Dashboard" with version-only display |
| 1.6.17  | 16.05.2026 | Refine top header layout: title changed to "System Health Dashboard" on one line, second line reduced to version info only, typography made slightly smaller/bolder, and vertical header padding tightened |
| 1.6.16  | 16.05.2026 | Enlarge the top-right ANG logo in the header by ~30%, rename header title to "System Health", and apply the same branding text update across all digest/instant mail templates |
| 1.6.15  | 16.05.2026 | Further soften global hover colors (sidebar, tabs, and primary button hover states) for a calmer visual response |
| 1.6.14  | 16.05.2026 | Remove the filter-reset control completely (UI + JS) and keep host filtering manual-only as requested |
| 1.6.13  | 16.05.2026 | Tighten vertical spacing between "Hosts" title and host stats, and move reset from "X" to a compact "Filter löschen" chip below title (left of host stats) while keeping existing reset logic |
| 1.6.12  | 16.05.2026 | Soften global hover tones across navigation/buttons and remove the misplaced "Nur Admin" hint from the overview notification menu item |
| 1.6.11  | 16.05.2026 | Optimize "Nur Admin" badges globally with reduced height, smaller typography, and subtler light/dark color tones |
| 1.6.10  | 16.05.2026 | Fix host sidebar header overlap by placing "Hosts" top-left and the host count line bottom-right with compact, non-overlapping spacing |
| 1.6.9   | 16.05.2026 | Add clear "Nur Admin" hint badges to all visible admin-only menu options while keeping non-admin-hidden entries unchanged |
| 1.6.8   | 16.05.2026 | Remove the active-user chip from the sidebar header and add an admin-only login changelog view showing the latest 50 logins with timestamp, user, and source IP |
| 1.6.7   | 16.05.2026 | Render overview and single-report side menus as one shared card with row-style items instead of individual card-like menu buttons |
| 1.6.6   | 16.05.2026 | Move the sidebar content higher by removing the "Hosts und Historie" heading and relocating active-user info into the sidebar header on the right |
| 1.6.5   | 16.05.2026 | Soften the global button palette and normalize button heights app-wide (including user-management actions) for a calmer, more consistent UI |
| 1.6.4   | 16.05.2026 | Increase vertical spacing below overview/report tab headings so section titles no longer stick to controls beneath |
| 1.6.3   | 16.05.2026 | Restore and emphasize the light/dark mode switch in the header so it remains clearly visible and usable in both themes |
| 1.6.2   | 16.05.2026 | Wrap overview/detail navigation menus in card-style containers matching the new sidebar filter/search card design, including aligned dark-mode styling |
| 1.6.1   | 16.05.2026 | Extend the clean enterprise design language app-wide: unified chip sizes/colors, card-style grouping for related sections, and cohesive light/dark visual refinements without logic changes |
| 1.6.0   | 16.05.2026 | Apply host sidebar design direction A (Clean Enterprise): improved visual hierarchy, consistent spacing tokens, clearer host card states, and refined typography for headers/filters/cards |
| 1.5.26  | 16.05.2026 | Restore host card title to bold (900), increase OS icon size in cards, and fix alert chip footer alignment in compact card layout |
| 1.5.25  | 16.05.2026 | Refine host card typography and icon density (smaller title, reduced OS icon size), add SAP chip fallback rendering, and add a one-time debug guard for missing chip rows |
| 1.5.24  | 16.05.2026 | Compact host cards in the sidebar by tightening spacing and merging value chips/alert chip into a single footer row while preserving all card information |
| 1.5.23  | 15.05.2026 | Support multiple SQL Server instances with instance_name tracking in database inventory and lifecycle; display instance info in DB overview table |
| 1.5.22  | 14.05.2026 | Add a printable A4 cheat sheet, a dedicated alerting/mail/OAuth comic page, and visual preview tiles on the process docs start page |
| 1.5.21  | 14.05.2026 | Unify the process HTML docs with a shared stylesheet and add a comic-style monitoring cheat sheet for key processes, scripts and parameters |
| 1.5.20  | 14.05.2026 | Remove the temporary local Mermaid validation script from the repository and keep the documentation release clean |
| 1.5.19  | 14.05.2026 | Fix Mermaid syntax errors in process HTML docs by decoding embedded Markdown before rendering, and extend the process docs index with offline/update metadata |
| 1.5.18  | 14.05.2026 | Make process HTML docs work fully offline by vendoring marked and mermaid locally instead of loading them from CDN |
| 1.5.17  | 14.05.2026 | Restore the Markdown source files for all process documents after the Mermaid HTML rendering fix |
| 1.5.16  | 14.05.2026 | Fix Mermaid rendering in process HTML docs by replacing the brittle inline marked renderer with a shared DOM-based Mermaid transformer |
| 1.5.15  | 14.05.2026 | Add HTML versions for all process documents with Mermaid rendering and include detailed docs for processes 1-8 |
| 1.5.14  | 14.05.2026 | Add dedicated process docs with Mermaid flows for mail delivery, alert lifecycle, backfill, data ingestion, and database write pipeline |
| 1.5.13  | 14.05.2026 | Extend deployment guide with embedded Mermaid flowcharts for overview, Windows, Linux, and API/queue process flows |
| 1.5.12  | 14.05.2026 | Use distro-specific OS icons in host cards (ubuntu/debian/suse) with linux.png fallback when no mapping matches |
| 1.5.11  | 14.05.2026 | Enhance deployment guide with emoji section markers and OS icons (windows.png/linux.png) in respective sections |
| 1.5.10  | 14.05.2026 | Fix corrupted HTML deployment guide markup and restore valid rendering with separate Windows/Linux sections |
| 1.5.9   | 14.05.2026 | Restructure HTML agent guide into separate Windows and Linux sections with identical flow and direct script download examples |
| 1.5.8   | 14.05.2026 | Add HTML deployment guide for Linux and Windows agents including install/update commands, payload parameters, license paths, and HANA/SAP data sources |
| 1.5.7   | 14.05.2026 | Revert v1.5.4 font size and weight reductions (body, sidebar title, host card names, Meldungen header) |
| 1.5.6   | 14.05.2026 | Restrict IBM Plex Mono to FP and HANA release chips only; revert from meta lines and SID chip |
| 1.5.5   | 14.05.2026 | Apply IBM Plex Mono to host card meta lines (IP, hostname, agent version, date) and value chips (FP, HANA release, SID) |
| 1.5.4   | 14.05.2026 | Reduce font sizes and weights for HOSTS title, host card names, Meldungen header and base body font (Edge compatibility) |
| 1.4.154 | 14.05.2026 | Fix Meldungen datetime jump by honoring jump_to_utc in host-reports API and trigger jump reliably on picker input |
| 1.4.153 | 14.05.2026 | Add Systemübersicht host text search (combinable with country filter) and compact pill-style overview action buttons |
| 1.4.152 | 14.05.2026 | Match Lizenzinfos typography exactly to neighboring AddOns pattern (label normal, value mono) |
| 1.4.151 | 14.05.2026 | Align SAP B1 AddOns table section typography to AddOns label/value reference (Name/Version table) |
| 1.4.150 | 14.05.2026 | Set global value typography to 11px and align AddOns value size |
| 1.4.149 | 14.05.2026 | Tune global label/value typography to match AddOns reference styling across the app |
| 1.4.148 | 14.05.2026 | Apply unified label/value typography pattern across major UI sections using shared kv styles |
| 1.4.147 | 14.05.2026 | Show first 10 AddOns in Systemübersicht with expandable '+x weitere' and align Lizenzinfos typography to AddOns style |
| 1.4.146 | 14.05.2026 | Rename Systemübersicht last column header from "Status / Update" to "Status" |
| 1.4.145 | 14.05.2026 | Refine Systemübersicht licenses: remove Datei-Stand row, align with AddOns height, rebalance column widths |
| 1.4.144 | 14.05.2026 | Hide AddOns and Lizenzinfos dropdowns in Systemübersicht when no data is available |
| 1.4.143 | 14.05.2026 | Add license info dropdown to Systemübersicht under OS column with row count |
| 1.4.142 | 14.05.2026 | Move SAP license info from header into SAP B1 dropdown section (open when filled, closed when empty) |
| 1.4.139 | 14.05.2026 | Prevent wrapping in license values and tighten label width |
| 1.4.138 | 14.05.2026 | Reduce spacing between license labels and values even further |
| 1.4.137 | 14.05.2026 | Reduce font sizes in license panel and hide license title |
| 1.4.137 | 14.05.2026 | Add SAP license extraction for Linux (collect_and_send.sh) from /usr/sap/SAPBusinessOne/B1_SHF/Lizenz* paths |
| 1.4.137 | 14.05.2026 | Reduce font sizes in license panel and hide license title |
| 1.4.137 | 14.05.2026 | Add SAP license information extraction and display (Hardware Key, Instno, Expiration, System Nr, Customer Name, Customer No) |
| 1.4.122 | 14.05.2026 | Trend-Digest respektiert jetzt die gewählten Metrik-Kategorien (CPU/RAM/SWAP/Filesystem) auch in API, Testmail und geplantem Versand |
| 1.4.121 | 13.05.2026 | Fix database lifecycle changelog tracking and backfill for SQL/HANA payloads |
| 1.4.120 | 12.05.2026 | Fix user settings wiring: Trend Digest metrics + Host Interests now persist via user-preferences endpoint; mail profile save no longer resets digest selections |
| 1.4.119 | 12.05.2026 | Daily Trend Digest filters blacklisted filesystems (e.g. /hana/shared/.snapshot) |
| 1.4.118 | 12.05.2026 | Persist backup mail settings in user profile API (no reset after save) |
| 1.4.117 | 12.05.2026 | Add explicit helper note below centralized mail settings save button |
| 1.4.116 | 12.05.2026 | Consolidate mail settings save action to one button at end of digest section |
| 1.4.115 | 12.05.2026 | Normalize German UI/user texts to umlauts (Swiss ss retained) |
| 1.4.114 | 12.05.2026 | Fix host notification save by persisting customer alert fields in host settings API |
| 1.4.113 | 12.05.2026 | Fix Windows self_update empty-string config binding for GITHUB_REPO reset |
| 1.4.112 | 12.05.2026 | Fix Windows self_update parser error and add X_API_KEY fallback in Windows agents |
| 1.4.111 | 12.05.2026 | Add comprehensive technical documentation for Linux and Windows agents |
| 1.4.110 | 12.05.2026 | Add SAP Feature Pack display to host changelog |
| 1.4.109 | 12.05.2026 | Bump version |
| 1.4.108 | 12.05.2026 | Bold Feature Pack in SAP Release changelog display |
| 1.4.107 | 12.05.2026 | Add SAP Release Feature Pack display to config changelog |
| 1.4.106 | 12.05.2026 | Compact config changelog and remove source column |
| 1.4.105 | 12.05.2026 | Resolve open blacklisted alerts on startup |
| 1.4.104 | 12.05.2026 | Enforce filesystem blacklist for alerts and summaries |
| 1.4.103 | 12.05.2026 | Fix duplicate sender_address syntax error in alert reminders |
| 1.4.102 | 12.05.2026 | Restore OAuth sender mailbox persistence and usage |
| 1.4.101 | 12.05.2026 | Make dashboard subtitle same size as header title |
| 1.4.100 | 12.05.2026 | Rebrand header to ANG System Health, remove digest mail severity prefix |
| 1.4.99  | 12.05.2026 | Apply filesystem blacklist to analysis trends (not just alerts) |

---

## Projektstruktur

```
client/
  linux/
    collect_and_send.sh    # Linux-Agent: Metriken sammeln + senden
    install_agent.sh       # Linux-Installationsskript
    self_update.sh         # Linux Self-Update
  windows/
    collect_and_send.ps1   # Windows-Agent
    install_agent.ps1      # Windows-Installationsskript
    self_update.ps1        # Windows Self-Update
    bulk_update_agents.ps1 # Massenupdate für Windows-Agents
server/
  receiver.py              # HTTP-Server, REST-API, Alert-Engine
  data/
    monitoring.db          # SQLite-Datenbank (WAL)
    sap_b1_version_map.json # SAP B1 Build-Zuordnungstabelle
  static/
    index.html             # Dashboard HTML
    app.js                 # Dashboard Logik (Vanilla JS)
    styles.css             # Dashboard Styling
    sw.js                  # Service Worker (PWA)
    manifest.json          # Web App Manifest
openapi.yaml               # OpenAPI 3.0.3 Spec
AGENT_VERSION              # Aktuelle Agent-Versionsnummer
BUILD_VERSION              # Aktuelle Server/App-Versionsnummer
```

---

## Changelog (Agent)
n### v1.6.204 (18. Mai 2026)

- **License Card Height Fix**: Lizenzkarte nun mit korrekter 56px Höhe wie andere Header-Chips; 3x2 Grid-Layout mit gleichmäßigen Reihenabständen.
n### v1.6.203 (18. Mai 2026)

- **License Card Redesign**: Lizenzkarte mit vereinfachter Struktur neu aufgebaut; 3x2 Grid-Layout mit allen 6 Lizenzfeldern, gleiche Höhe und gelber Balken wie andere Header-Chips.
n### v1.6.202 (18. Mai 2026)

- **License Card Border**: Linker Balken von Orange zu Gelb geändert (Farbcodierung passt besser zum System-Theme).
n### v1.6.201 (18. Mai 2026)

- **Old UI Header**: SAP-Lizenzinfos in den oberen Statuskarten-Bereich verschoben (neben Offene Alerts, gleiche Kartenoptik mit gelbem linken Balken).
- **Layout**: Spaltenabstände innerhalb der Lizenzkarte deutlich verkleinert und Schrift kompakter gemacht.
- **Bereinigung**: Zusätzliche Lizenzkarte im Report-Kopf entfernt; SAP-B1-Bereich bleibt weiterhin erhalten.
n### v1.6.200 (18. Mai 2026)

- **Branding**: App-Name auf "System Infoboard" aktualisiert (Header, Login, PWA, Mail-Branding).
- **Telegram**: Telegram-Alarmtexte enthalten jetzt ebenfalls das neue Branding.
- **Old UI SAP-Karten**: Zusätzliche Lizenz-Karte oben integriert; zeigt alle verfügbaren Lizenzfelder kompakt ("Gültig bis" optional).
n### v1.6.199 (18. Mai 2026)

- **Old UI report hotfix**: JavaScript-Fehler "technicalHostname is not defined" in der Report-Ansicht behoben.
n### v1.6.198 (18. Mai 2026)

- **Old UI SAP card spacing**: Hostbezeichnung und Unterzeile aus dem Report-Header entfernt, damit die 3 großen SAP-Infokarten mehr Platz bekommen und den Header-Bereich dominieren.
n### v1.6.197 (18. Mai 2026)

- **Old UI SAP card alignment**: Titel der 3 SAP-Karten an die dargestellten Werte angepasst und Kartenhöhe/Position im Report-Header korrigiert (kompakter, auf Höhe zwischen Hostbezeichnung links und Datum rechts).
n### v1.6.196 (18. Mai 2026)

- **Old UI SAP header cards**: Kleine SAP/HANA Chips unter dem Hostnamen im Report-Header durch 3 große Karten im ui-next-Stil ersetzt (Feature Pack, Patch Level, Build) und responsiv/dark-mode-fähig gestaltet.
n### v1.6.195 (18. Mai 2026)

- **Old UI header cards**: Die drei oberen Status-Chips nutzen jetzt den moderneren UI-next-Look mit kompakter Card-Optik, linker Farbakzentkante sowie angepasster Dark-Mode-/Mobile-Darstellung.
n### v1.6.194 (18. Mai 2026)

- **UI old refresh**: Obere 3 Status-Chips als kompakte moderne Statuskarten gestaltet (bessere Lesbarkeit, Karten-Look, konsistente Größe im Header).
n### v1.6.193 (18. Mai 2026)

- **ui-next refinements**: Datenbanken-Tab lists actual SQL databases; SAP B1 tab reads real sap_business_one payload fields (FP/PL/Build) and includes detailed license/AddOn info.
n### v1.6.192 (18. Mai 2026)

- **ui-next host card status**: (OK/alert) moved back to top row next to customer name, no longer one line too low.
n### v1.6.191 (18. Mai 2026)

- **ui-next host card typography**: swapped: customer name larger, host designation smaller.
n### v1.6.190 (18. Mai 2026)

- **UI Shortcuts**: ui-next now has missing menu shortcuts for Benutzereinstellungen, globale Ansicht, globale Alerts, kritische Trends, inaktive Hosts, Alarm-Einstellungen, Admin-Einstellungen.
- **Deep-linking**: legacy UI now supports '?start=...' deep-link routing from ui-next.
n### v1.6.189 (18. Mai 2026)

- **Host Visibility**: ui-next now respects host is_hidden and hides hidden hosts by default again; status line now indicates hidden host count.
n### v1.6.188 (18. Mai 2026)

- **SAP Versioning**: ui-next now resolves SAP release/build to Feature Pack using SAP B1 version map (/api/v1/sap-b1-version-map), matching old UI behavior.
n### v1.6.187 (18. Mai 2026)

- **UI Layout**: In ui-next Host-Cards wurde die Header-Reihenfolge angepasst: Kundenname oben, dann Host-Bezeichnung, gefolgt von Hostname + IP.
n### v1.6.186 (18. Mai 2026)

- **Performance**: pull-server-only.sh überspringt jetzt standardmäßig die teure Re-Download-Verifizierung (VERIFY_SYNC=0) und nutzt konfigurierbare parallele Downloads (MAX_PARALLEL_DOWNLOADS, Standard 8); strikte Verifizierung weiterhin über VERIFY_SYNC=1 möglich.
n### v1.6.185 (18. Mai 2026)

- **Pull Scripts**: pull-server.sh und pull-server-only.sh liefern jetzt auch ui-next.html, ui-next.css und ui-next.js aus, damit /ui-next nach einem Server-Update funktioniert.

### v1.6.184

- **UI-Next**: Added country filters and own hosts filter to the parallel UI.

### v1.6.183 (18. Mai 2026)

- **Parallel UI (Variante B) live**: Neue, separate Parallel-Oberflaeche unter `/ui-next` umgesetzt, ohne die bestehende Hauptseite zu veraendern.
- **Header beibehalten**: Der bestehende Brand-Header wurde im neuen Layout uebernommen.
- **KPI-Leiste wie Screenshot**: Vier Kennzahlen-Karten (Offene Alerts, Kritische Trends, Inaktive Hosts, Hosts Healthy) werden direkt unter dem Header dargestellt.
- **Detailansicht mit Historie**: Links Hostliste mit Filtern/Suche, rechts Host-Detailtabs (`Overview`, `Datenbanken`, `SAP B1`, `Filesystems`) inkl. Blaettern durch Reports (Neueste/Neuer/Aelter).

### v1.6.182 (18. Mai 2026)

- **Detail-Mockups erweitert**: `layout-mockups.html` enthaelt jetzt drei zusaetzliche konkrete Detailansichten fuer die Parallel-UI-Planung: (1) Datenbanken, (2) SAP B1, (3) Filesystems. Alle drei enthalten realistische Inhaltsbloecke inkl. Suche, Schnellfilter sowie Benutzer-/Global-/Admin-Settings.

### v1.6.181 (18. Mai 2026)

- **Mockups Bedienlogik konkretisiert**: In allen drei Mockup-Varianten wurden Suche, Schnellfilter sowie Benutzer-/Global-/Admin-Settings als eigene Utility-Leiste sichtbar positioniert, damit die spaetere Navigation eindeutig ist.

### v1.6.173 (18. Mai 2026)

- **Mockups konkretisiert (3 Versionen)**: `layout-mockups.html` zeigt jetzt drei realitaetsnahe Endbild-Varianten mit den aktuellen Informationsgruppen der bestehenden UI: (A) vollstaendige Global-Overview ohne Host-Selektion, (B) vollstaendige Einzelhost-Detailansicht (Overview/Journal/Prozesse/Container/Netzwerk/Filesystems/Databases), (C) Split-View mit Hostliste links und globalem Kontext rechts.

### v1.6.172 (18. Mai 2026)

- **Layout-Mockups modernisiert**: Neue visuelle Vergleichsseite mit zwei Richtungen umgesetzt (`Calm Professional` und `Data-First Compact`) zur Bewertung der Punkte 1-4: ruhiger Hintergrund, vereinfachte Sidebar-Karten, mehr Weissraum und modernere KPI-Karten.

### v1.6.171 (18. Mai 2026)

- **Hostkarten Typografie Feinschliff**: Kundenname wieder reduziert und die darunterliegende Host-Zeile groesser/staerker gesetzt, damit die Proportionen ausgeglichener sind.

### v1.6.170 (18. Mai 2026)

- **Hostkarte Kundenname Fix**: Uebergreifender `span`-Selector hat den Kundennamen auf `11px`/muted ueberschrieben. Regel auf Metazeile eingeschraenkt und Kundenname auf `20px` gesetzt.

### v1.6.169 (18. Mai 2026)

- **Hostkarte Typografie**: Kundenname in der Hostkarte nochmals deutlich vergroessert, damit er visuell klarer dominiert.

### v1.6.168 (18. Mai 2026)

- **Hostkarten CSS Hotfix**: Defekten Chip-Style-Block (fehlende Klammer) korrigiert, der zu kaputtem Karten-Layout und falsch dargestellten Icons fuehrte.

### v1.6.167 (18. Mai 2026)

- **Hostkarten Typografie**: Kundenname in der Hostkarte weiter vergroessert; die drei unteren SAP/HANA/SID-Chips kleiner und mit weniger fetter Schrift dargestellt.

### v1.6.166 (18. Mai 2026)

- **Inaktive Hosts Anzeige**: Platzhalterwerte wie `-`/`--` werden beim Kundennamen nicht mehr vor den Hostnamen gesetzt.

### v1.6.165 (18. Mai 2026)

- **Inaktive Hosts**: Kundenname wird in der Inaktive-Hosts-Karte jetzt vor dem Hostnamen angezeigt (z. B. `Kunde · Anzeigename`).

### v1.6.164 (18. Mai 2026)

- **DB Changelog UI**: Bei HANA-Eintraegen in der Aktionsspalte wird jetzt nur noch `erstellt/geloescht` mit Emoji gezeigt (ohne das Wort `Schema`). Zusaetzlich wurde Spalte 1 verschmälert, damit Spalte 2 weiter nach rechts rueckt.

### v1.6.163 (18. Mai 2026)

- **Startup-Rebuild Stabilitaet**: Changelog-Backfill verarbeitet Reports jetzt streamend statt mit `fetchall` und schreibt zusaetzlich in Intervallen Zwischen-Commits, um OOM-Spitzen beim 18-Tage-Neuaufbau zu vermeiden.

### v1.6.161 (18. Mai 2026)

- **Changelog Rebuild beim Start**: Optionaler Einmal-Trigger fuer einen Greenfield-Neuaufbau aus den letzten 15 Tagen eingebaut. Dabei werden die bestehenden Changelog-Tabellen geloescht und aus den Reports neu aufgebaut.

### v1.6.160 (18. Mai 2026)

- **Installer Jitter**: Initialer Install-Selbsttest laeuft jetzt ohne Jitter (`collect_and_send --no-jitter`), damit die Installation nicht bis zu 5 Minuten verzoegert wird. Reguläre geplante Laeufe behalten Jitter bei.

### v1.6.159 (18. Mai 2026)

- **Hostkarte Typografie**: Chip-Schrift auf normal (nicht fett) umgestellt und Kundenname nochmals um +2px vergrößert.

### v1.6.158 (18. Mai 2026)

- **DB Changelog (HANA Schema)**: Erkennung auf aktuelles Payload-Feld `hana_db_info.schemas` erweitert (mit Legacy-Fallbacks), damit neu angelegte HANA-Schemas im DB-Changelog korrekt als erstellt erscheinen.

### v1.6.157 (18. Mai 2026)

- **Hostkarte Typografie**: Kundenname in der Hostkarte um weitere 2px vergrößert.

### v1.6.156 (18. Mai 2026)

- **Hostkarten Chips**: Eckenradius der SAP/HANA/SID-Chips weiter reduziert (noch kantiger).

### v1.6.155 (18. Mai 2026)

- **Hostkarten Chips**: SAP/HANA/SID-Chips visuell auf eine blau abgestimmte Farbkombi umgestellt und mit kleinerem Eckenradius (weniger rund) versehen.

### v1.6.154 (18. Mai 2026)

- **Hostkarte Feinschliff**: Prod-Gradient aufgehellt (weiterhin klar von Test unterscheidbar), Firmenname größer dargestellt und Hostbezeichnung mit `🏷️` statt bisherigem Emoji.

### v1.6.153 (18. Mai 2026)

- **Hostkarte Umgebung**: `Prod/Test` wird nicht mehr als Chip in der Hostkarte gezeigt; `Prod/Test` erscheint im Detail-Header. Prod-Hosts erhalten stattdessen einen navy-bläulichen Kartenhintergrund, Test bleibt beim bisherigen Hintergrund.
n### v1.6.152 (18. Mai 2026)

- **Hostkarte Layout**: Kundenname wird als normale Info (mit Emoji) dargestellt; darunter wird die Hostbezeichnung als zusätzliche Zeile angezeigt.

### v1.6.151 (18. Mai 2026)

- **Host-Interessen**: Kundenname wird in der Liste jetzt als erste Zusatzinformation pro Zeile angezeigt.

### v1.6.150 (18. Mai 2026)

- **Filesystem Drilldown Close Fix**: Das `X`, der Backdrop und `Escape` schließen das Filesystem-Drilldown jetzt zuverlässig, auch wenn das Modal-Markup erst nach dem Script geladen wird.
n### v1.6.149 (18. Mai 2026)

- **Filesystem Chart Drilldown Fix**: Klick auf FS-Chart öffnet nun zuverlässig das korrekt selektierte Chart; Drilldown-Fenster lässt sich wieder sauber schließen.

### v1.6.148 (18. Mai 2026)

- **Server Pull (Linux Installer)**: `pull-server-only.sh` lädt und spiegelt jetzt auch `client/linux/install_agent.sh` nach `updates/client/linux/install_agent.sh`.

### v1.6.147 (18. Mai 2026)

- **Einzelmeldung Chip-Design**: SAP/HANA Chips in der Einzelmeldung verwenden jetzt exakt dieselben Hostkarten-Klassen und damit das identische Pill-Design.

### v1.6.146 (18. Mai 2026)

- **Einzelmeldung Chip-Rendering Fix**: SAP/HANA Chips werden in der Einzelmeldung wieder zuverlässig angezeigt (Fallback auf Host-Metadaten, wenn Report-Felder fehlen).

### v1.6.145 (18. Mai 2026)

- **Einzelmeldung Chip-Farben**: SAP Feature Pack, HANA Release und HANA SID in der Einzelmeldung jetzt im gleichen Orangeton wie in der Hostkarte.

### v1.6.144 (18. Mai 2026)

- **Chip Colors**: SAP Feature Pack, HANA Release, and HANA SID chips now use consistent orange color scheme across all views

### v1.6.143 (21. Mai 2026)

- **Host Interests Auto-Sync**: When user selects hosts, mail subscriptions are automatically activated for those hosts. When hosts are deselected, mail subscriptions are disabled.

### v1.6.142 (18. Mai 2026)

- **UI Text**: Bereich "Login Changelog" in der Globalansicht auf "Anmeldungen" umbenannt.

### v1.6.141 (18. Mai 2026)

- **Globalansicht**: Bereich "Kunden" (Tab + View + Event-Verkabelung) vollständig entfernt.

### v1.6.140 (18. Mai 2026)

- **Kundenansicht UI**: Kunden-Toggle-Zeilen entschärft (weniger Chip-Optik) und nicht mehr über volle Breite bis zum rechten Rand.

### v1.6.139 (18. Mai 2026)

- **Journal Fehler Fix**: Ersten Buchstaben der Meldung nicht mehr abschneiden (Off-by-one bei short-iso Zeitstempel-Parsing).

### v1.6.138 (18. Mai 2026)

- **Kundennamen Font-Größe**: Angepasst auf 13px für bessere Platznutzung bei längeren Namen.

### v1.6.136 (18. Mai 2026)

- **Chip Farben**: SAP/HANA/SID und Kundennamen Chips transparenter und heller gestaltet für bessere Harmonie mit Hostkarten-Hintergrund.

### v1.6.180 (18. Mai 2026)

- **Hostkarten-Hintergrund zurueckgesetzt**: Der eigentliche Kartenhintergrund wurde auf den Stand vor der letzten Farbumstellung zurueckgestellt. Die aktuellen Pillenfarben (Kunde/SAP/HANA/SID) bleiben unveraendert.

### v1.6.179 (18. Mai 2026)

- **Chip-Farben vereinheitlicht**: In der vorletzten Hostkarten-Reihe nutzen jetzt alle drei Chips (SAP, HANA, SID) den gleichen Stil/Farbton `#f7a600`.

### v1.6.178 (18. Mai 2026)

- **Hostkarten-Pillenfarben angepasst**: Die Kundennamen-Pille im Hostkartenkopf nutzt jetzt `#006285`; die HANA-Pillen in der unteren Chip-Reihe wurden auf `#f7a600` umgestellt.

### v1.6.177 (18. Mai 2026)

- **Hostkarten-Gradient auf Markenfarben**: Der Hintergrundverlauf der einzelnen Hostkarte wurde auf die gewuenschten Farben `#006285` und `#f7a600` umgestellt und insgesamt leicht dunkler abgestimmt.

### v1.6.176 (18. Mai 2026)

- **Hostkarten-Hintergrund leicht dunkler**: Der bestehende Verlauf auf der einzelnen Hostkarte wurde in den gleichen Farbtönen beibehalten, aber dezent dunkler abgestimmt, damit die Karten etwas mehr Tiefe und Kontrast haben.

### v1.6.175 (18. Mai 2026)

- **Host-Kundenpille vereinheitlicht**: Die Kunden-Pille im Host-Kartenkopf nutzt jetzt immer die volle verfuegbare Breite (unabhaengig von der Textlaenge). Dadurch erscheinen alle Karten im Headerbereich einheitlicher ausgerichtet.

### v1.6.174 (18. Mai 2026)

- **Mail-Header Kunde + Host**: In ausgehenden hostbezogenen Mails wird der Kunde jetzt im Header prominent angezeigt (gleiche Groesse wie bisherige Host-Hauptzeile), die Hostbezeichnung darunter deutlich kleiner. Die Darstellung wurde zentralisiert und in Instant-/Reminder-Alerts sowie hostbezogenen Testmails vereinheitlicht.

### v1.6.173 (18. Mai 2026)

- **DB Changelog HANA-Schema**: HANA-Einträge werden im DB Changelog jetzt explizit als Schema behandelt/angezeigt (inkl. Aktionstext für Schema erstellt/gelöscht). SQL-Datenbanken bleiben unverändert im bisherigen Format.

### v1.6.172 (18. Mai 2026)

- **Host-Changelog getrennt**: Im hostbasierten Bereich wurde ein separater Menüpunkt `DB Changelog` wieder eingeführt. DB-Änderungen werden dort angezeigt; der hostbasierte Standard-`Changelog` zeigt wieder nur Konfig-/Hardware- und AddOn-Änderungen.

### v1.6.171 (17. Mai 2026)

- **Harvest SQL Setup robuster**: `setup_harvest_sql_user.ps1` behandelt Auth-/Rechteprobleme jetzt besser (GRANT als Best-Effort mit Warnungen statt hartem Abbruch) und unterstuetzt optionalen SQL-Admin-Fallback via `HARVEST_SETUP_SQL_ADMIN_USER` + `HARVEST_SETUP_SQL_ADMIN_PASSWORD` in `agent.conf`.

### v1.6.170 (17. Mai 2026)

- **Changelog Spaltenbreiten**: Die Feld-Spalte wurde im Host- und Global-Changelog deutlich vergroessert; die Spalten "Alter Wert" und "Neuer Wert" wurden entsprechend verkleinert, damit Feldnamen besser vollstaendig sichtbar sind.

### v1.6.169 (17. Mai 2026)

- **Hardware-Changelog Symbol**: Hardware-basierte Changelog-Felder zeigen jetzt zusaetzlich das Computersymbol direkt im Feldnamen, z. B. `💻 CPU Cores`, `💻 RAM (GB)`, `💻 Kernel`.

### v1.6.168 (17. Mai 2026)

- **DB-Changelog Symbole**: Im globalen und im hostbasierten Changelog zeigen DB-Lifecycle-Eintraege wieder die bekannten Icons direkt im Text: `✨ DB erstellt` und `🗑️ DB geloescht`.

### v1.6.167 (17. Mai 2026)

- **Changelog Vereinheitlichung**: DB-Lifecycle-Events (Erstellen/Loeschen) sind jetzt im globalen Changelog und im hostspezifischen Changelog enthalten (zusammen mit Hardware-Metriken und AddOn-Aenderungen).
- **Host UI bereinigt**: Der separate Bereich "DB-Verlauf" wurde entfernt; der Sidebar-Bereich "Aenderungen" wurde in "Changelog" umbenannt.

### v1.6.166 (17. Mai 2026)

- **Host-Aenderungsprotokoll AddOns**: Der Host-spezifische Tab "Aenderungen" zeigt jetzt auch SAP/HANA AddOn-Versionsaenderungen (LW/Legacy) direkt im Kunden-Host-Changelog an.

### v1.6.165 (17. Mai 2026)

- **Changelog Filter**: Neuer "3 Tage" Zeitraumfilter hinzugefuegt; ist jetzt auch der Standard beim Seitenaufruf.

### v1.6.164 (17. Mai 2026)

- **Changelog Kundengroupierung**: Kunde ist jetzt die oberste Gruppierungsebene; Host-Display-Name (mit Hostname als Untertitel) ist die zweite Ebene. Backend gibt `customer_name` zurueck (via JOIN auf `customers`).

### v1.6.163 (17. Mai 2026)

- **Critical-Trends Chips**: Fehlenden `.ct-badge`-Selektor ergaenzt – jetzt erscheinen "Kritisch" und "Warnung" beide als einheitliche Chips.
- **Kundenname kleiner**: Schriftgroesse in den Trend-Karten von 20px auf 14px reduziert.
 
### v1.6.162 (17. Mai 2026)

- **Critical-Trends Kundenzeile ohne Platzhalter**: In der Kundenzeile der Trend-Karten wird bei fehlendem Kundenwert kein `-` mehr angezeigt (kein Fallback auf Dash).

### v1.6.161 (17. Mai 2026)

- **Mute-Icone statusorientiert**: In den Alert-Aktionen zeigt `🔇` jetzt den stummgeschalteten Status und `🔔` den aktiven (nicht stummgeschalteten) Status.

### v1.6.160 (17. Mai 2026)

- **Kundenname in Critical-Trends sichtbar**: In den Trend-Karten wird der Kunde nun vorne in der Kopfzeile angezeigt (oberhalb vor dem Hostnamen), wie in der angefragten Ansicht.

### v1.6.159 (17. Mai 2026)

- **Changelog-Block bereinigt**: Der v1.6.158-Eintrag wurde aus dem Dateikopf in den Abschnitt `Changelog (Agent)` verschoben.

### v1.6.158 (17. Mai 2026)

- **Global-Alerts Spaltenbreiten optimiert**: `Host`, `Mountpoint`, `Aktiv seit` und `Aktion` neu austariert, damit rechte Inhalte nicht mehr aus dem Rahmen laufen.
- **Actions kompakter gemacht**: Geringerer Button-Abstand/Padding und `nowrap` fuer die Aktionsgruppe, damit die rechte Spalte stabil bleibt.

### v1.6.157 (17. Mai 2026)

- **Hotfix Receiver-Start**: Syntaxfehler in der CSV-Export-Quoting-Zeile behoben (`receiver.py`), der zu `status=1/FAILURE` beim Service-Start fuehren konnte.

### v1.6.156
- Alerts table now includes current value and absolute delta columns; alerts API and CSV export include current_used_percent and delta_used_percent.
### v1.6.155 (17. Mai 2026)

- **Dark Mode Lesbarkeit korrigiert**: Der Kundenname in der Global-Alerts-Ansicht nutzt jetzt im Dark Mode eine helle Schriftfarbe, damit er nicht mehr mit dem Hintergrund verschmilzt.

### v1.6.154 (17. Mai 2026)

- **Alerts-Zeile typografisch angepasst**: Kundenname jetzt gross und fett wie die bisherige Hostzeile, Hostbezeichnung darunter 2px kleiner und nicht mehr fett.

### v1.6.153 (17. Mai 2026)

- **Alerts-Ansicht startet mit quittierten Alerts**: Das Häkchen `Quittierte anzeigen` ist nun standardmaessig aktiv und die Tabelle zeigt beim Start auch quittierte Eintraege.

### v1.6.152 (17. Mai 2026)

- **Kundenname in Global-Alerts korrigiert**: Die Alerts-Ansicht bezieht den Kunden jetzt aus dem gleichen Host-Settings/Customer-Join wie die anderen Übersichten, damit dort nicht nur ein Platzhalter angezeigt wird.

### v1.6.151 (17. Mai 2026)

- **Kunde in Global-Alerts sichtbar**: In der Alerts-Ansicht steht der Kundenname jetzt oberhalb der Hostbezeichnung, damit offene Alerts schneller zugeordnet werden koennen.

### v1.6.150 (17. Mai 2026)

- **Inaktive-Hosts Versand implementiert**: Bei aktivierter Option werden inaktive Hosts jetzt tatsaechlich als Benachrichtigung versendet (Mail + Telegram), inklusive Deduplizierung pro Host/Channel, damit pro Inaktiv-Phase nicht mehrfach gesendet wird.
- **Neue Inaktive-Hosts Mailvorlage**: Branded HTML-Mail mit App-Logo im Header, ANG-Logo im Footer und Host-Tabelle (letzte Meldung, Inaktivdauer, Status DOWN).

### v1.6.149 (17. Mai 2026)

- **Inaktive-Hosts Mockup erweitert**: App-Logo im Header und ANG-Logo im Footer eingebaut, plus Telegram-Nachrichtenentwurf unterhalb des Mail-Layouts ergänzt.

### v1.6.148 (17. Mai 2026)

- **Inaktive-Hosts-Mail Mockup hinzugefuegt**: Neues Entwurfs-HTML unter `inactive-host-mail-mockup.html` im gleichen visuellen Stil wie die bestehenden Digest-Mails, mit Fokus auf Host-Down/Inaktiv-Informationen.

### v1.6.147 (17. Mai 2026)

- **"Agent Quelle" jetzt Admin-Only**: Der Menüpunkt ist nun nur für Admins sichtbar; Nicht-Admins werden bei direkter Submode-Auswahl automatisch auf "Globale Alerts" zurückgeführt.

### v1.6.146 (17. Mai 2026)

- **Hinweistexte in Sidebar-Navigation**: Unter "Container" steht nun klein "Nur wo Docker läuft", unter "Export" "Nur Linux Systeme".

### v1.6.145 (17. Mai 2026)

- **Konsistentes manuelles Backup**: `_create_database_backup_job` verwendet jetzt `Connection.backup()` statt rohem `shutil.copy2` — WAL-aware, keine Inkonsistenz durch zeitversetzte Kopien von `.db`, `-wal` und `-shm`.

### v1.6.144 (17. Mai 2026)

- **Automatischer sFTP Upload integriert**: Nach lokalem Backup wird die erzeugte Datei bei aktivierter sFTP-Konfiguration automatisch auf den Zielserver hochgeladen (manuell + Scheduler).
- **Run-Status erweitert**: `uploaded_sftp` wird nun korrekt gesetzt; Upload-Fehler werden im Lauf als Fehlertext gespeichert.

### v1.6.143 (17. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.142 (17. Mai 2026)

- **Backup-Run Tabelle erweitert**: Neue Spalte `sFTP` zeigt im UI pro Lauf an, ob die Datei hochgeladen wurde (`ja`/`nein`).

### v1.6.141 (17. Mai 2026)

- **Host-Chips transparenter gemacht**: SAP/HANA/SID-Chips (z. B. FP2602, 2.00.087, ANG) verwenden jetzt einen weiss-transparenten Hintergrund.

### v1.6.140 (17. Mai 2026)

- **sFTP Testfunktion eingebaut**: Neuer Admin-Button "sFTP testen" prueft Verbindung und fuehrt einen echten Test-Upload (put + rm) im Zielpfad aus.
- **Backend-Endpoint ergaenzt**: `/api/v1/admin/backup-automation/test-sftp` mit Validierung fuer Host/Port/User/Auth und klaren Fehlermeldungen.
- **Auth-Unterstuetzung**: SSH-Key direkt unterstuetzt; Passwort-Modus wird ueber `sshpass` getestet (falls auf dem Server vorhanden).

### v1.6.139 (17. Mai 2026)

- **Kundenchip nach links verschoben**: Der Kundenname-Chip steht in Reihe 2 jetzt ganz links unter der Host-Bezeichnung.
- **Rechte Gruppe beibehalten**: Host-Controls und Meldungszaehler bleiben rechts ausgerichtet.

### v1.6.138 (17. Mai 2026)

- **Kundenchip in Reihe 2 angehoben**: Der Kundenname-Chip wurde leicht nach oben versetzt, damit er visuell auf derselben Hoehe wie die Nachbar-Controls sitzt.

### v1.6.137 (17. Mai 2026)

- **Reihe 2 nachgezogen**: Die Meldungsanzeige "Meldung X von Y" wurde auf dieselbe Hoehe wie die Chips/Buttons (24px) gesetzt.
- **Header-Zeilen konsistent**: Erste und zweite Header-Zeile verwenden nun durchgaengig dieselbe Kontrollhoehe.

### v1.6.136 (17. Mai 2026)

- **Header-Hoehen vereinheitlicht**: Chips und Buttons im Host-Headerbereich auf die Hoehe von "Export JSON" (24px) angeglichen.
- **Refresh-Dropdown angepasst**: Intervall-Select hat nun dieselbe Kompakthoehe wie die benachbarten Controls.

### v1.6.135 (17. Mai 2026)

- **Header-Zeile 2 rechts gebuendelt**: Alle Chips der zweiten Zeile werden zur rechten Seite verschoben.
- **Meldungsanzeige gruppiert**: Kunden- und Host-Controls stehen direkt neben "Meldung X von Y".

@@### v1.6.134 (17. Mai 2026)
@@
@@- **Zweite Zeile neu angeordnet**: Kundenname → Buttons → Meldungs-Info (via CSS order).
@@- **Verbesserte Lesbarkeit**: Klarere Abfolge der Informationen von links nach rechts.
@@

### v1.6.130 (17. Mai 2026)

- **Erste Zeile umgestaltet**: API/Count Chips nun nach rechts neben den Refresh-Tools.
- **Zweite Zeile optimiert**: Kundenname ganz links, Buttons (Visibility/Favorite) ganz rechts.
- **Verbesserte visuelle Balance**: Klarere Trennung zwischen Kontroll-Elementen und Meta-Informationen.

### v1.6.129 (17. Mai 2026)

- **Header-Layout reorganisiert**: API-Key und Report-Count Chips in die erste Zeile verschoben (neben Title).
- **Zweite Zeile neu strukturiert**: Kundenname bleibt auf der linken Seite, Buttons (Visibility/Favorite) auf der rechten.
- **Verbesserte Raumaufteilung**: Klarere visuelle Trennung zwischen Kontroll-Elementen und Daten-Informationen.

### v1.6.97 (17. Mai 2026)

- **Kundenname-Chip größer**: Schrift jetzt 16px (vorher 14px) für mehr Prominenz.
- **Hostbezeichnung kleiner**: Von 10px auf 9px für bessere Gewichtung der Hierarchie.
- **Verbesserte visuelle Balance**: Kundenname dominiert noch stärker, Details sind untergeordnet.

### v1.6.96 (17. Mai 2026)

- **Host-Karte umstrukturiert**: Kundenname-Chip rückt nach oben (größere, intensivere Schrift), Hostbezeichnung nach unten (klein).
- **Verbesserte visuelle Hierarchie**: Kundenname ist jetzt das prominenteste Element, Hostbezeichnung untergeordnet.
- **Chip-Styling für Kundenname**: Der Chip oben hat nun 14px Schrift und Weight 900 für maximale Betonung.

### v1.6.95 (17. Mai 2026)

- **Kunden-Name auf separate Zeile**: Der Kunden-Chip wird konsequent auf einer eigenen Zeile unterhalb der SAP/HANA-Chips angezeigt.
- **Bessere optische Hierarchie**: Kleinere (10px) und fettere Schrift (Weight 700) für konsistente visuelle Trennung.
- **Konsistentes Layout**: Kunden-Information ist jetzt unabhängig von anderen Chip-Kombinationen immer auf derselben Position.

### v1.6.94 (17. Mai 2026)

- **Host-Karte um Kunden-Chip erweitert**: In der unteren Chip-Zeile wird bei zugewiesenem Kunden jetzt ein zusätzlicher Kunden-Chip angezeigt.
- **Kunden-Icon angepasst**: Der Chip verwendet das Firmengebäude-Emoji `🏢` (statt Personen-Emoji).

### v1.6.93 (17. Mai 2026)

- **Systemübersicht Kundengruppe korrigiert**: Die 2. Ebene verwendet jetzt den echten `customer_name` statt Host-Anzeigename.
- **Hierarchie wieder korrekt**: Anzeige ist jetzt konsistent `Land → Kunde → Hosts`.

### v1.6.92 (17. Mai 2026)

- **Neue Admin-Übersicht für veraltete Agenten**: Zeigt Hosts, deren Agent-Version mindestens 5 Versionen hinter der aktuellen Repo-Agent-Version liegt.
- **Self-Update-Früherkennung**: Major/Minor-Abweichungen werden ebenfalls als potentiell kritischer Rückstand markiert.
- **Direkt im Admin-Bereich**: Die neue Tabelle ist im Abschnitt „Agent Update Status (Alle Hosts)“ integriert.

### v1.6.91 (17. Mai 2026)

- **Systemübersicht: Kundenebene standardmäßig zugeklappt**: Unter jedem Land starten Kunden jetzt geschlossen.
- **Neuer Button `Alles aufklappen` (Systemübersicht)**: Öffnet alle Gruppen auf einmal.
- **Neuer Button `Alles aufklappen` (Backup Stati)**: Öffnet alle Kunden-Gruppen auf einmal.

### v1.6.90 (17. Mai 2026)

- **Systemübersicht-Anzeige korrigiert**: In der Host-Zeile wird wieder der echte Host-Name angezeigt statt erneut des Kunden-Namens.
- **Hierarchie visuell eindeutig**: Dadurch ist die Struktur wieder klar als `Land → Kunde → Host` erkennbar.

### v1.6.89 (17. Mai 2026)

- **Backup Stati: Kunden standardmäßig zugeklappt**: Die Kundenebene startet jetzt immer geschlossen.
- **Unabhängig vom Status**: Kein automatisches Aufklappen mehr bei fehlenden aktuellen Backups.

### v1.6.88 (17. Mai 2026)

- **Changelog-Hierarchie angepasst**: Im Changelog-Bereich ist die erste Ebene jetzt `Kunde`.
- **Neue zweite Ebene `Host`**: Unter jedem Kunden werden die einzelnen Hosts separat gruppiert angezeigt.
- **Datums-Topgruppe entfernt**: Die vorherige oberste Gruppierung nach Datum entfällt zugunsten der Kundenstruktur.

### v1.6.87 (17. Mai 2026)

- **Systemübersicht weiter vereinfacht**: In der Standardsicht ist die Hierarchie jetzt nur noch `Land → Kunde`.
- **OS-Zwischenebene entfernt**: Hosts eines Kunden werden unabhängig vom Betriebssystem in einer gemeinsamen Tabelle angezeigt.
- **Sicht-/Sorttexte angepasst**: Labels zeigen in der Standardsicht jetzt konsistent `Land > Kunde`.

### v1.6.86 (17. Mai 2026)

- **Systemübersicht-Hierarchie neu aufgebaut**: In der Standardsicht ist die Gruppierung jetzt `Land → Kunde → OS`.
- **Kundenebene als zweite Stufe**: Pro Land werden zuerst die Kunden gruppiert und danach die jeweiligen Betriebssysteme.
- **Sort-/Sichttexte aktualisiert**: Button- und Statistik-Label zeigen jetzt konsistent `Land > Kunde > OS` an.

### v1.6.85 (17. Mai 2026)

- **Backup-Status mit zusätzlicher Hierarchie**: Neue Top-Gruppierung nach Kunde im Bereich "Backup Stati".
- **Struktur Kunde → Hosts**: Unter jedem Kunden werden die zugehörigen Host-Karten wie bisher angezeigt.
- **Kunden-Kennzahlen in Summary**: Pro Kundengruppe werden Host-Anzahl sowie aktuelle vs. fehlende Backups aggregiert dargestellt.

### v1.6.84 (17. Mai 2026)

- **Telegram Quick Actions zurück**: Alert-Nachrichten enthalten wieder einen direkten Button zum Quittieren.
- **Neu: Schliessen aus Telegram**: Zusätzlich gibt es nun einen zweiten Button zum direkten Schliessen des Alerts.
- **Signierter Action-Link**: Neue verifizierte Endpoint-Verarbeitung über `GET /api/v1/telegram/alert-action` mit Ablaufzeit und HMAC-Signatur.
- **Gilt für Instant + Reminder**: Buttons werden bei offenen/escalated Alerts und Heads-Up-Reminder-Nachrichten angehängt.

### v1.6.83 (17. Mai 2026)

- **Host-Suche erweitert**: Die bestehende Suche im Hosts-Bereich durchsucht jetzt zusätzlich Kundendaten.
- **Neu durchsuchbar**: Neben Hostname/Anzeigename werden jetzt auch `customer_name` und `customer_maringo_project_number` berücksichtigt.

### v1.6.82 (17. Mai 2026)

- **Auto-Backups sichtbar im Admin-Bereich**: Läufe der automatischen Backups werden tabellarisch angezeigt.
- **Tabellenfelder erweitert**: Datum, Uhrzeit, Quelle, Status, Datei, Größe, Link und Fehler werden pro Lauf gelistet.
- **Direkter Download-Link**: Jeder erfolgreiche Lauf enthält jetzt einen klickbaren Download-Link zur zugehörigen Backup-Datei.
- **Sicherer Download-Endpoint**: Neuer Admin-Endpoint `GET /api/v1/admin/backup-automation/download?run_id=...` mit Pfadvalidierung.

### v1.6.81 (17. Mai 2026)

- **Masken-Layout angepasst**: "Meldung X von Y" ist jetzt in der zweiten Zeile rechts ausgerichtet.
- **Kunden-Chip verschoben**: Der Kunden-Chip wurde aus der oberen Titelzeile in die zweite Zeile an die frühere Position der Meldungsanzeige verschoben.

### v1.6.80 (17. Mai 2026)

- **Automatische DB-Backups**: Lokale SQLite-Backups laufen jetzt automatisch im Hintergrund (Default: alle 12 Stunden).
- **Retention eingebaut**: Alte automatische Backup-Dateien werden automatisch nach der konfigurierten Aufbewahrungszeit (Default: 7 Tage) bereinigt.
- **Admin-API ergänzt**: Neue Endpoints für Backup-Automation (`GET/POST /api/v1/admin/backup-automation`, manueller Trigger für lokales Backup).
- **Admin-UI erweitert**: Neuer Bereich "Backup Automation (lokal + sFTP vorbereitet)" mit Settings, Sofort-Backup-Button und Laufhistorie.
- **sFTP vorbereitet**: sFTP-Konfigurationsfelder werden gespeichert (Host/Port/User/Path/Auth), Upload-Logik folgt in einem späteren Schritt.

### v1.6.79 (17. Mai 2026)

- **Charts mit Skala**: Dezente horizontale Gitternetzlinien und Y-Achsenwerte pro Chart ergänzt.
- **Bessere Lesbarkeit**: Skalen sind bewusst zurückhaltend gestaltet und in Light/Dark-Theme abgestimmt.

### v1.6.78 (17. Mai 2026)

- **Delta-Farben im DB-Verlauf**: Positive Delta-Werte werden jetzt grün, negative rot dargestellt.
- **Dark-Theme berücksichtigt**: Angepasste Grün-/Rot-Töne für gute Lesbarkeit in dunkler Ansicht.

### v1.6.77 (17. Mai 2026)

- **Manueller Trigger in der UI**: Neuer Button `↻ Jetzt berechnen` im Bereich `DB Wartung (SQLite)`.
- **Direktaufruf des Trigger-Endpoints**: Der Button ruft `POST /api/v1/admin/database-stats/trigger` auf und lädt Charts/Verlauf unmittelbar neu.
- **Saubere Sperrlogik**: Während `VACUUM` oder manuellem Rechnen sind die jeweiligen Buttons gegenseitig deaktiviert.

### v1.6.76 (17. Mai 2026)

- **DB-Berechnungsintervall auf 2h** umgestellt (statt 3h).
- **UI dynamisch angepasst**: Status- und Delta-Texte zeigen jetzt das effektive Intervall (z. B. Δ2h, Nächster 2h-Lauf).
- **Manueller Trigger ergänzt**: Neuer Admin-Endpoint `POST /api/v1/admin/database-stats/trigger` berechnet den aktuellen Bucket sofort neu und liefert das aktualisierte Dashboard zurück.

### v1.6.75 (17. Mai 2026)

- **DB-Kennzahlen als Charts**: Die bisherigen Kennzahlen-Karten wurden durch 6 KPI-Charts ersetzt.
- **Trendindikatoren**: Jeder Chart zeigt Trendpfeil (steigend/fallend/stabil), aktuelles Niveau und 3h-Delta.
- **Responsive Reihenlayout**: Auf großen Screens 6 Charts in einer Reihe, bei weniger Platz automatische Verteilung auf 2 Reihen (3+3), mobil weiter reduziert.

### v1.6.74 (17. Mai 2026)

- **Hotfix Admin-Load**: DB-Kennzahlen-Verlauf wird beim Öffnen des Admin-Tabs jetzt aktiv geladen (nicht nur beim initialen App-Start).
- **Symptom behoben**: Der Bereich bleibt nicht mehr auf "Lade DB Kennzahlen-Verlauf..." stehen, wenn Login/Admin-Status erst nach dem Bootstrapping verfügbar ist.

### v1.6.73 (17. Mai 2026)

- **Admin-Tab umbenannt**: Registerkarte heißt jetzt **Admin** statt "Admin Settings".
- **Admin-Bereiche verschoben**: "Admin Aktionen", "DB Wartung (SQLite)" und "Agent Update Status" sind jetzt im Admin-Tab gruppiert.
- **DB-Kennzahlen automatisiert**: Kennzahlen werden automatisch in eine Historien-Tabelle geschrieben (alle 3 Stunden, Zeitzone konfigurierbar), inklusive Start-Snapshot.
- **Kein manueller Kennzahlen-Refresh mehr**: Der manuelle ↻-Button wurde entfernt.
- **Charts + 14-Tage-Trendanalyse**: Visualisierung der wichtigsten Kennzahlen und lineare 2-Wochen-Prognose im DB-Wartungsbereich.
- **Verlaufstabelle**: Anzeige der letzten 20 Historienzeilen inklusive Veränderung zur vorherigen Zeile (+/-).

### v1.6.72 (16. Mai 2026)

- **Chips in Titelzeile**: API-Chip, Meldungsanzahl-Chip, Kunden-Chip und Action-Buttons sind jetzt in der Titelzeile eingebaut statt in einer zweiten Reihe — die Header-Karte bleibt gleich hoch.
- **Trennlinie** zwischen Chips-Gruppe und Refresh/Export-Tools.
- **✏️-Button kompakt** (24px, passend zu den Chips).

### v1.6.71 (16. Mai 2026)

- **Kundennamen nachträglich bearbeiten**: Im Kunden-Tab erscheint bei jedem Kunden ein ✏️-Button. Klick öffnet einen Dialog zum Ändern von Name und Maringo-Projektnummer (PATCH `/api/v1/customers/<id>`).


\
- **Chips einheitlich gross**: Alle Chips und Buttons in der Host-Kopfzeile haben jetzt dieselbe Hoehe wie der "Export JSON"-Button (24px, gleicher Border-Radius).\
- **Kundenchip als erstes Element**: Der Kunden-Chip steht jetzt ganz links in der Kontrollleiste vor API, Meldungsanzahl und den Action-Buttons.

### v1.6.69 (16. Mai 2026)

- **Hotfix 502 nach Login**: Absturz im Endpoint `/api/v1/hosts` behoben (Spalten-Mismatch zwischen SQL-Query und Python-Mapping).
- **Hostkarten wieder sichtbar**: Laden der Hostliste funktioniert wieder stabil.
- **Bleistift wieder nutzbar**: Da Hosts wieder geladen werden, ist der Host-Bearbeiten-Flow wieder erreichbar.

### v1.6.68 (16. Mai 2026)

- **Neue Kunden-Auswertung (Global-Tab)**: Eigene Ansicht "Kunden" mit Kennzahlen je Kunde fuer Hosts, offene Alerts, kritische Alerts und Backup-Luecken.
- **Drilldown pro Kunde**: Aufklappbare Hostliste je Kunde inklusive Land, Alert-Zahlen und Backup-Status.
- **Suche integriert**: Filter nach Kunde, Maringo-Projektnummer sowie Hostname/Hosttitel direkt in der Kundenansicht.

### v1.6.67 (16. Mai 2026)

- **Hotfix Service-Start**: SQL-Syntaxfehler in der `host_settings`-Tabellendefinition behoben, der den Receiver beim Start mit `sqlite3.OperationalError` beendet hat.
- **Init-DB wieder stabil**: Monitoring-Service startet nach dem Update wieder normal.

### v1.6.66 (16. Mai 2026)

- **Kundenstamm eingefuehrt**: Neue Kunden werden zentral gespeichert und koennen Hosts sauber zugeordnet werden.
- **Host-Bearbeiten erweitert**: Der ✏️-Dialog kann jetzt Titel, Land und Kunde in einer Maske bearbeiten.
- **Dropdown statt Freitext-Dubletten**: Bestehende Kunden sind auswaehlbar; alternativ kann ein neuer Kunde direkt angelegt werden.
- **Optionale Maringo-Projektnummer**: Beim Anlegen eines Kunden kann eine Maringo-Projektnummer mitgespeichert werden.

### v1.6.65 (16. Mai 2026)

- **Alert-Abos nach Land gruppiert**: In der Host-Ansicht sind Hosts jetzt in Ländergruppen zusammengefasst.
- **Bessere Uebersicht bei vielen Hosts**: Pro Land wird ein klarer Gruppenkopf mit Host-Anzahl angezeigt.
- **Filter sauber integriert**: Such-/Benutzer-/"Nur Aenderungen"-Filter blenden ganze Laendergruppen automatisch aus, wenn darin kein sichtbarer Host mehr passt.

### v1.6.64 (16. Mai 2026)

- **Alert-Abos mit umschaltbarer Ansicht**: Admin-Bereich kann jetzt zwischen Host-Ansicht und User-Ansicht wechseln.
- **Skalierung fuer viele Benutzer verbessert**: Gleiche Abo-Daten lassen sich je nach Aufgabe host-zentriert oder benutzer-zentriert bearbeiten.
- **Unsaved-Changes bleiben beim Ansichtswechsel erhalten**: Nicht gespeicherte Checkbox-Aenderungen gehen beim Wechsel Host/User nicht verloren.

### v1.6.63 (16. Mai 2026)

- **Alert-Abos besser bedienbar**: Hostsuche, Benutzerfilter und Option "Nur Aenderungen" im Admin-Abo-Bereich hinzugefuegt.
- **Bulk-Aktionen erweitert**: Sammelaktionen fuer sichtbare Eintraege (Mail/Telegram an/aus) sowie pro Host (Mail/Telegram alle an/aus).
- **Aenderungen klar sichtbar**: Geaenderte Checkboxen/Zeilen werden visuell markiert und der Status zeigt die Anzahl ungespeicherter Aenderungen.

### v1.6.62 (16. Mai 2026)

- **Globales Telegram in eigene Karte verschoben**: Bot Token, globale Chat ID und Telegram an/aus stehen jetzt in einer separaten Telegram-Karte neben den Schwellwert-Karten.
- **Benachrichtigungskarte vereinfacht**: Der Bereich enthaelt nun nur noch Heads-Up-/Inaktiv-Logik und ist dadurch deutlich uebersichtlicher.

### v1.6.61 (16. Mai 2026)

- **Telegram-Settings im UI praezisiert**: Globaler Bot/Channel klar von persoenlicher Telegram Chat ID getrennt beschriftet.
- **Benachrichtigungsbereich verstaendlicher**: Hinweise im Admin-Panel erklaeren, dass Bot Token systemweit ist und persoenliche Chat IDs pro Benutzer gepflegt werden.

### v1.6.60 (16. Mai 2026)

- **Separates Telegram Heads-Up Intervall**: In den globalen Alarm-Einstellungen gibt es jetzt ein eigenes Feld fuer Telegram-Reminder, unabhaengig vom Mail-Intervall.
- **Mail und Telegram entkoppelt**: Offene Alerts fuehren nun getrennte Reminder-Zeitstempel pro Kanal, damit unterschiedliche Intervalle sauber parallel funktionieren.
- **UI klar erweitert**: Benachrichtigungsbereich zeigt jetzt Mail- und Telegram-Heads-Up als zwei separate, kanalbezogene Intervalle.

### v1.6.59 (16. Mai 2026)

- **Heads-Up Intervall im UI praezisiert**: Beschriftung klar als Mail-Intervall markiert.
- **Klarstellung fuer Betrieb**: Das globale Heads-Up-Intervall gilt fuer wiederholte Mail-Heads-Ups bei offenen Alerts, nicht fuer Telegram.

### v1.6.58 (16. Mai 2026)

- **Globale Alarm-Einstellungen sauber verdrahtet**: Backend persistiert jetzt alle Felder aus dem Admin-Panel konsistent (inkl. CPU/RAM-Schwellen, Inaktive-Hosts-Optionen und KI-Parameter).
- **Fix fuer verlorene Inaktive-Hosts-Einstellung**: `Inaktive Hosts alarmieren` und `Inaktiv ab (Stunden)` bleiben nach Speichern/Neuladen erhalten.
- **API-Response vervollstaendigt**: `GET/POST /api/v1/alarm-settings` liefern jetzt die vollstaendige Feldmenge fuer das UI.
- **OpenAI-Key sicher behandelt**: Key bleibt serverseitig erhalten, wenn das Feld leer bleibt; API liefert nur `openai_api_key_is_set` statt Klartext.

### 1.4.137 (14.05.2026)
- Add SAP license information extraction and display (Hardware Key, Instno, Expiration, System Nr, Customer Name, Customer No)

### v1.4.75 (11. Mai 2026)

- **Privates GitHub-Repo unterstützt**: `pull-server-only.sh` kann Deploy-Dateien jetzt authentifiziert per GitHub-Token aus einem privaten Repo laden.
- **Token-Quellen**: `MONITORING_GITHUB_TOKEN`, `GITHUB_TOKEN` oder `GH_TOKEN`; alternativ liest das Skript `MONITORING_GITHUB_TOKEN` aus der serverseitigen `monitoring.env`.
- **Deploy-Hinweise erweitert**: README und `monitoring.env`-Template dokumentieren den einmaligen Token-Schritt für Server-Deploys bei privatem Repo.

### v1.4.74 (11. Mai 2026)

- **Agent-Quelle Ansicht optisch verdichtet**: kleinere Schrift und kompaktere Zellen für mehr Host-Zeilen auf gleicher Höhe.
- **Breite besser genutzt**: Tabellenlayout der "Agent Quelle"-Seite auf bessere Spaltenverteilung angepasst, weniger abgeschnittene Werte.
- **Lesbarkeit verbessert**: URL-Felder umbrechen nun kontrolliert statt früh mit Ellipsis zu enden.

### v1.4.73 (11. Mai 2026)

- **agent.conf Migration für bestehende Agents**: Linux- und Windows-`self_update` schreiben relevante Source-Keys jetzt aktiv nach (`SERVER_URL`, `UPDATE_BASE_URL`, `RAW_BASE_URL`) und leeren `GITHUB_REPO`.
- **Neue Global-Seite "Agent Quelle"**: Tab mit Host-Tabelle für schnellen Umstellungsstatus auf server-only Quelle.
- **Ampel-Checks pro Host**: `SERVER_URL`, `UPDATE_BASE_URL`, `RAW_BASE_URL`, `GITHUB_REPO` werden pro Host ausgewertet; korrekte Werte sind gruen markiert.
- **Neuer API-Endpunkt**: `/api/v1/agent-source-status` liefert den Migrationsstatus aus der letzten gemeldeten `agent.conf` pro Host.

### v1.4.72 (11. Mai 2026)

- **Server-only Quelle für Install/Update**: Linux/Windows Update- und Bootstrap-Skripte nutzen jetzt ausschliesslich die konfigurierten Server-Updates (`SERVER_URL/updates` bzw. `UPDATE_BASE_URL`).
- **Kein GitHub-Fallback mehr im Agent-Pfad**: Download-Fallbacks auf `raw.githubusercontent.com`/GitHub wurden aus den Agent-Skripten entfernt.
- **Install-Beispiele angepasst**: Installer-Beispiele verweisen auf die eigene Server-Quelle.

### v1.4.71 (11. Mai 2026)

- **DB-Schema Guard für Host-Config**: Der Server stellt vor Host-Config-Tracking/Backfill jetzt runtime-sicher sicher, dass `host_config_snapshot.kernel_release` existiert.
- **Nutzen**: Alte/extern eingespielte DBs ohne neue Spalte brechen nicht mehr bei Host-Config-Operationen.

### v1.4.70 (11. Mai 2026)

- **HANA AddOn-Parser tolerant gemacht**: CSV-Extraktion fällt jetzt bei Mischformaten automatisch auf die Zeilenlogik zurück, damit echte AddOn-Daten nicht mehr im `parse_failed` landen.
- **Ziel**: die bereits wieder ankommenden Daten auch bei leicht variierendem hdbsql-Output sauber als AddOns erfassen.

### v1.4.69 (11. Mai 2026)

- **1.4.42-Mehrfach-Commit Abgleich umgesetzt**: HANA-Abfragepfad wurde gegen die originale 1.4.42-Kette abgeglichen und robust gemacht.
- **Spaltennamen-Fallbacks für heterogene Hosts**: Query-Varianten für `Version/VERSION` sowie `AName/ANAME` werden automatisch probiert, um `invalid column name` auf einzelnen Hosts zu vermeiden.
- **Verbindungs-Fallback erweitert**: Bei Connect-Fehlern wird nicht nur der Port, sondern auch Host-Ziele (`127.0.0.1`, `localhost`, Hostname/FQDN) gegen aktive `3xx15`-Listener geprobt.

### v1.4.68 (11. Mai 2026)

- **HANA Query-Regression gefixt**: SQL-Statements werden für `su -c` jetzt shell-sicher escaped, damit quoted Identifier wie `"Version"` und `"AName"` korrekt bei hdbsql ankommen.
- **Fehlerbild behoben**: `invalid column name: VERSION/ANAME` durch verlorene Quotes in der Refaktorierung.

### v1.4.67 (11. Mai 2026)

- **Rückkehr zur 1.4.42-Verbindungsstrategie**: HANA AddOn-Queries nutzen wieder zuerst den impliziten `hdbsql`-Modus (ohne `-n`), wie im früh stabilen Stand.
- **Fallback bleibt erhalten**: Explizites `target` und lokale `3xx15`-Port-Probe bleiben als nachgelagerter Fallback aktiv.
- **Ziel**: Verhalten wieder an den urspruenglich funktionierenden Ablauf angleichen, ohne die neuen Diagnosepfade zu verlieren.

### v1.4.66 (11. Mai 2026)

- **Connection-Diagnose erweitert**: Bei `query_failed` mit Verbindungsfehler liefert der Agent jetzt zusätzlich Runtime-Listener-Infos (`listener_target`, `listeners_3xx15`, `sid`) direkt im Fehlertext.
- **Ziel**: sofort sichtbar machen, ob auf dem Host zur Laufzeit wirklich ein SQL-Listener auf `:30015` aktiv ist.

### v1.4.65 (11. Mai 2026)

- **HANA Port-Fallback gehaertet**: SID-Erkennung passiert jetzt vor der SQL-Port-Autodetection, damit Instanz-basierte Ports (`3xx15`) korrekt berechnet werden.
- **Runtime-Probe bei `connection refused`**: Bei lokalem Ziel und fehlschlagendem `30015` testet der Agent automatisch aktive lokale `3xx15`-Ports (via `ss`) und nutzt den funktionierenden Port für beide AddOn-Queries.

### v1.4.64 (11. Mai 2026)

- **HANA SQL-Port Auto-Detection**: Wenn `HANA_ADDONS_PORT` noch auf Default `30015` steht, erkennt der Linux-Agent die lokale Instanznummer automatisch (z. B. `HDB90`) und nutzt den passenden SQL-Port (z. B. `39015`).
- **Verbindungs-Fix ohne manuelle Konfig**: Hosts mit abweichender Instanznummer brauchen damit kein manuelles Port-Override mehr für AddOn-Queries.

### v1.4.63 (11. Mai 2026)

- **HANA AddOns Regression-Hotfix**: Bei `connection failed` auf explizitem `HANA_ADDONS_HOST:HANA_ADDONS_PORT` fällt der Linux-Agent automatisch auf den frueheren impliziten `hdbsql`-Verbindungsmodus zurück.
- **Diagnose erweitert**: Payload enthaelt jetzt `target_mode` sowie `mode=lw:...,lg:...` im Fehlertext, damit sichtbar ist, ob der Fallback aktiv war.

### v1.4.62 (11. Mai 2026)

- **Host-Config-Changelog erweitert**: `OS Release` und `Kernel` werden jetzt als eigene Metriken verfolgt und als Änderungen geloggt.
- **Snapshot-Migration integriert**: Bestehende Datenbanken erhalten das neue Feld `kernel_release` automatisch beim Serverstart.

### v1.4.61 (11. Mai 2026)

- **HANA AddOns Connection-Fix**: `hdbsql` nutzt jetzt ein explizites Ziel (`HANA_ADDONS_HOST:HANA_ADDONS_PORT`) statt implizitem Default `localhost:30015`.
- **Stabilerer Standard**: neue Defaults `HANA_ADDONS_HOST=127.0.0.1`, `HANA_ADDONS_PORT=30015`.
- **Selbstheilung**: `self_update.sh` und `repair_agent_conf.sh` schreiben die neuen Felder automatisch in `agent.conf`.
- **Bessere Diagnose**: `error` enthält jetzt zusätzlich das verwendete `target=...`.

### v1.4.60 (11. Mai 2026)

- **Parse-Failed Diagnose erweitert**: Bei `reason=parse_failed` liefert der Linux-Agent jetzt ein kurzes hdbsql-Snippet (`LW`/`LEG`) im Fehlertext, damit das konkrete Rohformat direkt im UI sichtbar wird.

### v1.4.59 (11. Mai 2026)

- **Linux HANA AddOn Parser erweitert**: Fallback erkennt jetzt zusätzlich tabellarische (`Mehrfach-Whitespace`) und `;`-getrennte hdbsql-Zeilen.
- **Bessere Diagnose statt Silent-Empty**: Bei vorhandenem hdbsql-Output ohne erkannte Zeilen wird jetzt `reason=parse_failed` geliefert (statt irrefuehrendem `empty_result`).

### v1.4.58 (11. Mai 2026)

- **Self-Update Quelle stabilisiert**: Wenn `UPDATE_BASE_URL` fehlt, wird jetzt zuerst `RAW_BASE_URL` verwendet und erst danach als Fallback `SERVER_URL/updates`.
- **Konfig fixiert**: `UPDATE_BASE_URL` wird beim Self-Update wieder in `agent.conf` geschrieben, damit kuenftige Updates konsistent von derselben Quelle kommen.

### v1.4.57 (11. Mai 2026)

- **Linux Repair-Skript ohne Prompts**: Das neue Repair-Skript schreibt alle relevanten Agent-Konfigurationsfelder automatisch neu, statt Werte vom Benutzer abzufragen.
- **HANA-Felder bleiben gesetzt**: `HANA_SID` und `HANA_ADDONS_*` werden aus vorhandenen Werten bzw. Defaults wieder aufgebaut.

### v1.4.56 (11. Mai 2026)

- **Linux Self-Update setzt HANA-Felder neu**: Fehlende `HANA_SID` und `HANA_ADDONS_*` Eintraege werden beim Update wieder in `agent.conf` geschrieben.
- **Konfigurations-Rehydrierung**: Wenn ein Host nur noch die Basisfelder hat, stellt der Updater die HANA-Parameter wieder her statt sie stillschweigend fehlen zu lassen.

### v1.4.55 (11. Mai 2026)

- **Linux Agent HANA AddOns stabilisiert**: hdbsql-Fehler wie `authentication failed` / `SQLSTATE` werden nicht mehr als AddOn-Zeilen interpretiert.
- **Bessere Fehlerdiagnose im Payload**: Statt leerer/irrefuehrender AddOn-Listen liefert der Agent jetzt bei Query-Problemen klare `reason`-Werte (`auth_failed`, `query_failed`, `partial_result`) und eine konkrete Fehlermeldung.

### v1.4.54 (11. Mai 2026)

- **Einzelmeldungen Navigation repariert**: In der Reports-Ansicht funktionieren Vorherige/Naechste Meldung wieder korrekt (Paginierungs-State wiederhergestellt).
- **HANA AddOns robuster gerendert**: HANA AddOn-Tabellen werden jetzt angezeigt, sobald Zeilen im Payload vorhanden sind, auch wenn das `available`-Flag fehlt oder inkonsistent ist.

### v1.4.53 (11. Mai 2026)

- **15-Minuten-Reports AddOn-Fix (UI)**: Die AddOn-Anzeige in den Host-Meldungen verarbeitet jetzt auch kombinierte HANA-Felder wie `Name","Version` und `Name",?` korrekt.
- **Noisy hdbsql-Zeilen gefiltert**: Footer wie `rows selected` / Timing-Zeilen werden in der Report-Ansicht nicht mehr als AddOn-Eintrag verarbeitet.

### v1.4.52 (11. Mai 2026)

- **HANA AddOn CSV-Kombi-Fix**: Die Backend-Normalisierung splittet jetzt wieder korrekt Werte im Format `"AddOnName","Version"`, sodass Name und Version getrennt im Changelog erscheinen.
- **Fehlende AddOn-Daten behoben**: Betroffene Hosts mit kombiniertem hdbsql-Feld zeigen AddOn-Änderungen nicht mehr als zusammengeklebten Namen mit `-` als Version.

### v1.4.49 (11. Mai 2026)

- **Changelog-Backfill sichtbar gemacht**: Der Button nutzt jetzt einen 30-Tage-Backfill und zeigt die resultierende 30d-Sicht direkt an, damit Hosts wie Rinco sofort auftauchen.
- **Changelog-Pfeile bereinigt**: Die nested Summary-Elemente im Changelog blenden den nativen Marker jetzt ebenfalls aus.

### v1.4.48 (11. Mai 2026)

- **Changelog-Backfill per Button**: Im Changelog gibt es jetzt einen Button, der gespeicherte Reports erneut auswertet und `host_config_changes` auffuellt.

### v1.4.47 (11. Mai 2026)

- **HANA AddOns bereinigt**: Der Agent und die UI entfernen jetzt hdbsql-Footer und doppelte Anführungszeichen aus AddOn-Zeilen.

### v1.4.46 (11. Mai 2026)
- **Deploy-Zielpfad robuster (`pull-server-only.sh`)**: Ohne Parameter wird das Ziel jetzt zuerst aus der bestehenden `monitoring.service` (`WorkingDirectory`) übernommen.
- **Fallback-Logik verbessert**: Wenn keine Unit vorhanden ist, nutzt das Skript den lokalen Repo-Pfad (falls vorhanden) statt blind `$HOME/monitoring-server`.
- **Wirkung**: Verhindert Deploys in ein falsches Verzeichnis bei identischer UI trotz Restart/Reboot.

### v1.4.45 (11. Mai 2026)
- **Deploy-Fix (`pull-server-only.sh`)**: Der Service `monitoring` wird nach dem Update jetzt automatisch neu gestartet.
- **Sichtbarkeits-Fix für UI-Updates**: Durch den automatischen Restart greifen neue `receiver.py` Header-/Routing-Änderungen direkt, statt bis zum manuellen Restart zu warten.

### v1.4.44 (11. Mai 2026)
- **Webclient-Update-Zuverlässigkeit**: No-Cache Header für `app.js`, `styles.css`, `sw.js` und `manifest.json`; Service Worker wird versionsgebunden registriert.
- **Host-Changelog Sichtbarkeit**: HANA AddOns werden beim ersten Auftreten als `addon-init` Eintrag angezeigt (nicht erst bei spaeteren Delta-Änderungen).
- **Darstellungsstabilität**: AddOn-Normalisierung für gemischte hdbsql-Formate bleibt erhalten, inklusive sauberer Werte ohne Timing-Footer-Artefakte.

### v1.4.43 (11. Mai 2026)
- **HANA AddOns Parsing verbessert**: Linux-Agent verarbeitet nun sowohl Pipe-Format (`A|B`) als auch CSV-Format (`"A","B"`) von hdbsql robust.
- **UI-Darstellung bereinigt**: Timing-Footer wie `rows selected (overall time...)` werden nicht mehr als AddOn-Zeile dargestellt.
- **Host-Changelog erweitert**: Änderungen der HANA AddOns fliessen jetzt in die Host-Config-Changes ein (`HANA LW` / `HANA Legacy`) und werden sauber formatiert angezeigt.

### v1.4.42 (11. Mai 2026)
- **HANA AddOns Extraction**: Neue Funktionalität für Linux Agent zur Auslesung von HANA AddOns über hdbsql
  - Lightweight Extensions aus `SLDDATA.EXTENSIONS` (Tabelle: NAME, Version)
  - Legacy AddOns aus `SBOCOMMON.SARI` (Tabelle: AName, AddOnVer)
  - Read-only Abfragen mit konfigurierbarem Timeout (default: 15 Sekunden)
  - Graceful Failure: Fehlende User/hdbsql/Timeout führen nicht zu Agent-Hängern
- **UI Update**: AddOns-Section im System-Tab zeigt nun auch HANA Extensions separat von SQL B1 AddOns
  - HANA Extensions (Lightweight + Legacy) collapsible unter SAP B1 AddOns
  - Aussagekräftige Fehlermeldungen bei User-nicht-angelegt oder hdbsql nicht vorhanden

### v1.4.41 (früher)
- AddOns Card mit subtlem Hintergrund-Gradient
