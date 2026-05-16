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

- **Agent** läuft per Cron (Standard: alle 5 Minuten) und sendet ein JSON-Paket mit System-Metriken an den Server.
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
