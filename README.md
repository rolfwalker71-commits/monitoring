# Monitoring – Server & Agent

Zentrales Monitoring-System für Linux- und Windows-Hosts, betrieben als selbst-gehosteter Web-Service auf einer Synology NAS.

**Produktiv:** `https://infoboard.ang-schweiz.ch`

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
curl -sSL https://infoboard.ang-schweiz.ch/updates/client/linux/install_agent.sh | bash
```

**Windows (PowerShell als Admin):**

```powershell
irm https://infoboard.ang-schweiz.ch/updates/client/windows/install_agent.ps1 | iex
```

**Windows repair/bootstrap für bestehende Hosts:**

```powershell
& .\bootstrap_agent.ps1 -ServerUrl https://infoboard.ang-schweiz.ch -DisableJitter
```

Der Wrapper zieht die aktuellen Windows-Skripte von `/updates`, repariert eine bestehende Installation in place und schaltet Jitter nur für diesen Lauf aus.

### Self-Update

Agents prüfen selbständig (alle ~6 Stunden, plus bei jedem Sammellauf wenn die Version veraltet ist) die vom Server bereitgestellten Pakete unter `/updates` und aktualisieren sich automatisch. Die aktuelle Agent-Version steht in `AGENT_VERSION`.

Wichtig für die Domain-Migration: Self-Update und Repair schreiben vorhandene Hosts aktiv auf die neue Canonical-URL `https://infoboard.ang-schweiz.ch` um, aber nur wenn die URL vom Host aus erreichbar ist. Als sichere Fallback-Quellen bleiben `https://infoboard.an-group.work/updates` und `https://monitoring.rolfwalker.ch/updates` aktiv.

### Payload-Sicherung vor Versand

Vor jedem `POST /api/v1/agent-report` speichert der Agent den ausgehenden JSON-Payload lokal als Snapshot.

- Rotation: standardmäßig werden die letzten **4** Snapshots behalten, ältere Dateien werden automatisch gelöscht.
- Linux-Pfad (Default): `/var/lib/monitoring-agent/payload-history`
- Windows-Pfad (Default): `C:\ProgramData\monitoring-agent\payload-history`
- Konfigurierbar über Umgebungsvariablen:
  - `PAYLOAD_ARCHIVE_DIR` (Zielordner)
  - `PAYLOAD_ARCHIVE_KEEP` (Anzahl zu behaltender Snapshots)

Damit kann nachträglich exakt geprüft werden, was der Agent zu einem Zeitpunkt gesendet hat (z. B. bei fehlenden SQL-/HANA-Daten).

### Query-Fehler im Payload (bereits vorhanden)

Ja: Query- und Verbindungsfehler werden bereits im Payload mitgegeben und können in den Snapshot-Dateien analysiert werden.

- Windows Hauptagent (`sap_business_one`):
  - `harvest_status.error`
  - `extensions.error` (aus `extensions_error`)
  - `sari_addons.error` (aus `sari_addons_error`)
- Linux Agent:
  - `hana_addons.error` und `hana_addons.reason` (z. B. `auth_failed`, `query_failed`, `partial_result`)
  - `hana_db_info.error` und `hana_db_info.reason`
- Windows SAP-Scan (`collect_and_scan_sap_tables.ps1`):
  - `sap_business_one.table_scan.sbo_common_sari.error`
  - `sap_business_one.table_scan.sld_extensions.error`

**Extensions-Abfrage (corrected):**  
Die Lightweight Extensions-Abfrage nutzt die korrekte Join-Bedingung `ON ed.[Extension_Id] = e.[Id]` (Windows) bzw. `"EXTENSIONDEPLOYMENTS"."EXTENSION_ID" = "EXTENSIONS"."ID"` (Linux/HANA), um nur aktiv deployete Extensions zu zeigen – die übrigen in der Extensions-Tabelle sind historisch und nicht mehr in Verwendung.

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

- Applikations-Version: `BUILD_VERSION` (semantisch, aktuell: **1.7.179**)
- Agent-Version: `AGENT_VERSION` (separat versioniert, aktuell: **1.7.179**)
- API-Spec: `openapi.yaml` (OpenAPI 3.0.3, Version folgt BUILD_VERSION)

### Recent Releases (v1.4.99+)

| Version | Datum | Änderung |
|---------|-------|----------|
| 1.7.179 | 01.06.2026 | SAP-Lizenzinfo-Liste besser lesbar gemacht: Zeilen unter „Lizenztyp / Anzahl“ jetzt im Zebra-Muster (abwechselnd hell und hellgrau) mit leichtem Innenabstand/Radius; Dark-Mode-Variante analog in zwei abgestuften dunklen Hintergründen umgesetzt. |
| 1.7.178 | 01.06.2026 | Login-Layout angepasst: schwebendes App-Logo so positioniert, dass es etwa zu einem Drittel in die Hauptkarte hineinragt, inkl. stärkerem Rahmen-/Ring-Look. Gleichzeitig den oberen Karten-Inhalt nach unten verschoben (mehr Top-Padding), damit sich Logo und Überschrift nicht überlappen (Desktop + Mobile, Light + Dark). |
| 1.7.177 | 01.06.2026 | Header-Branding angepasst: Zeile „ANG Monitoring Suite“ im Hauptheader entfernt und der Titel „System Infoboard“ sichtbar grösser sowie kräftiger gesetzt (höhere Schriftgrösse und Font-Weight), damit die Hauptüberschrift klarer dominiert. |
| 1.7.176 | 01.06.2026 | KPI-Breitenkorrektur nach Oversize-Feedback: Start-/Fallback-Breite reduziert und die Breiten-Synchronisierung auf verfügbare Strip-Breite begrenzt (`fit-to-row`), sodass die KPI-Karten wieder vollständig in eine Zeile passen. Persistierte Altwerte werden dabei automatisch auf die neue Maximalbreite eingegrenzt. |
| 1.7.175 | 01.06.2026 | KPI-Startup beruhigt: Karten erscheinen jetzt direkt in stabiler Zielgrösse statt im Ladeverlauf mehrfach sichtbar zu wachsen. Umgesetzt durch festen Initial-Fallback (`--kpi-uniform-card-width`) plus monotone Breiten-Synchronisierung ohne vorheriges Zurücksetzen auf Auto, inklusive Persistenz der zuletzt ermittelten Breite und Re-Sync nach Font-Ready. |
| 1.7.174 | 01.06.2026 | Header-Feinschliff nach UI-Feedback: KPI-Kartenabstände im finalen Header-Override vereinheitlicht (Sonderabstand bei Gruppenstart entfernt), sodass die Karten durchgehend gleichmässig getrennt sind. Zusätzlich wurde die obere Icon-Leiste als gemeinsame Gesamtkarte gestaltet (ein Container mit integrierten Icon-Buttons in Light/Dark), statt wie einzelne isolierte Pills zu wirken. |
| 1.7.173 | 01.06.2026 | KPI-Karten auf Wunsch gleichbreit umgesetzt: alle sichtbaren KPI-Chips erhalten jetzt dynamisch die Breite der jeweils breitesten Karte im Strip. Implementiert über JS-Messung + CSS-Variable (`--kpi-uniform-card-width`) inkl. Re-Sync bei KPI-Updates und Window-Resize. Ergebnis: optisch einheitliche Kartenbreiten ohne willkürlichen Stretch-Mix. |
| 1.7.172 | 01.06.2026 | KPI-Strip final kompakt gestellt: im finalen Header-Override von gleichbreiten Karten (`1fr`) auf inhaltsbreite Karten (`max-content`) umgestellt und Typografie/Padding weiter reduziert. Ergebnis: deutlich schmalere KPI-Karten, kein überbreiter Stretch-Effekt und kein sichtbarer Scrollbalken im oberen KPI-Bereich. |
| 1.7.171 | 31.05.2026 | KPI-Layout ohne Scrollbar: KPI-Karten wurden kompakter gemacht (kleinere Paddings, reduzierte Typografie, geringere Mindesthöhe/-breite, engeres Gap), und der Strip wurde wieder auf nicht-scrollendes Grid (`overflow: hidden`) umgestellt, sodass alle Karten in einer Zeile ohne sichtbaren Scrollbalken dargestellt werden. |
| 1.7.170 | 31.05.2026 | KPI-Header-Strip korrigiert: letzte Karte wird nicht mehr abgeschnitten. Der Strip ist jetzt horizontal scrollbar (inkl. dezenter Light/Dark-Scrollbar), mit verbessertem rechtem Innenabstand und Snap-Verhalten für sauberes horizontales Navigieren bei vielen KPI-Karten. |
| 1.7.169 | 31.05.2026 | Theme-Toggle auf Icon-only-Variante umgestellt: Textlabel `Dark/Light` entfernt, Switch als kompakte reine Icon-Schaltfläche ausgeführt und Accessibility über `aria-label`/`title` beibehalten. Sonne/Mond-Zustand bleibt direkt am Thumb sichtbar. |
| 1.7.168 | 31.05.2026 | Theme-Toggle visuell verbessert: Switch zeigt jetzt ein Sonne/Mond-Symbol direkt am Thumb (Sonne im Light-Mode, Mond im Dark-Mode) mit leicht vergrößertem Track für bessere Lesbarkeit und klarere Zustandsrückmeldung. |
| 1.7.167 | 31.05.2026 | Header-Iteration nach UX-Feedback: im Hauptheader wieder auf das vertraute Bildlogo umgestellt (statt erfundenem CSS-Signet), Session-Zähler in der Profil-Card entfernt und die Header-Höhe insgesamt reduziert (kompaktere Abstände, kleineres Logo/Avatar/Controls). Login-Maske wurde auf denselben Logo-Stil angepasst, damit Branding zwischen Login und Hauptansicht konsistent bleibt. |
| 1.7.166 | 31.05.2026 | Premium-Header-Variante: Brand-Bereich typografisch aufgewertet (neuer Kicker, stärkere Titelpräsenz, atmosphärischerer Header-Background) und das linke CSS-Brand-Mark komplett überarbeitet, damit es auf hellem Hintergrund klar lesbar bleibt. Das Signet ist jetzt ein kontraststarkes Monitor-/Dashboard-Symbol statt einer zu subtilen Form. |
| 1.7.165 | 31.05.2026 | Header-Feinschliff: Bild-Icons im linken Brand-Bereich und bei den Plattformen durch eine konsistentere, CSS-basierte Formsprache ersetzt (Brand-Mark links, Linux/Windows als ruhige Plattform-Pills). Die rechte Seite wurde zu einer markanteren Profil-Card mit Avatar, Name und Session-Status ausgebaut. Ziel: weniger Stilbruch, klarere Account-Hierarchie und ein bewussterer Premium-Look. |
| 1.7.164 | 31.05.2026 | Header-Redesign im Hauptlayout: rechter Bereich als kompakte Account-Zone neu gefasst, Theme-Toggle entrahmt, User/Logout in eine gemeinsame Glass-Card gelegt, Titeltypografie beruhigt und Versions-/Plattform-Metadaten visuell zurückgenommen. Ziel: weniger Pill-Unruhe, klarere Hierarchie und modernerer Kopfbereich ohne kompletten Layoutbruch. |
| 1.7.163 | 31.05.2026 | Changelog-Backfill-Pre-Seeding auch für `backfill_host_config_changes` nachgezogen: Erster Report pro Host im Rebuild-Fenster erhielt fälschlicherweise `VORHER=-`-Einträge für alle Hardware-/HANA-Felder (`backfill-init`). Fix: Snapshot des letzten Reports **vor** dem Fenster wird vorab geladen, damit `include_initial_snapshot_events=True` nur für wirklich neue Hosts (ohne jegliche Vorgeschichte) greift. **„Rebuild heute"** auf **„Rebuild 30d"** umgestellt (30 statt 1 Tag), damit alle gängigen Zeitfenster (24h–30d) nach einem Rebuild vollständig befüllt sind. Nach dem Deploy: einmalig **„Rebuild 30d"** ausführen. |
| 1.7.162 | 31.05.2026 | Changelog-DB-Lifecycle-Backfill-Bug behoben: `backfill_database_lifecycle` seeded jetzt `prev_dbs_by_host` aus dem letzten Report **vor** dem Backfill-Fenster. Vorher wurde für den ersten Report jedes Hosts im Fenster jede vorhandene Datenbank fälschlicherweise als „neu erstellt" eingetragen (persistente Fake-`create`-Events in `database_lifecycle`). Nach dem Deploy: einmalig Changelog-Rebuild im Admin-UI triggern, um bestehende Fake-Einträge zu bereinigen. |
| 1.7.161 | 31.05.2026 | Changelog-Phantom-Einträge behoben: `_collect_sap_addon_change_items` seeded jetzt den Vergleichs-Snapshot aus dem letzten Report **vor** dem Zeitfenster. Vorher wurde der erste Report im Fenster immer als neuer Host behandelt, was rollierend Fake-Einträge mit `VORHER=-` erzeugte (alle 30 Minuten neu, nie aus dem Fenster fallend). Nur wirklich neue Hosts ohne jegliche Vorgeschichte erhalten weiterhin Baseline-Einträge. |
| 1.7.160 | 31.05.2026 | Neues Skalierungskonzept fuer Alert-Abos dokumentiert (`docs/processes/alert-abo-skalierungskonzept.md/.html`): Scope-Vererbung (`global -> country -> team -> service -> host_group -> host`), Empfaenger-Gruppen, Tri-State-Regeln (`inherit/force_on/force_off`), Simulations-API und stufenweise Migration vom aktuellen Host-User-Matrixmodell. Prozess-Index wurde um den neuen Eintrag erweitert. |
| 1.7.159 | 31.05.2026 | SAP-Lizenztyp-Matrix auf Sichtbar-Flag umgestellt: pro Zeile gibt es jetzt eine Checkbox `Sichtbar`. Die Auswertungen (inkl. Lizenztyp+Anzahl) verifizieren nun strikt gegen dieses Flag statt gegen reine Übersetzungslogik. Initiale Migration setzt `Sichtbar=Ja` nur für tatsächlich übersetzte Einträge; nicht übersetzte Auto-Discover-Einträge starten leer (`display_name=''`) und unsichtbar. |
| 1.7.158 | 31.05.2026 | Critical-Trends massiv umgebaut für First-Request-Performance: statt N+1-Host-Queries werden Reports, Host-Metadaten und Mute-Regeln jetzt gebatcht geladen und pro Host in-memory verarbeitet. Zusätzlich wurde die Hidden-Mountpoint-Zuordnung robust für `hostname` und `host_uid` vereinheitlicht. Cache-TTLs für schwere Endpoints bleiben separat konfigurierbar (`MONITORING_HOSTS_CACHE_TTL_SECONDS`, `MONITORING_CRITICAL_TRENDS_CACHE_TTL_SECONDS`). |
| 1.7.157 | 31.05.2026 | Performance-Nachschärfung nach Live-Logs: Endpoint-spezifische Cache-TTLs für `/api/v1/hosts` und `/api/v1/critical-trends` erhöht (separat via ENV konfigurierbar), sodass bei normalen Tab-Wechseln tatsächlich `cache=hit` eintritt. Zusätzlich in `/api/v1/critical-trends` N+1-Queries auf `filesystem_visibility` durch eine gebatchte Einzelabfrage ersetzt. |
| 1.7.156 | 31.05.2026 | Zusätzlicher Performance-Hotfix nach Live-Messung: Kurzzeit-Servercache für `/api/v1/hosts` (5s) und `/api/v1/critical-trends` (bis 20s, begrenzt durch globale Cache-TTL) eingeführt. Ergebnis: wiederholte Aufrufe/Tab-Wechsel laden diese schweren Ansichten deutlich schneller; Perf-Logs markieren jetzt explizit `cache=hit`/`cache=miss` für beide Endpoints. |
| 1.7.155 | 31.05.2026 | Endpoint-Performance-Logs jetzt zusätzlich als Datei mit Rotation: neue ENV-Optionen `MONITORING_ENDPOINT_TIMING_FILE_LOG_ENABLED`, `MONITORING_ENDPOINT_TIMING_FILE_LOG_PATH` (Default `server/data/endpoint_perf.log`), `MONITORING_ENDPOINT_TIMING_FILE_LOG_MAX_BYTES` und `MONITORING_ENDPOINT_TIMING_FILE_LOG_BACKUPS`. Damit können Perf-Logs dauerhaft gesammelt und extern analysiert werden, ohne unkontrolliertes Logwachstum. |
| 1.7.154 | 31.05.2026 | Performance-Diagnostik erweitert: zentrale Endpoint-Timing-Logs mit Phasen-Breakdown (`db`, `compute/build`, `send`) für die Hauptansichten (`/api/v1/hosts`, `/api/v1/host-reports`, `/api/v1/analysis`, `/api/v1/alerts`, `/api/v1/critical-trends`, `/api/v1/inactive-hosts`, `/api/v1/backup-status-overview`, `/api/v1/alerts-summary`, `/api/v1/system-overview`). Steuerbar über neue ENV-Variablen `MONITORING_ENDPOINT_TIMING_LOG_ENABLED` und `MONITORING_ENDPOINT_TIMING_LOG_MIN_MS`. |
| 1.7.153 | 31.05.2026 | Performance-Breitband-Optimierung: SQLite-Verbindungen erhalten jetzt globale PRAGMA-Tunings (WAL, `synchronous=NORMAL`, `temp_store=MEMORY`, Cache- und MMAP-Größen via ENV). Zusätzlich wurden mehrere teure Read-Endpunkte (`system-overview`, `inactive-hosts`, `backup-status-overview`, `alerts-summary`) mit kurzem TTL-Servercache versehen. Im Frontend wurden zentrale serielle Ladepfade auf paralleles Laden umgestellt (Host-Panels/Report-Navigation/Admin-Settings), wodurch Ansichten insgesamt schneller sichtbar werden. |
| 1.7.152 | 31.05.2026 | Globale Alerts-Ansicht verfeinert: Spaltenkopf `Used` auf `Initial` umgestellt und Delta-Werte jetzt mit Vorzeichen (`+/-`) sowie semantischer Farbcodierung dargestellt (`+` grün, `-` rot). |
| 1.7.151 | 31.05.2026 | Hotfix Systemübersicht: JavaScript-Initialisierungsfehler `Cannot access 'searchQuery' before initialization` behoben (Variable wird vor URL-Param-Aufbau initialisiert). Aufruf der Systemübersicht funktioniert damit wieder stabil. |
| 1.7.150 | 30.05.2026 | Performance-Fix Systemübersicht: Suchbegriff wird jetzt als Query-Parameter (`q`) an `/api/v1/system-overview` übergeben und serverseitig vorgefiltert. Dadurch werden bei kundenspezifischer Suche deutlich weniger Hosts/Payloads geparst und übertragen, was den initialen Aufruf spürbar beschleunigt. |
| 1.7.149 | 30.05.2026 | Systemübersicht-Lizenztypen gefiltert: es werden jetzt nur noch Lizenztypen angezeigt, die in der SAP-Lizenzzuweisungs-Map übersetzt sind (wie in den übrigen Bereichen). Nicht-gemappte Roh-Lizenztypen werden in der Systemübersicht nicht mehr gelistet. |
| 1.7.148 | 30.05.2026 | Systemübersicht-Korrektur bei doppelten Hostnamen: Kunde/Land werden jetzt priorisiert aus `host_uid_settings` (host_uid-basiert) statt primär hostname-basiert aus `host_settings` gelesen. Dadurch landen Hosts mit korrekter UID-Zuordnung nicht mehr fälschlich unter `XX` / `Ohne Kunde`. |
| 1.7.147 | 30.05.2026 | Admin-Navigation bereinigt: in der oberen horizontalen Global-Registerleiste bleibt nur noch der Einstieg `Admin`; die Unterpunkte `Agent Quelle`, `Alert Abos`, `Anmeldungen` laufen ausschließlich über die linke Admin-Sidebar. Zusätzlich wird die Admin-Sidebar nur noch angezeigt, wenn tatsächlich ein Admin-Unterbereich aktiv ist (nicht mehr bei normalen Global-Menüpunkten). |
| 1.7.146 | 30.05.2026 | Admin-Bereiche-Menü deutlich kompakter gestaltet: kleinere Headline/Unterzeile, reduzierte Kartenhöhen und Paddings, kleinere Icons, engere Abstände und schmalere Sidebar-Spalte im Admin-Workspace-Modus. Ergebnis: wesentlich geringerer Platzbedarf bei weiterhin klarer Lesbarkeit. |
| 1.7.145 | 30.05.2026 | Meldungsbereich nochmals verdichtet: alle Texte inkl. Menüoptionen/Untermenüs, Tabellen und Header-Controls eine weitere Stufe verkleinert; Menüpunkte bleiben bewusst fett für klare Orientierung. |
| 1.7.144 | 30.05.2026 | Meldungsbereich typografisch verdichtet: Schriftgrössen in Header, Tabs, Sidebar, Untermenüs und Tabellen reduziert; Menüpunkte deutlich fetter gesetzt und Untermenü-/Control-Stile vereinheitlicht, damit die gesamte Übersicht ruhiger und besser lesbar wirkt. |
| 1.7.143 | 30.05.2026 | KPI-Werte im Header deutlich verkleinert (kompaktere Zahlentypografie und angepasste Zeilenhoehe), damit insbesondere Metriken mit Einheit wie `MB` weniger dominant wirken und sauberer in die Kacheln passen. |
| 1.7.142 | 30.05.2026 | KPI-Header visuell in Themenblöcke gruppiert (Alarme, Infrastruktur, Datenbank/Metriken) via zusätzliche Block-Abstände; Zahlformat bei DB-Werten vereinheitlicht (`de-CH`, z. B. `1'223`), Einheiten (`MB`) in den Hauptwert verschoben und Unterlabels auf Kontextbegriffe umgestellt (z. B. `Datenvolumen`, `Letzte Stunde`). |
| 1.7.141 | 30.05.2026 | KPI-Icons im Header auf einen einheitlichen, monochromen Symbolstil umgestellt (keine gemischten farbigen/transparenten Emoji-Glyphen mehr) und pro KPI semantisch passend vereinheitlicht (z. B. Warnung, Kritisch, Quittiert, Stumm, Aktiv/Inaktiv, Berichte, DB-Groesse, Delta). |
| 1.7.140 | 30.05.2026 | KPI-Header weiter verdichtet: Kacheln, Zahlen und Label im oberen Info-Strip nochmals verkleinert fuer eine kompaktere Darstellung; zudem KPI-Begriffe sprachlich vereinheitlicht (Deutsch, z. B. `STUMM`, `BERICHTE`, `DB DIFFERENZ 1H`). |
| 1.7.133 | 29.05.2026 | Admin Einstellungen > Betrieb auf Unterbereiche aufgeteilt (Aktionen, DB Wartung, Ingest, Backup, Agent Status), sodass nur noch eine Karten-Gruppe gleichzeitig sichtbar ist; zusätzlich Seitenleisten-Typografie (Titel, Untertitel, Menütext/Icons) auf kompakteres Referenzniveau reduziert. |
| 1.7.132 | 29.05.2026 | Sidebar-Feinschliff gemäß Referenzrhythmik: einheitliche Menü-Kartenhöhe in der linken Admin-Navigation, zusätzliche Trennlinie sowie sichtbarer Gruppenabstand vor dem letzten Menüpunkt für klarere vertikale Struktur. |
| 1.7.131 | 29.05.2026 | Visuelle Angleichung der linken Admin-Menüleiste an das Referenzmuster: neutrales Sidebar-Panel (grau/blau statt orange), größere Titeltypografie, klare vertikale Menü-Buttons mit Icon-Präfixen sowie stärkerer Active-State mit linker Akzentkante. |
| 1.7.130 | 29.05.2026 | Admin-Workspace Breitenfix: zweispaltiges Admin-Layout hart auf Seitenbreite begrenzt (Sidebar + Content), Min-Width/Max-Width für Admin-Content korrigiert und Chart-Grid in Admin-Einstellungen responsiv angepasst, sodass keine Bereiche mehr nach rechts aufreißen oder aus dem Viewport laufen. |
| 1.7.129 | 29.05.2026 | Admin-Bereich optisch auf vertikale linke Menüleiste umgestellt (statt Kachel-Umbruch): die Haupt-Admin-Navigation rendert jetzt als echte Sidebar-Liste mit voller Breite pro Menüpunkt, analog zur gewünschten Navigationslogik aus Einzelmeldungen. |
| 1.7.128 | 29.05.2026 | Admin Einstellungen aufgeteilt: innerhalb des Admin-Tabs wurde eine thematische Unter-Navigation eingeführt (`Betrieb`, `Sicherheit`, `Alerting`, `SAP Mappings`, `Datenhygiene`), sodass jeweils nur eine Funktionsgruppe sichtbar ist und der zuvor überladene Gesamtblock deutlich besser navigierbar wird. |
| 1.7.127 | 29.05.2026 | Admin-Reorganisation Phase 2: Global-Admin-Navigation in einen Workspace-Modus überführt (Sidebar-ähnliches Layout bei aktiven Admin-Unterbereichen), Legacy-Global-Tabs in diesem Modus visuell gedimmt und das Nachladen des aktiven Global-Submodes über eine zentrale Loader-Funktion vereinheitlicht. |
| 1.7.126 | 29.05.2026 | Admin-Reorganisation gestartet (safe scaffold): neue Admin-Navigation im Global-Bereich eingefuehrt, inklusive nicht-destruktiver Bridge auf bestehende Admin-Subtabs (`Agent Quelle`, `Alert Abos`, `Anmeldungen`, `Admin Einstellungen`) und separatem `adminSubMode`-State fuer schrittweise Migration ohne Funktionsverlust. |
| 1.7.121 | 28.05.2026 | Performance-Fix fuer globale Listen: Global Alerts laden Requests jetzt parallel statt sequenziell, und Host-Config-Changelog vermeidet N+1-Lookups durch gebatchte Host-Metadaten. Dadurch erscheinen beide Bereiche deutlich schneller. |
| 1.7.120 | 28.05.2026 | UI-Fix Global Alerts: Aktionsspalte und 4 Icon-Buttons weiter verbreitert, damit die rechte Leiste nicht mehr am Rand abgeschnitten wird. |
| 1.7.119 | 27.05.2026 | Endgueltiger UI-Fix Global Alerts: Tabelle fuer Alerts auf `table-layout:auto` umgestellt und Aktionsspalte als feste Pixelbreite (170px) definiert. Dadurch werden alle 4 Aktionsicons stabil vollständig gerendert (kein Abschneiden am rechten Rand). |
| 1.7.118 | 27.05.2026 | UI-Fix Global Alerts: Aktionsspalte im Tabellenlayout real verbreitert (`colgroup` + feste Button-Breite), damit das 4. Alert-Icon nicht mehr rechts abgeschnitten wird. |
| 1.7.117 | 27.05.2026 | UI-Fix Global Alerts: Schliessen-Button auf robustes Symbol umgestellt, damit in der Aktionsspalte wieder alle 4 Alert-Icons sichtbar sind. |
| 1.7.116 | 27.05.2026 | Backfill/Rebuild-Konkurrenz abgesichert: zentrale Maintenance-Sperre eingefuehrt, damit keine parallelen DB-Heavy-Operationen laufen. Bei Lock-Konflikten liefert Backfill jetzt kontrolliert `409` mit klarer Fehlermeldung statt `500 OperationalError: database is locked`. |
| 1.7.115 | 27.05.2026 | UI-Fix Global Alerts: rechte Aktionsspalte stabilisiert (feste Mindestbreite, kompaktere Button-Paddings, rechtsbuendige Action-Gruppe), damit die 4 Alert-Icons nicht mehr ueber den Rahmen hinausragen. |
| 1.7.114 | 27.05.2026 | Hotfix Global Alerts: JavaScript-Fehler `currentReportStandHtml is not defined` behoben. Die `Aktuell`-Spalte mit `Stand:`-Unterzeile rendert wieder stabil. |
| 1.7.113 | 27.05.2026 | Alerts korrigiert: `Used` bleibt jetzt der urspruengliche Ausloesewert (wird bei offenen Alerts nicht mehr mit jedem Report ueberschrieben). `Aktuell` zeigt weiterhin den letzten gemeldeten Wert und darunter den Zeitstempel des Reports (`Stand: ...`). `Delta` berechnet sich damit wieder gegen den initialen Ausloesewert. Zusätzlich zeigt Backfill-Fehler in der UI den Backend-Fehlertext statt nur HTTP-Status. |
| 1.7.112 | 27.05.2026 | Host-Config-Changelog-Suche erweitert: Suchbegriffe matchen jetzt auch `customer_name`, damit Eintraege wie "Netto" gefunden werden, auch wenn Hostname/UID nicht den Begriff enthalten. |
| 1.7.111 | 27.05.2026 | Changelog-UX/Backfill-Fix: Host-Config-Changelog laedt nicht mehr automatisch beim Tabwechsel oder Filteraenderungen, sondern erst per `Suchen`/`Refresh` (Enter in Suche ebenfalls moeglich). Zusätzlich Einrueckungsfehler im Host-Config-Backfill behoben, damit pro Report immer der korrekte Payload verarbeitet wird. |
| 1.7.110 | 27.05.2026 | Rebuild-Job-Selbstheilung erweitert: ein alter `running`-Job wird automatisch auf `failed` gesetzt, wenn bereits ein neuerer terminaler Job (`completed`/`failed`) existiert. Verhindert Zombie-Status wie „Job #5 läuft“, obwohl ein späterer Job schon fertig ist. |
| 1.7.109 | 27.05.2026 | Global Alerts UI aufgeraeumt: Block "Host-Identitaet (offene Alerts)" vollstaendig entfernt (HTML, Rendering und Styles), damit die eigentliche Alert-Tabelle ohne zusaetzlichen Zwischenblock angezeigt wird. |
| 1.7.108 | 27.05.2026 | Rebuild-Stabilitaet verbessert: SQLite-Busy-Timeout erhoeht (gegen `database is locked`) und hängende Rebuild-Jobs im Status `running` werden nach Inaktivitaets-Timeout automatisch auf `failed` gesetzt, damit neue Rebuilds wieder startbar sind. |
| 1.7.107 | 27.05.2026 | Rebuild-Fehleranzeige verbessert: Bei HTTP-Fehlern zeigt die UI jetzt zusätzlich die Backend-Fehlermeldung (`error`/`message`) statt nur den Statuscode (z. B. `HTTP 500: no such table ...`). |
| 1.7.106 | 27.05.2026 | SAP-Lizenztypen-Changelog: korrekte Schnittmenge – nur Typen werden gespeichert, die SOWOHL im Payload (focus_license_types) vorhanden als AUCH in der Lizenztypen-Übersetzungstabelle eingetragen sind. Nicht-übersetzte Typen aus B01.txt werden ignoriert, auch wenn sie Werte > 0 haben. |
| 1.7.105 | 27.05.2026 | Changelog-Filterung für SAP-Lizenztypen: nur Einträge mit mind. einem Wert > 0 werden gespeichert (kein `- → 0`-Rauschen mehr). Gilt für Live-Tracking, Backfill und Rebuild. |
| 1.7.104 | 27.05.2026 | Changelog um SAP-Lizenztypen-Anzahlen erweitert: pro Host und übersetztem Lizenztyp wird jetzt ein eigener Changelog-Feldkey (`sap_license_type::<TYPE>`) mit Vorher/Neu erfasst. Initialeinträge pro Typ (`- -> Anzahl`) werden gesetzt und Folgeberichte tracken Änderungen kontinuierlich; in UI (Host-Changelog + Global-Changelog) wird beim neuen Wert zusätzlich das Delta in Klammern angezeigt (z. B. `(+2)` oder `(-1)`). |
| 1.7.103 | 27.05.2026 | SAP-Lizenz Hover-Karte erweitert: zeigt jetzt zusätzlich in kleiner Schrift den Zeitstempel `B01.txt Stand` (aus `sap_license.file_mtime_utc`, Linux+Windows), damit sofort sichtbar ist, von wann die gelesenen Lizenzdaten stammen. |
| 1.7.102 | 27.05.2026 | Globale Alert-Ansicht um Filter `Nur Heads-Up unterdrückt` erweitert. Der Filter ist als zusätzliche Checkbox im UI verfügbar und wird serverseitig über `heads_up_suppressed=yes/no` in `/api/v1/alerts` ausgewertet, damit Paging/Total-Zähler konsistent bleiben. |
| 1.7.101 | 27.05.2026 | Alerts-Aktionsleiste um 4. Icon erweitert: pro Host+Mountpoint kann Heads-Up nun separat unterdrückt/reaktiviert werden (ohne Alert zu schließen). Neue persistente Regel-Tabelle (`heads_up_suppression_rules`) inkl. API-Endpoints und UI-Button; unterdrückte Heads-Ups stoppen sowohl Instant-Alerts (Mail/Telegram/Web-Push) als auch Reminder, während der Alert in der Liste sichtbar bleibt. |
| 1.7.100 | 27.05.2026 | Header-KPI Feinschliff: Label der Mute-Kachel auf `Gemuted` geändert, Mute-Kachel farblich an die Alert-Familie angeglichen, und KPI-Strip auf feste Toolbar-Reservierung + kompaktere Kartenmaße umgestellt, damit keine Kachel mehr unter die rechten 5 Icons läuft. |
| 1.7.99 | 27.05.2026 | Kopf-KPIs kompakter gemacht: Alerts-Kacheln heißen jetzt nur noch Offen/Kritisch/Quittiert, eine neue Kachel für gemutete Alerts wurde ergänzt, Reports-1h zeigt jetzt als Hauptwert die Anzahl Reports mit der Unterzeile 1h, und die Kacheln wurden in der Breite so gestrafft, dass die zusätzliche Karte Platz findet. |
| 1.7.98 | 27.05.2026 | Linux-Mountpoint-Defaults gehärtet: Für Linux-Hosts bleiben initial nur `/`, `/hana`, `/hana/log`, `/hana/shared`, `/hana/shared/backup_service`, `/usr/sap` aktiv. Alle anderen Mountpoints werden pro Benutzer/Sektion automatisch ausgeblendet; Neu-Hosts erhalten diese Defaults beim Ingest, und eine einmalige Migration setzt bestehende Linux-Hosts auf denselben Startzustand. |
| 1.7.97 | 26.05.2026 | Fix für Alert-Listen-502: In `/api/v1/alerts` wurde beim Rendern von Alert-Zeilen eine bereits geschlossene SQLite-Connection verwendet; die Zeilenverarbeitung läuft jetzt innerhalb der aktiven Connection, damit Hosts mit offenen Alerts wieder stabil geladen werden. |
| 1.7.96 | 26.05.2026 | Backup-Job Stabilisierung: DB-Backup-Worker nutzt inkrementelles `sqlite backup` mit Busy-Timeout, fängt jetzt alle Exceptions ab (setzt Status sauber auf `error` statt endlos `running`), Status-Endpoint hat Running-Watchdog (15 Minuten), und UI wartet bis 10 Minuten mit klarerer Fortschritts-/Timeout-Meldung |
| 1.7.95 | 26.05.2026 | Breiter Host-Identity-Hardening-Release: `muted_alert_rules` und `filesystem_visibility` auf `host_uid` migriert (inkl. DB-Migration), Alert-/Summary-/Open-Alert-Filter auf host_uid-basierte Mute+Hidden-Logik umgestellt, Host-Update-Log host_uid-fähig gemacht, Filesystem-Visibility speichert host_uid aus der UI und Hostkarten-/Alert-Zähler bleiben bei gleichen Hostnamen sauber getrennt |
| 1.7.94 | 26.05.2026 | Host-Isolation erweitert: Analyse (`/api/v1/analysis`) und DB-Lifecycle (`/api/v1/database-lifecycle`) unterstützen jetzt `host_uid`-Filter, UI sendet `host_uid` in beiden Calls, und Hostkarten-Alertzähler werden host-key-basiert ermittelt; damit keine CPU/RAM/Mountpoint-Vermischung mehr bei gleichen Hostnamen |
| 1.7.93 | 26.05.2026 | Hotfix fuer Hosts-Seitenleiste: `/api/v1/hosts` lieferte 502 wegen fehlend initialisierter `host_uid_settings_map`; Map-Aufbau fuer `host_uid`-Settings wiederhergestellt und Hostliste rendert stabil |
| 1.7.92 | 26.05.2026 | Host-Settings vollständig `host_uid`-spezifisch gemacht (Backend-Lesen/Schreiben + Hostliste-Merge + UI-Mini-Aktionen mit `host_uid`), damit Hosts mit gleichem Hostnamen keine gemeinsamen Favorit/Hidden/Land/Kunden/Typ-Metadaten mehr überschreiben |
| 1.7.91 | 25.05.2026 | SAP Lizenz-Anzahlen in der UI jetzt ohne führende Nullen (z. B. 1 statt 001) in Lizenzinfos, Hover-Popup und Systemübersicht |
| 1.7.90 | 25.05.2026 | SAP Lizenzinfos erweitert: Linux- und Windows-Agent lesen `SYSTEM-TYPE` aus B01.txt (z. B. aus `PARAMS=SYSTEM-TYPE=Prod;...`) und UI zeigt den Wert als `Systemtyp` in den Lizenzinfos an |
| 1.7.89 | 25.05.2026 | Header push toggle refined to icon-only bell state: 🔔 when active, 🔕 when inactive/not available, with reduced glyph size to match neighboring toolbar icons |
| 1.7.88 | 25.05.2026 | Reverted SAP license hover popup to translated-only behavior: ungemappte Roh-Lizenztypen werden wieder ausgeblendet, so wie zuvor vorgesehen |
| 1.7.87 | 25.05.2026 | SAP license hover popup now falls back to raw license types when no translation is configured, so Lizenztyp and Anzahl remain visible (with robust count parsing/aggregation) |
| 1.7.86 | 25.05.2026 | Web-push alert payload now mirrors Telegram-style details (customer, host, mountpoint, severity, usage, timestamp) with explicit logo icon/badge and click target to `/mobile/alerts` |
| 1.7.85 | 25.05.2026 | Added a dedicated "Test Push" button on `/mobile/alerts` to trigger `/api/v1/push-test` directly from the app and show immediate send feedback |
| 1.7.84 | 25.05.2026 | Updated app icon references to the official logo (`/icons/logo.png`) for PWA manifest, Apple touch icon, mobile alerts page, and push notification icon/badge |
| 1.7.83 | 25.05.2026 | Mobile alerts push fix: service worker is now explicitly registered on /mobile/alerts so tapping the push button reliably triggers subscribe/unsubscribe instead of silently waiting on an unregistered worker |
| 1.7.82 | 25.05.2026 | Added dedicated mobile alerts-only page at /mobile/alerts (compact alert handling + optional push toggle) and updated pull-server-only deploy sync to include sw.js/manifest/mobile assets plus pywebpush installation |
| 1.7.81 | 25.05.2026 | Added additive PWA web-push support (server-side push subscription endpoints, service-worker push handling, optional UI toggle) without replacing existing alert/dashboard workflows |
| 1.7.80 | 25.05.2026 | Added a comic-style app explainer SVG with six story scenes and linked it in the process docs quick-access section |
| 1.7.79 | 25.05.2026 | Added a blueprint-style technical process drawing with explanatory callouts and linked it in the process docs quick-access section |
| 1.7.78 | 25.05.2026 | Process-visual documentation completed with a detailed Pixel Art SVG variant and quick-access link in the process docs index |
| 1.7.77 | 25.05.2026 | Process-visual documentation expansion: added a second detailed app-process infographic in Flat Design style (SVG) and linked it in the process docs quick-access section |
| 1.7.76 | 25.05.2026 | Documentation visuals expanded: added a detailed Corporate Memphis business illustration plus technical process flow SVGs for end-to-end app process communication, and linked them from the process docs index |
| 1.7.75 | 25.05.2026 | Report pruning scope fix: retention/count pruning now follows host identity (`host_uid`) when present, with hostname fallback for legacy payloads without host_uid, preventing cross-identity truncation on split hosts |
| 1.7.74 | 25.05.2026 | Report header typography tuning: made the top "Erste Nachricht" info block significantly smaller across all lines and emphasized current report date/time info in bold |
| 1.7.73 | 25.05.2026 | Host card micro-layout adjustment: moved the compact last-report clock from the bottom technical row to the second line, right-aligned and vertically centered |
| 1.7.72 | 25.05.2026 | Host card usability refinement: added a compact last-report time (HH:MM) in the technical metadata row between hostname and IP, with tooltip showing the full timestamp |
| 1.7.71 | 25.05.2026 | Queue flush hardening on Linux and Windows agents: malformed/empty queue payload files and permanent 4xx rejects are quarantined instead of blocking backlog replay; transient transport failures still pause the flush to preserve unsent queue files |
| 1.7.70 | 25.05.2026 | Hotfix receiver hang under load: fixed SQLite file-descriptor leak by ensuring context-managed DB connections are closed on block exit, preventing exhaustion of open files and resulting local timeouts on port 8080 |
| 1.7.50 | 24.05.2026 | DB-size KPI presentation refinement: removed the `MiB` unit from the main value line and moved the unit to the subtitle as `MB`, so the KPI value row now shows only the numeric size |
| 1.7.49 | 24.05.2026 | KPI color restore hotfix: added a final high-priority CSS override at stylesheet end so semantic KPI left accent bars (Alerts/Host status/DB metrics) can no longer be neutralized by later global chip harmonization rules |
| 1.7.48 | 24.05.2026 | KPI accent color harmonization: removed pink from KPI bars and introduced semantic color grouping with shared accents per category (Alerts = orange family, Host status = blue family, DB/Report metrics = teal/green family), including dark-mode tuned counterparts |
| 1.7.47 | 24.05.2026 | KPI card visual separation pass: enforced distinct single-card rendering for each KPI (small explicit gaps, full card borders/backgrounds) with equal-width distribution in the strip, preventing the previous “cards running into each other” appearance |
| 1.7.46 | 24.05.2026 | Sidebar cleanup: removed redundant host summary line under the Hosts title and removed the separate “Aktive Hosts (…)” section header in the host list; compacted the hosts sidebar header spacing/border to better align with KPI-driven status presentation |
| 1.7.45 | 24.05.2026 | Header layout fix: enforced vertical panel-header stacking (`flex-direction: column`) so the full host search/filter card renders as a separate block below the KPI row (instead of appearing in the same horizontal row due legacy flex rules) |
| 1.7.44 | 24.05.2026 | Login card compactness pass: increased ANG logo size by ~30% in the login mask, reduced vertical spacing between submit button/status and ANG logo, and tightened card paddings/gaps (including mobile sizing) so the overall login card height is more compact |
| 1.7.43 | 24.05.2026 | Header filter card finalization: removed the expand/collapse mechanism and related toolbar icon entirely; host search/filter card now stays fixed and always visible as a standalone block directly below the KPI strip (only hidden when not authenticated) |
| 1.7.42 | 24.05.2026 | Login logo positioning refinement: moved the floating app logo significantly further upward so it is clearly outside the login card with explicit visual spacing above the card top edge (desktop + mobile) |
| 1.7.41 | 24.05.2026 | Header filter placement adjustment: converted the host filter/search area from an overlapping overlay into a standalone in-flow block directly below the KPI strip, so expanding the block now pushes the content below downward and preserves the same one-row control layout |
| 1.7.40 | 24.05.2026 | Header filter UX correction: moved host filters/search into a dedicated collapsible overlay box directly below the KPI strip (instead of sharing the KPI row), added toolbar toggle button with active state, and enforced one-line presentation for the filter controls with horizontal scrolling fallback to prevent KPI compression and wrapping |
| 1.7.39 | 24.05.2026 | Login UI refresh: moved the app logo out of the login card into a floating top position with halo glow, reduced card footprint/spacing for a more compact form layout, and tuned mobile/dark-mode rendering for the new login composition |
| 1.7.38 | 24.05.2026 | Header usability polish: fixed Active Hosts KPI count by adding backend `online` state to `/api/v1/hosts` (with frontend fallback via `last_seen_utc`), switched KPI semantic accent from top-strip to left border with wider tile spacing, moved Host search + interest + OS/country filters into the top header bar, removed the duplicate sidebar filter block, and simplified DB Delta KPI value display to numeric-only (unit remains in subtitle) |
| 1.7.37 | 24.05.2026 | Header KPI parity update: added missing KPI tiles (kritische Alerts, quittierte offene Alerts, aktive Hosts), re-enabled DB Delta tile, and removed the unwanted left accent/border so KPI cards now keep only the top semantic accent in line with the mockup intent |
| 1.7.36 | 24.05.2026 | Header KPI strip layout refinement: removed horizontal scroll and switched to a dynamic one-row equal-width KPI layout (`grid-auto-columns: minmax(0,1fr)`) so all KPIs stay visible without wrapping/scrolling; responsive KPI typography adjusted accordingly |
| 1.7.35 | 24.05.2026 | Header variant-3 refinement: KPI strip now stays single-line (horizontal scroll instead of wrapping), partner ANG logo remains plain (no card treatment), and desktop layout hacks that shifted header/sidebar alignment were neutralized so the hosts sidebar no longer needs extra vertical compensation |
| 1.7.34 | 24.05.2026 | Header UX refresh: top status bar is now sticky while scrolling; panel header split into KPI strip + action toolbar; top-right user controls (Dark/User/Logout) redesigned from chip-heavy look to a cleaner segmented control style |
| 1.7.33 | 24.05.2026 | Receiver crash hotfix: guard `collect_host_mail_context` against missing latest report rows (including hostname fallback lookup) so `/api/v1/agent-report` no longer fails with `TypeError: 'NoneType' object is not subscriptable` during alert reminder processing |
| 1.7.32 | 24.05.2026 | Alert reminder spam fix for acknowledged/muted alerts: reminder cadence now anchors to `ack_at_utc` (next heads-up only after configured hours from acknowledgement) and muted alert pairs are skipped in reminder dispatch for both Mail and Telegram |
| 1.7.31 | 24.05.2026 | Host-detail changelog identity fix: `/api/v1/host-changelog` and frontend host detail requests now pass and honor `host_uid` (with hostname fallback), so hosts with duplicate hostnames no longer show mixed changelog entries; also includes host-scoped DB lifecycle/addon item filtering by `host_uid` |
| 1.7.30 | 24.05.2026 | System overview status fix: online/offline determination now uses a configurable threshold (`MONITORING_SYSTEM_OVERVIEW_ONLINE_THRESHOLD_MINUTES`, default 60) instead of a hard 20-minute cutoff, reducing false Offline states in host cards |
| 1.7.29 | 24.05.2026 | UI permissions hardening: both host-config changelog action buttons (`Backfill` and `Rebuild heute`) are now admin-only (button visibility) |
| 1.7.28 | 24.05.2026 | Changelog identity and baseline fix: changelog entries are now host_uid-aware (duplicate hostnames are separated correctly), and initial baseline entries are generated as Neu-only values (old='-') for host config and AddOns; backfill button now includes this baseline initialization too |
| 1.7.27 | 24.05.2026 | Server startup hotfix: fixed indentation crash in `/api/v1/alert-mute` handler and repaired DB init migration order so legacy databases add `alerts.host_uid` before creating host_uid index (prevents `sqlite3.OperationalError: no such column: host_uid`) |
| 1.7.26 | 24.05.2026 | Added global-alert diagnostics panel (hostname, host_uid, latest report IP, open-alert counts) and expanded changelog rebuild to also write initial system-parameter baseline entries (OS/kernel/CPU/RAM/SAP/HANA/SQL) so rebuilds no longer miss those values when no prior delta exists |
| 1.7.25 | 24.05.2026 | Duplicate-hostname alert/mail fix: alert lifecycle now keys by host_uid (fallback-safe) instead of hostname-only, including debounce/rebuild context and alert actions via alert_id/host_uid so equal hostnames on different IPs no longer auto-resolve each other or trigger misleading open/resolved mail pairs |
| 1.7.24 | 24.05.2026 | Changelog-Rebuild safety and progress UX: added explicit destructive warning + confirmation gate in UI, and live progress bar during running rebuild jobs (hosts processed / total hosts) |
| 1.7.23 | 24.05.2026 | User settings width harmonized: header, tab menu and settings sections now use the same centered max content width, and the settings tab strip now scrolls instead of widening the layout |
| 1.7.22 | 24.05.2026 | Global view width harmonized: header, tab menu and tab panels now share one consistent max content width, and the tab strip now scrolls safely instead of pushing the layout wider |
| 1.7.21 | 24.05.2026 | Event alert mails now include the Alert-ID from the Infoboard (visible in subject and HTML body) so each mail can be uniquely mapped to one alert event |
| 1.7.20 | 24.05.2026 | DB maintenance cards now wrap in multiple rows (3/2/1 responsive columns) instead of stretching in one long row, and each card shows the current value centered at the top in bold (CPU/RAM-style) |
| 1.7.19 | 23.05.2026 | Host card OS icon emphasis increased significantly (higher opacity, slightly larger size, and full color rendering without desaturation) |
| 1.7.18 | 23.05.2026 | Host row alignment fix: move IP+OS block to the right edge aligned with corner flag and restore hostname visibility next to the status dot |
| 1.7.17 | 23.05.2026 | Host card icon position swap: country flag moved to corner position and license emoji moved into the top row next to customer name |
| 1.7.16 | 23.05.2026 | Host card visual cleanup: show host designation as plain text (no badge), remove circular framing around country flag and license icon, and align IP+OS block further to the right |
| 1.7.15 | 23.05.2026 | Host card cleanup: remove redundant left status bar, reorder row 3 to show IP before OS icon, and shift license icon further right |
| 1.7.14 | 23.05.2026 | Host card layout reset to vertical 3-row structure (customer+flag, designation badge, hostname+OS with IP), while keeping current visual refinements and preventing early hostname truncation |
| 1.7.13 | 23.05.2026 | Host card stability polish: license info emoji no longer affects card flow (corner overlay), OS icon moved behind hostname, and technical column sizing adjusted so hostnames can be shown longer before truncation |
| 1.7.12 | 23.05.2026 | Host card typography/contrast polish: keep customer title dominant while softening technical host/IP text contrast, reducing technical font weight, and toning down inline OS icon emphasis |
| 1.7.11 | 23.05.2026 | Host card layout refresh: identity/tech grid split, designation rendered as rounded badge, inline country flag integration, and technical column with status pulse + monochrome OS icon |
| 1.7.10 | 23.05.2026 | Host card customer name typography: reduce size by 1px and increase weight to the strongest available bold style |
| 1.7.9 | 23.05.2026 | Host card note line: remove designation emoji, shift text left, and increase note-line font size by 1px |
| 1.7.8 | 23.05.2026 | Host card meta row: remove visible "Host" label, shift hostname left, align hostname/IP vertically, and render IP value in bold for clearer scanning |
| 1.7.7 | 23.05.2026 | Host card visuals: reduce corner radius for a slightly less rounded, more compact look |
| 1.7.6 | 23.05.2026 | Host card compactness: remove visible "IP" label while keeping the IP value in the same position to free horizontal space for longer host names |
| 1.7.5 | 23.05.2026 | SAP license hover popup: swap columns so Lizenztyp is first and Anzahl is second; refine second-column width/gap to keep values close but avoid clipping descriptions |
| 1.7.4 | 23.05.2026 | Final premium UI micro-polish per module: refined spacing rhythm, row density, heading cadence and compact chip/table typography in Global/Admin/System views for both Light and Dark mode |
| 1.7.3 | 23.05.2026 | View-by-view polish across Global/Admin sections: harmonized toolbars, dense tables, cards, changelog blocks and system-overview layout details for consistent readability in both Light and Dark mode |
| 1.7.2 | 23.05.2026 | Extend the new UI language to all menu sections and views (not only overview): unified panel/card surfaces, tabs, sidebars, toolbars, tables, buttons and form controls for both Light and Dark mode |
| 1.7.1 | 23.05.2026 | Mobile/UI fine-tuning for the new dashboard look: tighter responsive paddings, scaled metric headline values, wrapped chart meta rows, and single-column host metadata alignment on small screens |
| 1.7.0 | 23.05.2026 | UI design refresh toward a graphit SaaS look: stronger card hierarchy for metric panels, more whitespace and numeric typography contrast, stricter host-list metadata alignment, and calmer charts with subdued grids plus soft area gradients |
| 1.6.292 | 20.05.2026 | Clarify the HANA detail view terminology in the UI: tenant-wise `M_CS_TABLES` results are labeled as Schemas instead of Datenbanken |
| 1.6.291 | 20.05.2026 | Add HANA multitenant support (DB_XXX discovery via /usr/sap/<SID>/SYS/global/hdb/custom/config): collect tenant-specific AddOns and schema memory by tenant port, extend backend extraction, and render tenant/port grouped HANA data across SAP/AddOn and Datenbank views |
| 1.6.290 | 20.05.2026 | Add customer-level data indicator emojis in System Overview groups: 🧩 for AddOns, 📄 for Lizenzfile, and 🏷️ for translated Lizenztypen when data exists |
| 1.6.289 | 20.05.2026 | Harmonize SAP popup license-type typography so the Lizenztyp column uses the same sizing style as Anzahl |
| 1.6.288 | 20.05.2026 | Remove the top header SAP license info card entirely; license details remain available via the host-card 🪪 hover popup |
| 1.6.287 | 20.05.2026 | Align SAP popup license list as true columns (Anzahl/Lizenztyp with values vertically aligned) and set Lizenztyp text size to match Anzahl |
| 1.6.286 | 20.05.2026 | Allow customer/holder name wrapping in the SAP license hover popup so long names no longer get cut off |
| 1.6.285 | 20.05.2026 | Refine SAP license popup list layout: add compact column labels "Anzahl" and "Lizenztyp" above entries and remove redundant "Lizenztypen" heading |
| 1.6.284 | 20.05.2026 | Remove native browser tooltip ("SAP Lizenzinfos vorhanden") from the host-card 🪪 badge so only the custom hover popup is shown |
| 1.6.283 | 20.05.2026 | Restrict SAP license types in host-card hover popup to only matrix-translated entries, matching the Lizenzinfos section behavior |
| 1.6.282 | 20.05.2026 | Tune host-card SAP license hover popup readability: reduce top-section typography and increase popup width so more information is visible at once |
| 1.6.281 | 20.05.2026 | Add hover popup on the host-card SAP license emoji (🪪) with SAP core license details, translated license types with counts, and copy-to-clipboard action; keep header info strip unchanged |
| 1.6.280 | 20.05.2026 | Simplify the Kundeninfos tab to edit only the customer name of the selected host's linked customer via the existing customer PATCH route |
| 1.6.279 | 20.05.2026 | Rebind customer info rendering to the selected host in the overview tab, rename the menu item to Kundeninfos, and remove the broken global customer menu entry |
| 1.6.278 | 20.05.2026 | Keep the three header summary chips permanently visible so alert, trend, and inactive-host counts no longer disappear at zero or during refresh timing gaps |
| 1.6.277 | 20.05.2026 | Make the new customer-changes tab visible for normal users and admins, add a dedicated global entry, and keep the panel accessible with a clear empty state when no host is selected |
| 1.6.276 | 20.05.2026 | Hotfix server startup failure: remove accidental Flask route injection in `receiver.py`, restore `main()` entrypoint, and move `user_type` migration into proper `web_users` migration block |
| 1.6.275 | 20.05.2026 | Fully implemented read-only user type and added customer management menu |
| 1.6.274 | 20.05.2026 | Add customer management UI (edit/delete customers); prepare read-only user type with restricted permissions |
| 1.6.273 | 20.05.2026 | System-Overview table: add third-column (CPU) dropdown for translated SAP B1 license types with counts (from `sap_license.focus_license_types`) |
| 1.6.272 | 20.05.2026 | Host overview cards: fix 🪪 badge alignment to stay consistently at far right in line 2 |
| 1.6.271 | 20.05.2026 | Host overview cards: show 🪪 on the right side of line 2 when SAP license info is present in latest payload |
| 1.6.270 | 20.05.2026 | Add copy-to-clipboard button to SAP B1 license types display (reuses sap-vmap-copy-btn pattern) |
| 1.6.269 | 20.05.2026 | SAP B1 license type display: count first (3-digit zero-padded), name on same line; increase spacing after header; horizontal flex layout |
| 1.6.268 | 20.05.2026 | Fix SAP license type matching: exact match instead of substring includes(); admin UI column header updated; only show types with non-empty translation |
| 1.6.267 | 20.05.2026 | Auto-discover ALL SAP license types from B01.txt (remove hardcoded LTD/PROFESSIONAL filter); server auto-syncs matrix when new types appear; UI shows only translated types (admin must provide mapping in license type matrix) |
| 1.6.266 | 20.05.2026 | Fix live SAP B1 Lizenzinfos runtime regression (`asNum is not defined`) by using safe numeric conversion for `focus_license_types` counts; SAP B1 section is clickable/rendering again |
| 1.6.265 | 20.05.2026 | Add admin-editable SAP license type translation matrix (match pattern -> display name) with persisted server API (`/api/v1/sap-license-type-map`) and apply it in live SAP B1 Lizenzinfos rendering for extracted `focus_license_types` (LTD/PROFESSIONAL) |
| 1.6.264 | 20.05.2026 | Move SAP B1 LTD/Professional license rendering to the live UI (Einzelmeldungen -> SAP B1 -> Lizenzinfos) and remove ui-next runtime artifacts/routes/deploy entries (`/ui-next`, `ui-next.css`, `ui-next.js`) |
| 1.6.263 | 20.05.2026 | Extend SAP B1 Lizenzinfos on Linux and Windows agents with aggregated LTD/PROFESSIONAL license types (`focus_license_types`: type + count) and render them in Einzelmeldungen with UI translation mapping (Limited CRM, Logistics CRM, Professional, Limited Finance) |
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
| 1.4.126 | 22.05.2026 | Add "Alle aufklappen" / "Alle zuklappen" controls for single-report SAP HANA DB and AddOns hierarchies |
| 1.4.125 | 22.05.2026 | Format all mail timestamps in configured timezone (Europe/Zurich, CEST/CET) instead of server-local UTC |
| 1.4.124 | 22.05.2026 | Remove SAP logo from header and from all outgoing mail templates |
| 1.4.123 | 22.05.2026 | Add hourly DB report count and DB size delta header tiles |
| 1.4.122 | 22.05.2026 | Add header tiles for DB report count and DB size |
| 1.4.121 | 22.05.2026 | Hide host UID labels in host views and expose system overview license types to all users |
| 1.4.120 | 22.05.2026 | Make SAP B1 and HANA database sections scrollable and collapsed by default |
| 1.4.119 | 22.05.2026 | Make SAP HANA databases section scrollable |
| 1.4.118 | 12.05.2026 | Persist backup mail settings in user profile API (no reset after save) |
| 1.4.117 | 12.05.2026 | Add explicit helper note below centralized mail settings save button |
| 1.4.116 | 12.05.2026 | Consolidate mail settings save action to one button at end of digest section |
| 1.4.115 | 12.05.2026 | Normalize German UI/user texts to umlauts (Swiss ss retained) |
| 1.4.114 | 12.05.2026 | Fix host notification save by persisting customer alert fields in host settings API |
| 1.4.113 | 12.05.2026 | Fix Windows self_update empty-string config binding for GITHUB_REPO reset |
| 1.4.112 | 12.05.2026 | Fix Windows self_update parser error and add X_API_KEY fallback in Windows agents |
| 1.4.111 | 12.05.2026 | Add comprehensive technical documentation for Linux and Windows agents |
| 1.4.114 | 22.05.2026 | Remove critical trends header chip |
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
### v1.7.139 (30. Mai 2026)

- **Header-KPI kompakter**: Kartenhoehe/-breite und Typografie der Infobar wurden wieder deutlich reduziert.
- **Hintergruende je KPI wieder sichtbar**: Die Farbtoenungen pro KPI-Gruppe sind klarer ausgepraegt und naeher am referenzierten Screenshot.
- **Reports-Label korrigiert**: `Reports in DB` zeigt jetzt `REPORTS` mit Unterzeile `Anzahl`; `Anz. Reports` zeigt `REPORTS` mit Unterzeile `1h`.
- **KPI-Icons ergaenzt**: In allen KPI-Labels wurden passende Symbol-/Outline-Icons vorangestellt.

### v1.7.138 (30. Mai 2026)

- **Header-Infobar visuell angepasst**: KPI-Chips im Header wurden farblich und typografisch auf das neue Kartenbild abgestimmt (kompaktere Karten, weichere Verlaeufe, klarere Farbfamilien pro Kennzahlgruppe).
- **KPI-Lesbarkeit verbessert**: Label/Count/Scope in den Chips sind jetzt klarer ausbalanciert und entsprechen dem angefragten Screenshot-Stil.

### v1.7.137 (30. Mai 2026)

- **Globales Changelog stabilisiert**: Der Collector laedt jetzt wieder die Host-Metadaten korrekt, damit die globale Changelog-Suche nicht mehr mit HTTP 502 abbricht.
- **Rebuild-Status entstoert**: Abgeschlossene Rebuild-Jobs werden nach einer Frist nicht mehr als aktive Statusmeldung angezeigt.

### v1.7.136 (30. Mai 2026)

- **Changelog Label bereinigt**: Der Praefix `SAP Lizenztyp:` wurde in der Feldspalte entfernt.
- **Anzeige vereinfacht**: Bei Lizenztypen steht jetzt nur noch der eigentliche Name inkl. Rohcode in Klammern (z. B. `Professional License (PROFESSIONAL_HDB)`).

### v1.7.135 (30. Mai 2026)

- **Linke Sidebar verschlankt**: Host-Kartenleiste ist nun etwas schmaler, damit der Inhaltsbereich rechts mehr nutzbare Breite erhaelt.
- **Host-Karten Typografie reduziert (Kunde ausgenommen)**: Schriftgroessen und Innenabstaende in den Host-Karten wurden leicht verkleinert; die Kundenzeile bleibt unveraendert prominent.
- **Changelog lesbarer in der Breite**: Die Schriftgroesse im Host-Changelog (Uebersicht) wurde minimal reduziert, damit mehr Inhalt nebeneinander sichtbar bleibt.
- **AddOn-Label vereinfacht**: Bei AddOn-Eintraegen steht jetzt nur noch `LW` bzw. `Legacy` (ohne `HANA`/`SQL` Prefix).

### v1.7.134 (30. Mai 2026)

- **Host-Changelog Layout repariert**: Die Tabelle im Bereich Uebersicht -> Changelog wurde wieder auf stabile Spaltenbreiten und lesbare Typografie gestellt, damit Feldnamen nicht mehr buchstabenweise umbrechen.
- **Delta fuer RAM und CPU Cores erweitert**: Bei den Feldkeys `ram_gb` und `cpu_cores` zeigt der neue Wert jetzt zusaetzlich die Aenderung im Format `(+/-xx)` an.
- **Lizenz-Delta verifiziert**: Die bestehende Delta-Anzeige fuer SAP-Lizenztypen (`sap_license_type::...`) bleibt aktiv und unveraendert bestehen.

### v1.7.125 (29. Mai 2026)

- **UI-Abnahme dokumentiert**: Neue Prozessdoku `ui-regression-checklist` (HTML + MD) mit 10-Punkte-Quick-Check fuer visuelle Releases ergaenzt und im Prozessindex verlinkt.
- **Session-Refresh 404 behoben**: Backend unterstuetzt jetzt auch `POST /api/v1/session/refresh` (wie vom Frontend verwendet), dadurch entfaellt der bisherige 404-Warnpfad.
- **Fix verifiziert**: Endpoint liefert nach Login einen gueltigen 200-Refresh-Response statt 404.

### v1.7.124 (29. Mai 2026)

- **Weitere Design-Punkte umgesetzt (ohne Funktionsaenderung)**: Zusaeztliche visuelle Verfeinerungen fuer Filterbar, Icon-Konsistenz und semantische Status-Hervorhebung vorgenommen.
- **Icon- und Filter-Politur**: Bestehende OS/Flag/Emoji-Elemente harmonisiert (Groesse, Radius, Kontur), ohne das zugrundeliegende Icon- oder Rendering-System zu ersetzen.
- **Chart-Erfassbarkeit verbessert**: Filesystem- und Trendkarten inkl. Progress-Bars fuer schnellere Erkennbarkeit visuell gestaerkt (Groesse, Kontrast, Lesefluss).

### v1.7.123 (29. Mai 2026)

- **Phase 1 UI Clean-Up umgesetzt (risikoarm)**: Rein visuelle Optimierungen in styles.css fuer mehr Whitespace, klarere Hierarchie und ruhigere Kartenoptik umgesetzt.
- **KPI- und Tab-Darstellung verfeinert**: Alarm-bezogene Kennzahlen deutlicher priorisiert und Underline-Tab-Styling konsistent harmonisiert.
- **Sidebar- und Filesystem-Karten beruhigt**: Hostkarten und Chartkarten mit konsistenteren Abstaenden, Radien, Schatten und besseren Kontrasten in Light/Dark angepasst.

### v1.7.122 (29. Mai 2026)

- **Kundeninfos fuer Duplicate-Hostnamen korrigiert**: Der Kundeninfos-Block laedt Host-Einstellungen jetzt mit host_uid und nicht nur ueber hostname.
- **Falsches Mapping bei 4 betroffenen Karten behoben**: Hosts mit gleichem Namen greifen wieder auf den richtigen host_uid-Datensatz zu.
- **Kundenname wieder sichtbar/speicherbar**: Zugeordnete Kunden werden in Kundeninfos wieder korrekt angezeigt und koennen wie erwartet bearbeitet werden.

### v1.7.80 (25. Mai 2026)

- **Comic-Erklaergrafik erstellt**: Neue SVG im Comic-Stil erklaert die App als sechsteilige Story von Agent-Erfassung bis Dashboard.
- **Narrative Prozessdarstellung ergaenzt**: Sprechblasen, Szenen und Zusammenfassungsbereich machen den Ablauf fuer nicht-technische Zielgruppen greifbarer.
- **Doku-Einstieg erweitert**: Die Comic-Variante ist als eigener Schnellzugriff in der Prozess-Startseite verlinkt.

### v1.7.79 (25. Mai 2026)

- **Blueprint-Variante erstellt**: Neue technische Prozesszeichnung im Blueprint-Stil als SVG hinzugefuegt.
- **Mit Erklaer-Callouts erweitert**: Die Grafik enthaelt technische Erklaerboxen zu 202-Admission, Queue-Telemetrie, host_uid-Pruning und Mail/OAuth-Verhalten.
- **Doku-Schnellzugriff aktualisiert**: Die Blueprint-Grafik ist auf der Prozess-Startseite als eigener Einstiegslink verankert.

### v1.7.78 (25. Mai 2026)

- **Pixel-Art Prozess-Infografik hinzugefuegt**: Eine weitere detaillierte SVG-Variante im Stil `Pixel Art` wurde erstellt.
- **Prozess-Index erweitert**: Die neue Pixel-Art Grafik ist als eigener Schnellzugriff in der Prozess-Startseite verlinkt.
- **Stilportfolio komplettiert**: Technische, Corporate-Memphis, Flat-Design und Pixel-Art Varianten stehen jetzt parallel zur Verfuegung.

### v1.7.77 (25. Mai 2026)

- **Neue Flat-Design Prozess-Infografik**: Eine zweite detaillierte SVG-Visualisierung der App-Prozesse wurde im Stil `Infografik-Elemente / Flat Design` erstellt.
- **Quick-Access Doku erweitert**: Die neue Grafik ist direkt in der Prozess-Startseite als eigener Einstiegslink verankert.
- **Visual-Set vervollstaendigt**: Corporate-Memphis und Flat-Design Varianten stehen jetzt parallel fuer unterschiedliche Praesentationskontexte bereit.

### v1.7.76 (25. Mai 2026)

- **Neue Corporate-Memphis Business-Illustration**: Detaillierte SVG-Grafik fuer die App-Prozesse von Agent-Erfassung bis Betrieb erstellt.
- **Prozess-Grafiken in Doku indexiert**: Die neuen SVGs wurden im Prozess-Index als schnelle Einstiegsdokumente verlinkt.
- **Visuelle Prozesskommunikation ausgebaut**: Neben textuellen Ablaufdokus steht nun eine grafische Gesamtuebersicht fuer fachliche und technische Abstimmung bereit.

### v1.7.75 (25. Mai 2026)

- **Pruning auf Host-Identitaet umgestellt**: Retention- und Count-Pruning laufen jetzt `host_uid`-basiert, sobald eine UID vorhanden ist.
- **Legacy-Fallback bleibt erhalten**: Wenn keine `host_uid` vorliegt, greift weiterhin der Hostname-basierte Fallback.
- **Split-Host Risiko reduziert**: Bei mehreren Identitaeten unter gleichem Hostname werden Reports nicht mehr uebergreifend gekuerzt.

### v1.7.74 (25. Mai 2026)

- **Obere Infozeilen stark verkleinert**: Der Bereich `Erste Nachricht` ist in allen Zeilen deutlich kleiner gesetzt (kompaktere Label- und Werteanzeige).
- **Aktuelle Report-Infos fett hervorgehoben**: Datum/Uhrzeit des aktuell angezeigten Reports im Header wurden typografisch deutlicher (fett) gestaltet.
- **Kontrast im Header verbessert**: Die hervorgehobene Zeitinfo wurde farblich so angepasst, dass sie in Hell- und Dunkelmodus klar lesbar bleibt.

### v1.7.73 (25. Mai 2026)

- **Uhrzeit in zweite Zeile verschoben**: Die kompakte letzte Report-Uhrzeit ist von der unteren Technikzeile in die zweite Zeile der Hostkarte gewandert.
- **Rechtsbuendig + vertikal zentriert**: Die Uhrzeit wird nun am rechten Rand der zweiten Zeile sauber ausgerichtet und vertikal zentriert angezeigt.
- **Untere Zeile wieder aufgeraeumt**: Die letzte Technikzeile zeigt wieder nur Host/IP/OS-Informationen ohne zusaetzliche Uhrzeit.

### v1.7.72 (25. Mai 2026)

- **Letzte Report-Uhrzeit auf Hostkarte ergänzt**: Auf der Hostkarte wird eine kleine Uhrzeit (`HH:MM`) der letzten Report-Anlieferung angezeigt.
- **Dezente kompakte Darstellung**: Die Zeit ist als kleine, unaufdringliche Zusatzinformation mit Tooltip auf den Vollzeitstempel integriert.
- **Fallback + Tooltip**: Bei fehlendem/ungueltigem Zeitstempel wird `--:--` angezeigt; der Tooltip zeigt weiterhin den vollständigen Zeitstempel.

### v1.7.71 (25. Mai 2026)

- **Queue-Flush robuster gemacht (Linux/Windows)**: Einzelne fehlerhafte oder leere Queue-Dateien blockieren den Backlog nicht mehr, sondern werden in ein Quarantäne-Verzeichnis verschoben.
- **4xx-Dauerfehler isoliert statt Stau**: Wenn der Server ein Queue-Payload dauerhaft mit 4xx ablehnt, wird nur diese Datei quarantänisiert und der Rest der Queue weiter abgearbeitet.
- **Transportfehler-Verhalten beibehalten**: Bei Netzwerk-/Timeout-Problemen stoppt der Flush weiterhin, damit nicht gesendete Queue-Dateien im regulären Queue-Verzeichnis für den nächsten Lauf erhalten bleiben.

### v1.7.69 (24. Mai 2026)

- **Header-KPIs zurückgestellt**: `Server CPU` und `Server Memory` wurden wieder durch die früheren Karten `Reports letzte 1h` und `DB Delta 1h` ersetzt.
- **KPI-Datenpfad rückgebaut**: `/api/v1/dashboard-db-kpis` liefert wieder stündliche Report-Anzahl sowie DB-Größenänderung gegenüber vor 1 Stunde.

### v1.7.68 (24. Mai 2026)

- **Hostkarten-Icons horizontal ausgerichtet**: Lizenz-Info und Länder-Icon werden jetzt in einer gemeinsamen Corner-Zeile gerendert und sind sauber auf einer Linie.
- **Kundentext nicht mehr unten abgeschnitten**: Zeilenhöhen und vertikale Innenabstände für Kundenname und Untertitel wurden angepasst, damit Buchstaben-Unterlängen sichtbar bleiben.

### v1.7.67 (24. Mai 2026)

- **Lizenzindikator auf Hostkarte wiederhergestellt**: Hosts mit gültigen SAP-Lizenzinfos zeigen den Indikator wieder als Corner-Badge auf der Karte.
- **Popup per Klick geöffnet**: Ein Klick auf den Badge öffnet bzw. schließt die SAP-Lizenzinfo-Ansicht direkt auf der Hostkarte.
- **Info-Emoji statt Ausweis-Emoji**: Der Badge und die Popup-Überschrift verwenden jetzt ein Informationssymbol (`ℹ️`).

### v1.7.66 (24. Mai 2026)

- **Server-Memory Unterzeile ergänzt**: Der `Server Memory` KPI zeigt jetzt in der Unterzeile die gesamte verfügbare RAM-Menge des Server-Hosts.
- **Anzeige auf feste GB-Darstellung umgestellt**: Die Unterzeile wird einheitlich als `Gesamt X.X GB` ausgegeben.

### v1.7.65 (24. Mai 2026)

- **KPI-Reihenfolge im Header angepasst**: `Server CPU` steht jetzt an der zweitletzten Position, direkt vor `Server Memory`.
- **Unterzeile `%` bei CPU/Memory entfernt**: Die beiden Server-Auslastungs-Chips zeigen den Prozentwert jetzt ohne separate Prozent-Unterzeile.
- **Farben fuer die letzten zwei KPIs aktualisiert**: `Server CPU` und `Server Memory` verwenden nun eine neue, nicht-pinke Farbpalette.

### v1.7.64 (24. Mai 2026)

- **Header-KPIs umgestellt auf lokale Serverauslastung**: Statt `Anzahl Reports (letzte 1h)` und `DB Delta 1h` zeigt die Leiste jetzt `Server CPU` und `Server Memory` in Prozent.
- **CPU/Memory direkt vom lokalen Server-Host**: Die Werte werden auf dem Monitoring-Server selbst erhoben (`/proc/stat`, `/proc/meminfo`) und als kompakte Prozentwerte ausgeliefert.

### v1.7.63 (24. Mai 2026)

- **Kunde im Ingest-Lieferlog ergänzt**: Die Admin-Tabelle zeigt jetzt pro Queue-Eintrag zusätzlich den zugeordneten Kunden.
- **Host-UID wird bei Kundenzuordnung priorisiert**: Die Auflösung erfolgt zuerst über die letzte bekannte Host-UID-Zuordnung und fällt nur bei Bedarf auf Hostname zurück.

### v1.7.62 (24. Mai 2026)

- **Ingest-Lieferlog fuer Admin eingebaut**: Neue Uebersicht zeigt pro Eintrag Host, Empfangszeit, Payload-Groesse und finalen DB-Schreibzeitpunkt inkl. Ende-zu-Ende-Latenz.
- **Rollierend auf die letzten 250 Eintraege begrenzt**: Das Audit-Log bleibt kompakt und ueberschreibt alte Eintraege automatisch.
- **Payload-Referenz auf Disk statt in DB**: Optional werden Original-Payloads als JSON-Dateien unter `server/data/agent_ingest_payload_audit/` abgelegt und in der Ansicht per "anzeigen" verlinkt.
- **Ansicht standardmaessig eingeklappt**: Das Ingest-Lieferlog startet zugeklappt und kann bei Bedarf geoeffnet werden.

### v1.7.61 (24. Mai 2026)

- **Admin-API fuer Ingest-Queue Uebersicht**: Neuer Endpoint `/api/v1/admin/agent-ingest-queue` liefert Queue-Tiefe, Ready/Retry/In-Flight/Delayed, Alterswerte und letzte Fehler als kompakte Betriebskennzahlen.
- **Neue Admin-Panelansicht fuer Queue-Betrieb**: In den globalen Admin-Operations zeigt die UI jetzt Queue-Kennzahlen als Karten inkl. Statuszeile und Refresh-Button.
- **Queue-Fehler direkt sichtbar**: Eine Tabelle listet die letzten Queue-Fehler mit Queue-ID, Host, Versuchszahl, Zeitstempeln und Fehlermeldung fuer schnelle Ursachenanalyse.

### v1.7.60 (24. Mai 2026)

- **Agent-Report Ingest auf Queue umgestellt**: `/api/v1/agent-report` speichert eingehende Reports jetzt zuerst durable in `agent_ingest_queue` und antwortet sofort mit `queued`.
- **Serielle Worker-Verarbeitung fuer Lastspitzen**: Ein dedizierter Background-Worker verarbeitet Queue-Eintraege nacheinander und schreibt erst dann in `reports`, Alerts und Changelog.
- **Retry-Backoff bei Verarbeitungsfehlern**: Fehlgeschlagene Queue-Eintraege bleiben erhalten und werden mit exponentiellem Backoff erneut versucht, statt im Burst verloren zu gehen.

### v1.7.59 (24. Mai 2026)

- **SAP Services/Ports jetzt als echte Diff-Ansicht**: Pro Service wird im Changelog markiert, ob der Eintrag neu (`+`), entfernt (`-`) oder geaendert (`~`) ist.
- **Port-Aenderungen direkt sichtbar**: Bei geaenderten Services wird in Alt/Neu jeweils der Gegenwert eingeblendet (`vorher`/`neu`), damit Port-Swaps sofort lesbar sind.
- **Host + Global vereinheitlicht**: Die Diff-Darstellung gilt identisch im Host-Detail-Changelog und im globalen Host-Config-Changelog, fuer Windows und Linux.

### v1.7.58 (24. Mai 2026)

- **SAP Services/Ports im Changelog lesbar gemacht**: Die Felder werden jetzt pro Service als einzelne Eintraege dargestellt statt als lange Semikolon-Zeile.
- **Gilt fuer beide Changelog-Ansichten**: Sowohl im Host-Detail-Changelog als auch im globalen Host-Config-Changelog ist die Darstellung jetzt identisch strukturiert.
- **Port-Hervorhebung fuer neue Werte**: In der Spalte `Neu` sind die Portangaben je Service visuell staerker markiert, damit Aenderungen schneller auffallen.

### v1.7.57 (24. Mai 2026)

- **Deployment-Freischaltung fuer Windows Probe-Script**: `pull-server-only.sh` und `pull-server.sh` laden jetzt auch `client/windows/probe_sap_services.ps1` herunter.
- **Updates-Mirror erweitert**: Das Probe-Script wird zusaetzlich nach `updates/client/windows/` gespiegelt, damit es serverseitig direkt verfuegbar bleibt.

### v1.7.56 (24. Mai 2026)

- **Windows: SAP Services jetzt im Payload integriert**: Der Windows-Agent liefert unter `sap_business_one.installed_services` jetzt installierte SAP-B1-Dienste mit `name`, `status`, `prot`, `live`, `ports`, `description`.
- **Windows: robuste Port-Ermittlung mit Fallback-Hints**: Ports werden primaer pro Prozess aus Listening-Sockets gelesen; fuer Service-Layer/Authentication greifen zusaetzlich Muster-Hints (z. B. `b1s50001` -> `50001`, Auth -> `40020`).
- **Windows: Nicht-SAP-Noise wird gefiltert**: Bekannte Fremddienste (z. B. `PPSOne_*`, `PrintWorkflow*`, `AppXSvc`) werden konsequent ausgeschlossen.
- **UI: Installierte Services auch auf Windows sichtbar**: Die Services-Sektion wird nicht mehr nur fuer Linux gerendert; Status `running` wird wie `active` gruen markiert.
- **Support-Tool aktualisiert**: `client/windows/probe_sap_services.ps1` bleibt als Diagnose-/Testskript im Repo fuer Host-seitige Validierungen.

### v1.7.55 (24. Mai 2026)

- **SAP Service-Subinfo visuell verfeinert**: Der Dienstname in der zweiten Zeile unter `Beschreibung` ist nun dezent grau und kursiv dargestellt.
- **Kleines Subinfo-Icon ergaenzt**: Vor dem Dienstnamen wird ein kompaktes Icon-Badge angezeigt, damit die zweite Zeile schneller als Zusatzinformation erkannt wird.

### v1.7.54 (24. Mai 2026)

- **SAP Services Tabelle kompakter gemacht**: Der `Dienstname` steht nun als zweite, kleinere Zeile direkt unter `Beschreibung`.
- **Eigene Dienstname-Spalte entfernt**: Die separate Spalte `Dienstname` wurde entfernt, damit `Port(s)`, `Status` und `Live` mehr horizontalen Platz erhalten.
- **Lesbarkeit optimiert**: Subzeile fuer den Dienstnamen ist visuell zurueckgenommen, aber weiterhin vollstaendig sichtbar.

### v1.7.53 (24. Mai 2026)

- **SAP Service-/Port-Aenderungen jetzt im Host-Changelog**: Das Host-Config-Tracking schreibt nun ein zusaetzliches Feld `SAP Services/Ports`, damit Servicebezeichnungen inkl. Portbelegung als Change mit Alt/Neu-Wert sichtbar sind.
- **Port-Change-Pruefung normalisiert**: Ports werden robust geparst (numerisch, dedupliziert, sortiert), damit echte Port-Aenderungen sauber erkannt werden und Reihenfolge-/Format-Rauschen keine falschen Changes erzeugt.
- **Schema-Migration automatisch**: Bestehende Installationen erweitern `host_config_snapshot` automatisch um das neue Tracking-Feld.

### v1.7.52 (24. Mai 2026)

- **Linux-Agent sammelt installierte SAP Services robust**: Neue Erkennung fuer Dienste mit Prefix `sapb1servertools`; Collector liefert pro Service `name`, `status`, `prot`, `live`, `ports`, `description` und bleibt fehlertolerant ohne Script-Abbruch.
- **Klare Fallback-Antwort ohne Dienste**: Wenn keine passenden Dienste gefunden werden, wird im Payload unter `sap_business_one.installed_services` konsistent `reason: "Keine SAPServices gefunden"` geliefert.
- **SAP B1 UI um Services-Tabelle erweitert**: Neue Sektion `Installierte Services` mit Spalten `Beschreibung`, `Dienstname`, `Port(s)`, `Status`, `Live`.
- **Status-/Port-Hervorhebung in der UI**: `active`-Status wird gruen, inaktive Stati rot dargestellt; Ports beginnend mit `4` werden visuell fett hervorgehoben.

### v1.7.51 (24. Mai 2026)

- **sFTP Upload-Timeout fuer grosse Backups gehaertet**: Der Backup-Upload verwendet nicht mehr ein fixes 30s-Timeout, sondern ein dateigroessenbasiertes Timeout mit sinnvollen Min/Max-Grenzen.
- **sFTP Test bleibt kurz und schnell**: Fuer den Test-Button bleibt ein separates, kurzes Timeout aktiv, damit Verbindungsprobleme weiterhin sofort sichtbar sind.
- **Timeouts per Env konfigurierbar**: Neue Parameter fuer Test-Timeout, Upload-Min/Max-Timeout und angenommene Upload-Rate erlauben Tuning pro Standort.

### v1.6.323 (22. Mai 2026)

- **UI-Integration fuer sofortigen Changelog-Rebuild**: In der Changelog-Ansicht gibt es jetzt den Button `♻ Rebuild heute`, der direkt den Rebuild-Job (`days=1`, `run_now=true`, `force_rebuild=true`) startet.
- **Job-Status in der UI sichtbar**: Neuer `📋 Jobs`-Button und Statuszeile zeigen den letzten Rebuild-Job-Status (geplant/laufend/abgeschlossen/fehlgeschlagen) direkt in der Toolbar.
- **Bestehender Backfill bleibt erhalten**: Der bisherige `📥 Backfill`-Flow bleibt unveraendert nutzbar fuer inkrementelles Nachfuellen.

### v1.6.322 (22. Mai 2026)

- **Globales Changelog-Rebuild als Job planbar**: Neue Admin-API `POST /api/v1/admin/changelog-rebuild/schedule` plant einen Bereinigungs-/Rebuild-Job fuer Host-Config- und DB-Lifecycle-Changelog.
- **Stichtag-heute Workflow vorbereitet**: Standard fuer den Rebuild-Job ist `days=1` (heutiger Stichtag); optional kann `run_now=true` fuer sofortige Ausfuehrung gesetzt werden.
- **Job-Status einsehbar**: Neue Admin-API `GET /api/v1/admin/changelog-rebuild/jobs` liefert geplante/laufende/abgeschlossene Rebuild-Jobs inklusive Ergebnis/Fehler.
- **Forcierter Neuaufbau moeglich**: Rebuild-Jobs unterstuetzen `force_rebuild`, damit bestehender Rebuild-State den erneuten Neuaufbau nicht blockiert.

### v1.6.321 (22. Mai 2026)

- **Systemansicht gegen Host-Merge gehaertet**: `/api/v1/system-overview` aggregiert jetzt ueber den kanonischen Host-Key (`host_uid`/Legacy-Key) statt nur ueber `hostname`, damit gleichnamige Hosts separat erscheinen.
- **Inaktive Hosts host_uid-spezifisch**: Die Inaktiv-Liste basiert jetzt ebenfalls auf dem kanonischen Host-Key und zeigt zusaetzlich die Host-ID zur eindeutigen Zuordnung.
- **Backup-/Customer-Overview auf Host-Key umgestellt**: Beide Uebersichten nutzen jetzt die neuesten Reports pro Host-Key; host_uid-spezifische Displaynamen werden bevorzugt.
- **Alerts im Host-Kontext host_uid-filterbar**: `alerts` und `alerts-summary` akzeptieren jetzt `host_uid`; die UI verwendet bei ausgewaehltem Host bevorzugt diesen Filter statt nur `hostname`.

### v1.6.320 (22. Mai 2026)

- **Doppelte Karten: Loeschen jetzt host_uid-spezifisch**: Der Kontextmenue-Delete sendet jetzt `host_uid` mit, damit exakt die ausgewaehlte Karte geloescht wird.
- **Kein Mit-Loeschen gleichnamiger Karten mehr**: Im Backend loescht `/api/v1/host-delete` bei gesetzter `host_uid` nur die zugehoerigen Reports/UID-Settings; hostname-basierte Sammel-Loeschungen erfolgen nur noch, wenn fuer den Hostnamen keine Reports mehr uebrig sind.

### v1.6.319 (22. Mai 2026)

- **502 nach Login behoben (Regression aus 1.6.316)**: Im API-Pfad `/api/v1/hosts` wurde das Mapping fuer `host_uid`-Displaynamen in bestimmten Faellen verwendet, ohne vorher aufgebaut zu sein.
- **Runtime-Crash entfernt**: Das `host_uid_display_name_map` wird jetzt im `/api/v1/hosts`-Handler immer initialisiert und mit den vorhandenen `host_uid_settings` geladen.

### v1.6.318 (22. Mai 2026)

- **Lifecycle-Anzeige fuer Datenbank/HANA-Schema vereinheitlicht**: Instanz-/Schema-Namen verwenden jetzt ` - ` als Trenner statt `::`.
- **HANA-T-Praefix in Anzeige entfernt**: In der Lifecycle-Darstellung wird ein fuehrendes `HANA-T` aus dem Instanzteil ausgeblendet (z. B. `NDB - CRS_PRODUKTIV`).

### v1.6.356 (23. Mai 2026)

- **Agent-Quelle zeigt jetzt den Kundennamen in der Zeile**: Im Tab `Agent Quelle` steht unter dem Host jetzt der zugehoerige Kunde, damit die Migrationsliste schneller lesbar ist.

### v1.6.355 (23. Mai 2026)

- **Canonical-URL auf `infoboard.ang-schweiz.ch` umgestellt**: Linux-/Windows-Agenten, Bootstrap und Agent-Quelle-Sollwert zeigen jetzt auf die neue Ziel-Domain.
- **Sicheres Rewrite im Self-Update**: `SERVER_URL` wird nur dann auf die neue Canonical-URL geschrieben, wenn ein Reachability-Probe vom Host erfolgreich ist.
- **Fallback ohne Host-Verlust gehaertet**: Update-Quellen priorisieren jetzt `infoboard.ang-schweiz.ch`, behalten aber `infoboard.an-group.work` und `monitoring.rolfwalker.ch` als automatische Fallback-Stufen.

### v1.6.354 (23. Mai 2026)

- **Inaktive Hosts jetzt strikt One-Shot pro Inaktiv-Phase**: Benachrichtigungen (Mail/Telegram) werden nur einmal gesendet, solange ein Host inaktiv bleibt.
- **Automatischer Reset bei Wiederaktivierung**: Sobald ein Host wieder innerhalb der Inaktiv-Schwelle reportet, werden die Inaktiv-Notification-Marker zurueckgesetzt.
- **Minutentakt-Spam verhindert**: Die Versandentscheidung haengt nicht mehr an laufenden Zeitstempel-Vergleichen pro Poll, sondern an einem robusten Phase-Status.

### v1.6.353 (23. Mai 2026)

- **Inaktive-Hosts Mail-Spam behoben**: Die Inaktiv-Erkennung konsolidiert Hosts jetzt zuerst auf den neuesten Report pro `hostname`.
- **Deduplizierung stabilisiert**: Historische Mehrfach-Identitaeten (z. B. nach `host_uid`-Migration) loesen dadurch keine wiederholten Inaktiv-Mails im Minutentakt mehr aus.
- **Erwartetes Verhalten wiederhergestellt**: Pro Inaktiv-Phase wird pro Host nur einmal benachrichtigt, bis ein neuer Report eintrifft.

### v1.6.352 (23. Mai 2026)

- **Dark-Mode Menuezeilen deutlich lesbarer**: Aufklappbare Zeilen in SAP/HANA-Bereichen (z. B. Tenant-/Discovery-Summaries) nutzen jetzt kontrastreiche Schriftfarben.
- **Chevron/Marker ebenfalls angepasst**: Pfeilindikatoren in diesen Menuezeilen wurden auf besser sichtbare Dark-Mode-Farben umgestellt.
- **Ueber alle Menuepunkte konsistent**: Die Anpassung greift fuer die gemeinsamen Summary-Komponenten in den betroffenen Ansichten.

### v1.6.351 (23. Mai 2026)

- **Dark-Mode Header-Titel wieder sichtbar**: Der App-Titel `System Infoboard` hat im Dark-Mode jetzt eine explizit kontrastreiche Farbe.
- **Agent-Quelle URLs wieder lesbar**: URL-Zellen im Tab `Agent Quelle` erhalten im Dark-Mode eine kontraststarke Text-/Hintergrundkombination statt blassem Gruen-auf-Hell.
- **Fallback-Ausnahmen erweitert**: Die globale Dark-Mode-Text-Fallback-Regel schliesst Agent-Quelle-Zellen jetzt gezielt aus, damit deren eigene Kontrastfarben greifen.

### v1.6.350 (23. Mai 2026)

- **Dark-Mode Lesbarkeit appweit gehaertet**: Eine globale Fallback-Schicht sorgt dafuer, dass bisher lichtmodus-fixierte dunkle Schrift im Dark-Mode kontrastreich dargestellt wird.
- **Statusfarben bleiben erhalten**: Semantische Badges (z. B. Alert-/Status-Chips) sind vom Fallback ausgenommen, damit deren Farblogik unveraendert bleibt.
- **Placeholder und Meta-Texte verbessert**: Platzhalter- und Nebeninformationen wurden im Dark-Mode auf besser lesbare Farbstufen angehoben.

### v1.6.349 (23. Mai 2026)

- **Dashboard-Header neu ausgerichtet**: Die oberen KPI-Kacheln wurden auf Desktop weiter nach rechts verschoben.
- **Linke Seitenleiste nach oben verdichtet**: Die Host-Seitenleiste nutzt den frei werdenden oberen Bereich jetzt besser aus.
- **DB-Delta-1h Kachel ausgeblendet**: Die Kachel fuer das DB-Wachstum der letzten Stunde wird nicht mehr angezeigt.

### v1.6.348 (23. Mai 2026)

- **Emoji vor Kundennamen entfernt**: In Host-Karten und im ausgewählten Host-Chip wird der Kundenname jetzt ohne vorangestelltes Gebäude-Emoji dargestellt.

### v1.6.347 (23. Mai 2026)

- **Kundenname auf Host-Karte vergroessert**: Die Schrift fuer den Kundennamen wurde von 17px auf 18px erhoeht.

### v1.6.346 (23. Mai 2026)

- **Header-Chips umbenannt**: `REPORTS DB` heisst jetzt `REPORTS IN DB` und `REPORTS 1H` heisst jetzt `ANZAHL REPORTS`.

### v1.6.345 (23. Mai 2026)

- **Hotfix fuer Linux-Agent-Syntaxfehler**: Ein fehlerhaftes `fi` in `collect_and_send.sh` nach dem Update-Quellen-Fallback wurde korrigiert, damit der Agent wieder normal laeuft.

### v1.6.344 (23. Mai 2026)

- **Zusatz-Selbstheilung in `collect_and_send`**: Linux- und Windows-Agenten probieren beim Nachladen von `self_update` jetzt mehrere Update-Quellen (neu + alt + Config), damit ein globales `update-now` auch Hosts mit veralteter lokaler `self_update` ohne manuelles Eingreifen wieder auf den aktuellen Stand bringt.

### v1.6.343 (23. Mai 2026)

- **Self-Update hat jetzt einen Notfall-Fallback auf die Alt-Domain**: Falls `infoboard.an-group.work` auf einem Host noch nicht erreichbar ist, pruefen Linux- und Windows-`self_update` zusaetzlich `https://monitoring.rolfwalker.ch/updates`, damit der Versions-Lookup nicht abbricht.

### v1.6.342 (23. Mai 2026)

- **Self-Update Domain-Migration gehaertet**: Linux- und Windows-`self_update` versuchen jetzt zuerst die neue Canonical-URL und fallen bei Bedarf auf vorhandene Host-Quellen zurueck. Dadurch tritt der Fehler "Remote version lookup failed (AGENT_VERSION/BUILD_VERSION empty or invalid)" auf bestehenden Hosts nicht mehr auf.

### v1.6.341 (23. Mai 2026)

- **Agent-Quelle bewertet jetzt strikt auf die neue Ziel-URL**: Gruen wird nur noch dann angezeigt, wenn `SERVER_URL`, `UPDATE_BASE_URL` und `RAW_BASE_URL` auf `https://infoboard.an-group.work` bzw. `/updates` zeigen.

### v1.6.340 (23. Mai 2026)

- **Agent-Quelle zeigt jetzt wirklich die neue Ziel-URL an**: `SERVER_URL` wird in der Status-Tabelle gegen `https://infoboard.an-group.work` bewertet, und die Spaltenbreiten verhindern das Ueberlappen des Soll-Werts mit dem letzten Header.

### v1.6.339 (23. Mai 2026)

- **Agent-Quelle auf neue Canonical-URL umgestellt**: Die Soll-URL in der UI und die Backend-Bewertung fuer `agent.conf` vergleichen jetzt gegen `https://infoboard.an-group.work`; die Tabelle zeigt den Migrationszielwert explizit an.

### v1.6.338 (23. Mai 2026)

- **Canonical-URL fuer die Agenten-Migration umgestellt**: Bootstrapping, Self-Update und Repair schreiben Hosts jetzt aktiv auf `https://infoboard.an-group.work` um, damit die alte Domain nur noch uebergangsweise gebraucht wird.

### v1.6.337 (23. Mai 2026)

- **Resolved- und Instant-Alert-Mails verwenden jetzt den konfigurierten Absender**: Auch die Sofort-Alarm-Mails aus dem Alert-Event-Pfad uebergeben nun `email_sender`.

### v1.6.336 (23. Mai 2026)

- **Test-Mail fuer Host-Abo nutzt jetzt den konfigurierten Absender**: Der Host-Alert-Abo-Testpfad uebergibt `email_sender` nun ebenfalls, damit nicht vereinzelt die O365-Standardadresse verwendet wird.

### v1.6.335 (23. Mai 2026)

- **Root Cause fuer Alerts-502 mit `host_uid` behoben**: SQL-Alias-Aufbau in `reports_host_key_sql()` gehaertet. Aufrufe mit Alias wie `r.` erzeugen jetzt gueltige SQL-Ausdruecke statt `r..host_uid`.

### v1.6.334 (23. Mai 2026)

- **Host-Settings fuer Alerts robuster gemacht**: Migrierte SQLite-Daten mit leeren oder kaputten `customer_id`-Werten brechen das Alerts-Rendering nicht mehr ab.

### v1.6.333 (23. Mai 2026)

- **Alerts-Listen-Endpoint gegen leere Hostnamen gehaertet**: Der globale/Host-Alerts-Response initialisiert `customer_names` jetzt immer, damit Alerts-Datensaetze ohne Hostname keinen 502-Fehler mehr ausloesen.

### v1.6.317 (22. Mai 2026)

- **Changelog-Feldnamen fuer HANA-Tenants bereinigt**: Das Praefix `tenant` wird in den AddOn-Feldbezeichnungen entfernt.
- **Trennzeichen normalisiert**: Doppelte Doppelpunkte `::` in den HANA-AddOn-Feldnamen werden als einzelner Doppelpunkt `:` dargestellt.

### v1.6.316 (22. Mai 2026)

- **Host-Bezeichnung jetzt pro Host-Karte (host_uid) moeglich**: Display-Name-Overrides koennen jetzt UID-spezifisch gespeichert werden, statt nur hostname-basiert.
- **Fix fuer gleichnamige, getrennte Karten**: Wenn mehrere Karten denselben Hostnamen haben (z. B. geklonte Systeme), aendert eine Namensanpassung nicht mehr automatisch alle Karten.
- **API/UI auf UID-Override erweitert**: `host-settings` unterstuetzt `host_uid` fuer den Display-Namen; Hostliste und Report-Ansicht verwenden UID-Overrides priorisiert vor hostname-Fallback.

### v1.6.315 (22. Mai 2026)

- **Port/Target-Anzeige aus HANA-Multitenant-UI entfernt**: In Discovery, Tenant-Ueberschriften und Leerstatus-Meldungen werden keine Port- oder Target-Informationen mehr angezeigt.
- **Spaltenausrichtung in HANA-Datenbanklisten vereinheitlicht**: Tenant-Tabellen verwenden jetzt feste, konsistente Spaltenbreiten fuer `Datenbank`, `Firma` und `Lokalisierung`, damit alle Tabellen sauber auf denselben Spaltenpositionen stehen.

### v1.6.314 (22. Mai 2026)

- **Host-UID fuer Linux gegen Klon-Kollisionen gehaertet**: Bei der automatischen Host-UID-Bildung wird jetzt zusaetzlich die MAC der Default-NIC eingebunden (`<hostname>::mid:<machine-id>::mac:<mac>`).
- **Ursache fuer 4-auf-2-Merge adressiert**: Wenn zwei Hosts denselben Hostnamen und dieselbe (geklonte) `/etc/machine-id` haben, war die bisherige Host-UID identisch. Mit der NIC-MAC im UID-Key bleiben solche Hosts getrennt.

### v1.6.313 (22. Mai 2026)

- **HANA-Multitenant-Verbindung auf DB-Name-only gehaertet**: Im Tenant-Scan wird fuer AddOn- und COMPANYDBS-Abfragen jetzt ausschliesslich `hdbsql -d <tenant>` verwendet. Der `-n`/Port-Fallback wurde im Tenant-Modus entfernt, damit keine implizite Verbindung auf falsche Targets erfolgt.
- **Tenant-Discovery ohne Port-Abhaengigkeit**: Tenant-Erkennung nutzt nur noch die Verzeichnisse unter `/usr/sap/<SID>/SYS/global/hdb/custom/config/DB_???`; der `indexserver.ini`-`-port` wird nicht mehr ausgewertet.
- **UI-Discovery-Text angepasst**: Discovery zeigt nun neutral "Tenant-Verzeichnisse erkannt" statt port-basierter Statusmeldungen.

### v1.6.312 (22. Mai 2026)

- **Kein automatisches Hostkarten-Merge ueber Hostname mehr**: Alle relevanten Host-Queries verwenden jetzt einen strikten Host-Key ohne Hostname-Fallback. Damit werden Hosts nicht mehr wegen identischem Hostnamen zusammengefuehrt.
- **Striktes Schluesselverhalten**: Wenn `host_uid` vorhanden ist, wird nur diese UID verwendet. Wenn `host_uid` fehlt, wird ein eindeutiger Legacy-Key pro Report (`__legacy_report__:<id>`) genutzt statt einer impliziten Zusammenfuehrung.
- **Host-Reports/Export angepasst**: Filterung fuer `host_uid` nutzt denselben strikten Host-Key wie die Hostlisten-Aggregation, damit Auswahl und Detaildaten konsistent bleiben.

### v1.6.311 (22. Mai 2026)

- **Historische Host-UID-Reparatur eingefuehrt**: Neue serverseitige Batch-Reparatur setzt fuer bestehende Reports die `host_uid` wieder strikt auf den aus Payload/Agent/IP abgeleiteten Wert, statt alte, zusammengefuehrte UID-Zustaende fortzuschreiben.
- **Admin-Endpoint fuer Vollreparatur**: `POST /api/v1/admin/repair-host-uids` fuehrt den globalen Reparaturlauf aus und liefert Vorher/Nachher-Kennzahlen (gescannte Reports, geaenderte Reports, Hostkarten-Differenz, betroffene Hostnamen).
- **Schema-Absicherung fuer Alt-Datenbanken**: Reparatur/Backfill stellen fehlende `reports.host_uid`-Spalte samt relevanter Indizes automatisch bereit, damit der Fix auch auf aelteren DB-Staenden laeuft.

### v1.6.310 (22. Mai 2026)

- **Automatische Host-Zusammenfuehrung beim Ingest deaktiviert**: Der serverseitige Legacy-Reconcile-Schritt, der bestehende `host_uid`-Werte historischer Reports umgeschrieben hat, wurde entfernt.
- **Strikteres Kartenverhalten ueber `host_uid`**: Eingehende Reports behalten jetzt ihre abgeleitete/eingelieferte `host_uid` unveraendert; ein Merging ueber nachtraegliche UID-Umschreibung findet nicht mehr statt.

### v1.6.309 (22. Mai 2026)

- **Hostlisten-Interaktion auf Event-Delegation umgestellt**: Statt pro Hostkarte bei jedem Render mehrere Listener neu zu binden, nutzt die Sidebar jetzt zentrale delegierte Handler. Das reduziert den Setup-Overhead bei vielen Hosts deutlich und beschleunigt die Reaktion der Seitenliste spuerbar.
- **Hostlisten-Seitengroesse reduziert**: Standard-Limit fuer `/api/v1/hosts` im Frontend wurde von 500 auf 200 gesetzt, um Initial-Load, JSON-Verarbeitung und DOM-Aufbau zu entlasten.

### v1.6.308 (22. Mai 2026)

- **Startrendering der Seitenliste entkoppelt**: Beim Dashboard-Refresh wird die Host-/Seitenliste jetzt zuerst geladen und gerendert; die drei schweren Global-Kacheln (Globale Alerts, Kritische Trends, Inaktive Hosts) werden erst danach asynchron nachgezogen.
- **Weniger Blockierung beim Initialaufbau**: Die bis dato gleichzeitigen Start-Requests fuer die Global-Kacheln blockieren den schnellen Listenaufbau nicht mehr. Dadurch reagiert die Sidebar deutlich frueher und bleibt waehrend des Nachladens bedienbar.

### v1.6.307 (22. Mai 2026)

- **HANA Tenant-Zugriff auf DB-Name (`-d`) umgestellt**: Fuer AddOn- und Datenbankabfragen nutzt der Agent im Multitenant-Modus jetzt primaer `hdbsql -d <tenant_db>` (optional mit `-n` als Fallback), statt hart vom Tenant-Port abzuhaengen.
- **Kein harter Abbruch mehr bei fehlendem Tenant-Port**: Tenants ohne erkannten Port werden weiterhin abgefragt (ueber `-d`), damit Daten nicht mehr komplett ausfallen, wenn `indexserver.ini`-Portinfos fehlen oder ungueltig sind.

### v1.6.306 (22. Mai 2026)

- **Falsches Zusammenfuehren gleichnamiger Hosts gehaertet**: Die serverseitige `host_uid`-Reconciliation verlangt jetzt strengere Sekundaerachsen (Agent-ID und/oder IP; wenn beide vorhanden sind, muessen beide passen) und bricht bei mehrdeutigen bestehenden `host_uid`-Werten pro Hostname ab. Dadurch werden unterschiedliche Maschinen mit gleichem Hostnamen nicht mehr versehentlich auf eine Karte zusammengezogen.
- **Hostlisten-Rendering beschleunigt**: Nachladen von stummgeschalteten Alerts rendert die Hostliste nur noch neu, wenn sich die Mute-Daten tatsaechlich geaendert haben. Das reduziert unnoetige Voll-Renderzyklen deutlich.

### v1.6.305 (22. Mai 2026)

- **Tenant-Queries erzwingen jetzt den jeweiligen Tenant-Port**: Bei HANA-Multitenant-Scans fuer AddOns, SARI und COMPANYDBS wird im Tenant-Modus die implizite Default-Verbindung uebersprungen und direkt gegen den erkannten `host:port` des jeweiligen Tenants verbunden. Das verhindert, dass mehrere Tenants irrtuemlich denselben Inhalt aus derselben Default-DB anzeigen.

### v1.6.304 (22. Mai 2026)

- **HANA-Datenbankabfrage auf COMPANYDBS umgestellt**: Statt Schema-/Memory-Auswertung aus `M_CS_TABLES` wird pro erkanntem Tenant jetzt `SELECT "NAME","COMPANYNAME","LOCALIZATION" FROM "SLDDATA"."COMPANYDBS"` ausgefuehrt.
- **HANA-UI auf Datenbankliste angepasst**: Die HANA-Kachel zeigt jetzt je Tenant eine Tabelle mit Datenbankname, Firmenname und Lokalisierung statt Schema und Groesse.

### v1.6.303 (22. Mai 2026)

- **HANA-Multitenant-Erkennung fuer alphanumerische Tenant-IDs korrigiert**: Tenant-Ordner unter `/usr/sap/<SID>/SYS/global/hdb/custom/config` werden jetzt als `DB_XXX` mit beliebigen drei alphanumerischen Zeichen erkannt, statt nur rein numerische Namen wie `DB_123` zu akzeptieren.

### v1.6.302 (22. Mai 2026)

- **Multitenant-Discovery explizit im Payload**: Linux-Agent sendet nun zusaetzlich `hana_multitenant_discovery` mit erkannten Tenant-IDs/Ports, Tenant-Anzahl, Port-Abdeckung und Discovery-Status (`success`/`partial_missing_port`/`none_found`).
- **Sichtbare Discovery im UI**: In den HANA-Schema-Details wird ein eigener "Multitenant Discovery"-Block angezeigt, damit erkannte Tenants auch dann sichtbar bleiben, wenn eigentliche HANA-Abfragen leer sind oder fehlschlagen.

### v1.6.301 (22. Mai 2026)

- **Doppelte Host-Karten automatisch zusammenführen**: Beim Eingang eines Reports mit neuer/echter `host_uid` werden ältere, serverseitig erzeugte Fallback-Keys (z. B. `::agent:` / `::ip:`) für denselben Host gezielt auf die neue `host_uid` nachgezogen.
- **Host-Karte löschen beschleunigt**: Delete-Pfad optimiert (keine separaten Vorab-Count-Scans pro Tabelle, zusätzliche Reports-Indexierung für Host/Agent/IP/UID), wodurch das Löschen spürbar schneller reagiert.

### v1.6.300 (22. Mai 2026)

- **Hosts-Liste nach host_uid-Migration beschleunigt**: `/api/v1/hosts` wurde auf effizientere Aggregation umgestellt (Total+Page in einem CTE-Durchlauf), Alert-Zähler werden gesammelt statt als korrelierte Subqueries je Host berechnet, und zusätzliche Indizes für host_key/received_at wurden ergänzt.

### v1.6.299 (22. Mai 2026)

- **Host-Suche/Filter deutlich beschleunigt**: Sidebar-Filter (Suche, OS, Land, Interessen) werden jetzt lokal auf bereits geladene Hosts angewendet statt bei jeder Änderung `/api/v1/hosts` neu zu laden; die Suche nutzt zusätzlich ein kurzes Debounce für flüssigere Reaktion.

### v1.6.298 (22. Mai 2026)

- **Performance-Optimierung Hosts/Einzelmeldungen**: Zusätzliche DB-Indizes für Reports/Alerts eingeführt und Host-Report-Filter auf index-freundliche `host_uid`-Abfrage umgestellt. Dadurch sind Hostlisten-Aufbau und Kartenwechsel deutlich schneller auf grossen Datenbeständen.

### v1.6.297 (22. Mai 2026)

- **Host-ID Chip neu positioniert**: Der `host_uid`-Chip wurde aus der oberen Host-Metazeile in die Einzelmeldungs-Navigation verschoben und direkt neben `Aktuellste` platziert.

### v1.6.296 (22. Mai 2026)

- **Web-Start-Fix bei host_uid-Backfill**: Der Start-Backfill nutzt jetzt ID-basiertes Paging statt wiederholter LIMIT-Abfragen auf denselben offenen Datensätzen. Damit wird ein möglicher Endloslauf beim Start verhindert und der Web-Listener kommt zuverlässig hoch.

### v1.6.295 (22. Mai 2026)

- **Server-Start stabilisiert**: Der `host_uid`-Backfill in der Initialisierung verarbeitet Reports nun in kleinen Batches statt alles auf einmal, wodurch OOM-Kills beim Dienststart auf grossen Datenbanken vermieden werden.

### v1.6.294 (22. Mai 2026)

- **Host-ID im UI sichtbar**: Beim ausgewählten Host wird die technische Host-ID (`host_uid`) nun als eigener Chip angezeigt, damit Kollisionen/Zuordnungen direkt im Dashboard nachvollziehbar sind.

### v1.6.293 (22. Mai 2026)

- **Host-Identität entkoppelt (host_uid)**: Linux- und Windows-Agent senden jetzt zusätzlich eine stabile `host_uid` (mit Fallback-Strategien), damit Hosts mit identischem Hostname/IP sicher getrennt bleiben.
- **Server/API erweitert**: Ingestion, Backfill und Host-Listing nutzen `host_uid` mit sauberem Fallback auf `hostname`; `/api/v1/host-reports` und Reports-Export unterstützen nun auch `host_uid`.
- **UI-Selektion robust gemacht**: Host-Auswahl, Report-Laden, Export und Systemübersicht-Row-Klick arbeiten host_uid-basiert (abwärtskompatibel), wodurch Kollisionen bei gleichnamigen Hosts verhindert werden.

### v1.6.262 (20. Mai 2026)

- **DB-Maintenance Charts**: Popup-Drilldown für vergrößerte Graphen nun nur noch per Klick auf den jeweiligen Graphen (kein Hover-Trigger mehr).

### v1.6.261 (20. Mai 2026)

- **DB-Maintenance Charts**: Hover auf einen Kachel-Graph öffnet einen deutlich vergrößerten Chart im Popup (mit Schließen per `X`) für besser lesbare X-/Y-Achsenwerte.

### v1.6.260 (20. Mai 2026)

- **DB-Chart X-Achse**: In den DB-Maintenance-Kacheln werden jetzt Datum/Uhrzeit des ersten und letzten Datenpunkts auf der horizontalen Achse angezeigt.

### v1.6.259 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Gruppierungsansicht umgestellt auf 3 Ebenen: `AddOn-Name` -> `Version` -> `Kunde`.

### v1.6.258 (20. Mai 2026)

- **Systemübersicht Toolbar/Infos**: Einzeilige Informationen und Controls wieder als Chips dargestellt (u.a. Statistikzeile, Sortier-/Action-Buttons und Länderfilter).

### v1.6.257 (20. Mai 2026)

- **Alert Digest Mail**: Host-Detailzeile ergänzt um den Kundennamen (`Kunde: ...`) zusätzlich zur IP.

### v1.6.256 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Beim Öffnen sind AddOn-Gruppen auf der obersten Ebene standardmäßig zugeklappt.

### v1.6.255 (20. Mai 2026)

- **Telegram Nachrichten erweitert**: Kundename ergänzt in allen relevanten Telegram-Texten (Inaktive Hosts, Instant Alert, Reminder und Host-Abo-Testnachricht).

### v1.6.254 (20. Mai 2026)

- **Daily Trend Digest Mail**: Detailzeile pro Host ergänzt um den Kundennamen (`Kunde: ...`) neben der IP.

### v1.6.253 (20. Mai 2026)

- **Systemübersicht UI vereinfacht**: Chip-/Pill-Optik (Hintergrund, Rahmen, Rundung) für Länderfilter, Sort-/AddOn-/Expand-/Reload-Buttons und Gruppen-Toggles in der Systemübersicht entfernt; Darstellung jetzt bewusst schlicht und flach.

### v1.6.252 (20. Mai 2026)

- **Inaktive Hosts Mail Reihenfolge**: In der Host-Detailzelle steht jetzt zuerst der Kunde, darunter der Anzeigename und danach Host/IP.

### v1.6.251 (20. Mai 2026)

- **Inaktive Hosts Mail**: Detailzeile pro Host erweitert um den Kundennamen (`Kunde: ...`) neben Host und IP.

### v1.6.250 (20. Mai 2026)

- **Header Session-Badge**: Sichtbaren Session-Countdown im Header entfernt; Session-Refresh- und Timeout-Logik bleiben weiterhin im Hintergrund aktiv.

### v1.6.249 (19. Mai 2026)

- **Mail-Footer SAP-Logo**: SAP-Logo in allen HTML-Mails (inkl. Testmail-Vorlagen) um ca. 20% verkleinert, damit das Footer-Balancing mit dem ANG-Logo harmonischer wirkt.

### v1.6.248 (19. Mai 2026)

- **Header SAP-Logo Größe**: SAP-Logo im Header um ca. 30% vergrößert und gleichzeitig per Max-Height begrenzt, sodass es optisch nicht höher als das ANG-Logo wird.

### v1.6.247 (19. Mai 2026)

- **Mail-Templates (inkl. Testmails)**: Footer in allen HTML-Mailvorlagen erweitert: SAP-Logo jetzt links unten auf gleicher Höhe wie das bestehende ANG-Logo rechts unten (zentral über gemeinsame Footer-Helper-Funktion in `receiver.py`).

### v1.6.246 (19. Mai 2026)

- **Header Logo Placement**: SAP-Logo ohne Überlappung direkt links neben den Darkmode-Schalter verschoben (kleiner Abstand, stabile Größe im Header).

### v1.6.245 (19. Mai 2026)

- **Header Logo Fine-Tuning**: SAP-Logo im Top-Header aus dem normalen Layoutfluss genommen (kein Titel-Umbruch mehr) und visuell weiter Richtung Darkmode-Bereich verschoben; mobile Darstellung bleibt responsiv gestapelt.

### v1.6.244 (19. Mai 2026)

- **Header Logo Position**: SAP-Logo aus der Report-Navigation entfernt und im oberen Header zentriert zwischen Titelbereich links und Darkmode-Bereich rechts platziert; Größe maximal responsiv ohne Layoutbruch.

### v1.6.243 (19. Mai 2026)

- **SAP B1 Logo Position**: Logo aus dem SAP-B1-Card-Header entfernt und in der Report-Navigation (bei Zurück/Vor) zentriert zwischen linkem Steuerblock und rechter Datumsinfo platziert, mit responsiver Maximalgröße ohne Layoutbruch.

### v1.6.242 (19. Mai 2026)

- **Deploy (pull-server-only)**: `server/static/icons/sap.png` zur Download-Dateiliste hinzugefügt, damit das SAP-B1-Logo bei Server-Updates zuverlässig mitgezogen wird.

### v1.6.241 (19. Mai 2026)

- **SAP B1 UI Asset**: `server/static/icons/sap.png` versioniert und ausgeliefert, damit das im SAP-B1-Header eingebundene Logo zuverlässig sichtbar ist.

### v1.6.240 (19. Mai 2026)

- **SAP B1 UI**: Neues `sap.png` Logo im SAP-B1-Bereich als rechter Header-Akzent eingebunden (responsive, ohne Layout-Verzerrung).

### v1.6.239 (19. Mai 2026)

- **SAP B1 Lizenzinfos UI**: Bereich "Lizenzinfos" startet jetzt standardmäßig zugeklappt und kann bei Bedarf aufgeklappt werden.

### v1.6.231 (19. Mai 2026)

- **HANA AddOns Query**: Lightweight-Abfrage auf `INNER JOIN` umgestellt (`SLDDATA.EXTENSIONS` ↔ `SLDDATA.EXTENSIONDEPLOYMENTS`), damit nur Datensätze mit passendem Deployment geliefert werden. Deployment-Guide entsprechend aktualisiert.

### v1.6.230 (19. Mai 2026)

- **Windows SQL Query (SLDData.Extensions)**: JOIN von `LEFT JOIN` auf `INNER JOIN` umgestellt, damit nur AddOns mit passendem Deployment in den Payload übernommen werden.

### v1.6.229 (19. Mai 2026)

- **README erweitert**: Payload-Snapshot-Rotation (Default 4), Standardpfade fuer Linux/Windows, Konfig-Overrides (`PAYLOAD_ARCHIVE_DIR`, `PAYLOAD_ARCHIVE_KEEP`) sowie bereits vorhandene SQL/HANA-Fehlerfelder im Payload dokumentiert.

### v1.6.228 (19. Mai 2026)

- **Payload-Sicherung vor Versand**: Agenten speichern vor jedem Report-POST automatisch einen lokalen Payload-Snapshot und behalten standardmäßig die letzten 4 Dateien (ältere werden rotiert) für nachträgliche Fehleranalyse.

### v1.6.227 (19. Mai 2026)

- **Admin Login-Audit UI**: Web-Login-Liste im Admin-Bereich als auf- und zuklappbaren Bereich umgesetzt; standardmäßig zugeklappt.

### v1.6.226 (19. Mai 2026)

- **Windows SQL Hotfix (Extensions)**: JOIN-Abfrage auf Alias-Syntax umgestellt (`Extensions` = `e`, `ExtensionDeployments` = `ed`), damit die AddOn-Daten aus `SLDData` wieder korrekt geliefert werden.

### v1.6.225 (19. Mai 2026)

- **Extensions Query Update (Windows + Linux)**: Auslesen der AddOn-Infos aus `SLDData.Extensions` auf Join mit `ExtensionDeployments` umgestellt; in beiden Windows-Skripten, im Linux-Collector und in der Deployment-Doku konsistent nachgezogen.

n### v1.6.224 (19. Mai 2026)

- **Windows Agent**: Lizenzfile-Suchpfade korrigiert und erweitert: `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenz\B01.txt` und `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenzen\B01.txt` hinzugefügt.
n### v1.6.223 (19. Mai 2026)

- **Windows Agent**: Zusätzlicher Suchpfad für Lizenzfile (B01.txt) hinzugefügt: `C:Program Files (x86)SAPSAP Business One ServerB1_SHRB01.txt`
n### v1.6.222 (19. Mai 2026)

- **DB-Backup Remote-502 Hardening**: Backup-Start auf asynchronen Hintergrundjob umgestellt (schnelle Start-Antwort, kein Proxy-Timeout), Dateidownload auf Chunk-Streaming umgestellt und Status/Fehler-Handling für Backup-Job verbessert.
n### v1.6.221 (19. Mai 2026)

- **DB-Backup One-Shot**: Backup-Download-Jobs werden nach erfolgreichem Download sofort invalidiert und die temporäre Backup-Datei direkt gelöscht (kein stale Job-State).
n### v1.6.220 (19. Mai 2026)

- **DB-Backup Download**: Download-Flow im Admin-Bereich auf Fetch+Blob umgestellt (statt nativer Anchor-Navigation), damit Backup-Dateien zuverlässig vollständig heruntergeladen werden und Fehler sauber erkannt werden.
n### v1.6.219 (19. Mai 2026)

- **Hostkarten UI**: Unterste Reihe mit den drei Infochips (z. B. SAP/HANA/SID) aus der Hostkarte entfernt; Informationen bleiben in anderen Ansichten verfügbar.
n### v1.6.218 (19. Mai 2026)

- **Admin-Markierung SAP B1**: Admin-exklusive Unterpunkte bleiben für Admins sichtbar und werden nun optisch markiert (Badge + Akzent), während sie für Nicht-Admins weiterhin komplett ausgeblendet sind.
n### v1.6.217 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Admin-Unterpunkt 'SAP B1 Setup Roh-Output' wird für Nicht-Admins nun vollständig ausgeblendet (kein Hinweistext, kein Menüpunkt).
n### v1.6.216 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Unterpunkt 'SAP B1 Setup Roh-Output' auf Admin-Benutzer eingeschränkt; Nicht-Admins sehen nur einen Hinweistext.
n### v1.6.215 (19. Mai 2026)

- **SAP B1 Lizenzinfos**: Detailinhalte (HW-Key, Installationsnummer, Systemnummer, Kundennummer, Lizenznehmer, Gültigkeit, Datei-Stand) ausgeblendet; angezeigt werden nur noch die zwei SQL/HANA-Suchpfad-Infozeilen.
n### v1.6.214 (18. Mai 2026)

- **pull-server-only**: PNG-Icon-Downloads auf denselben Parallelwert wie Standarddateien umgestellt (MAX_PARALLEL_DOWNLOADS, standardmäßig 8).
- **Hostkarte**: Testweise eingebauten Versionsrückstands-Zahlenchip wieder ersatzlos entfernt.
n### v1.6.213 (18. Mai 2026)

- **Hostkarten Versionsindikator**: Roten Punkt durch runden Zahlen-Chip ersetzt; zeigt den Versionsrückstand (Anzahl Versionen) nur bei Rückstand > 0.
n### v1.6.212 (18. Mai 2026)

- **Hostkarten Layout**: Vertikalen Abstand zwischen Hostbezeichnung und der darunterliegenden IP-/Meta-Zeile reduziert.
n### v1.6.211 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte nochmals deutlich verkleinert (fast ohne Zusatzabstand).
n### v1.6.210 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte leicht reduziert (feineres Tuning).
n### v1.6.209 (18. Mai 2026)

- **License Card Layout-Fix**: Clipboard-Icon aus dem Grid-Flow entfernt und als Floating-Button oben rechts positioniert, damit die Kartenstruktur stabil bleibt.
n### v1.6.208 (18. Mai 2026)

- **License Card Datenlogik**: Lizenzkarte wird strikt nur bei selektiertem Host und vorhandenen Lizenzdaten angezeigt.
- **License Card Layout**: Spaltenabstand in der Lizenzkarte reduziert.
- **Clipboard Komfort**: Neues 📋-Icon kopiert HW-Key, Installationsnummer und Systemnummer in die Zwischenablage.
n### v1.6.207 (18. Mai 2026)

- **License Card Height**: Maximale Hoehe der Lizenzkarte von 150px auf 100px reduziert (overflow-y: auto).
n### v1.6.206 (18. Mai 2026)

- **License Card Position**: Lizenzkarte ins horizontale Zentrum des Headers verschoben; Karteninhalt linksbündig.
n### v1.6.205 (18. Mai 2026)

- **License Card Styling**: Lizenzkarte: Labels kleiner und leichter, Werte extra-fett (800), mehr Spaltenabstand, Inhalte horizontal zentriert.
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

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.168 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.167 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.166 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.165 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.164 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.163 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.162 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.161 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.160 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.159 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.158 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.157 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.156 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.155 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.154 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.153 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.152 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

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

- **Hostkarten-Hintergrund zurueckgesetzt**: Der eigentliche Kartenhintergrund wurde auf den Stand vor der letzten Farbumstellung zurueckgesetzt. Die aktuellen Pillenfarben (Kunde/SAP/HANA/SID) bleiben unveraendert.

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
- **Kundenchip verschoben**: Der Kunden-Chip wurde aus der oberen Titelzeile in die zweite Zeile an die frühere Position der Meldungsanzeige verschoben.

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
- **Benachrichtigungsbereich vereinfacht**: Der Bereich enthaelt nun nur noch Heads-Up-/Inaktiv-Logik und ist dadurch deutlich uebersichtlicher.

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

### v1.4.39 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.38 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.37 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.36 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.35 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.34 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.33 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.32 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.31 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.30 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.29 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.28 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.27 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.26 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.25 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.24 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.23 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.22 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.21 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.20 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.19 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.18 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.17 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.16 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.15 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.14 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.13 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.12 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.11 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.10 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v-1.6.274 (20. Mai 2026)

- **Add customer management UI (edit/delete customers); prepare read-only user type with restricted permissions**

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
### v1.6.262 (20. Mai 2026)

- **DB-Maintenance Charts**: Popup-Drilldown für vergrößerte Graphen nun nur noch per Klick auf den jeweiligen Graphen (kein Hover-Trigger mehr).

### v1.6.261 (20. Mai 2026)

- **DB-Maintenance Charts**: Hover auf einen Kachel-Graph öffnet einen deutlich vergrößerten Chart im Popup (mit Schließen per `X`) für besser lesbare X-/Y-Achsenwerte.

### v1.6.260 (20. Mai 2026)

- **DB-Chart X-Achse**: In den DB-Maintenance-Kacheln werden jetzt Datum/Uhrzeit des ersten und letzten Datenpunkts auf der horizontalen Achse angezeigt.

### v1.6.259 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Gruppierungsansicht umgestellt auf 3 Ebenen: `AddOn-Name` -> `Version` -> `Kunde`.

### v1.6.258 (20. Mai 2026)

- **Systemübersicht Toolbar/Infos**: Einzeilige Informationen und Controls wieder als Chips dargestellt (u.a. Statistikzeile, Sortier-/Action-Buttons und Länderfilter).

### v1.6.257 (20. Mai 2026)

- **Alert Digest Mail**: Host-Detailzeile ergänzt um den Kundennamen (`Kunde: ...`) zusätzlich zur IP.

### v1.6.256 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Beim Öffnen sind AddOn-Gruppen auf der obersten Ebene standardmäßig zugeklappt.

### v1.6.255 (20. Mai 2026)

- **Telegram Nachrichten erweitert**: Kundename ergänzt in allen relevanten Telegram-Texten (Inaktive Hosts, Instant Alert, Reminder und Host-Abo-Testnachricht).

### v1.6.254 (20. Mai 2026)

- **Daily Trend Digest Mail**: Detailzeile pro Host ergänzt um den Kundennamen (`Kunde: ...`) neben der IP.

### v1.6.253 (20. Mai 2026)

- **Systemübersicht UI vereinfacht**: Chip-/Pill-Optik (Hintergrund, Rahmen, Rundung) für Länderfilter, Sort-/AddOn-/Expand-/Reload-Buttons und Gruppen-Toggles in der Systemübersicht entfernt; Darstellung jetzt bewusst schlicht und flach.

### v1.6.252 (20. Mai 2026)

- **Inaktive Hosts Mail Reihenfolge**: In der Host-Detailzelle steht jetzt zuerst der Kunde, darunter der Anzeigename und danach Host/IP.

### v1.6.251 (20. Mai 2026)

- **Inaktive Hosts Mail**: Detailzeile pro Host erweitert um den Kundennamen (`Kunde: ...`) neben Host und IP.

### v1.6.250 (20. Mai 2026)

- **Header Session-Badge**: Sichtbaren Session-Countdown im Header entfernt; Session-Refresh- und Timeout-Logik bleiben weiterhin im Hintergrund aktiv.

### v1.6.249 (19. Mai 2026)

- **Mail-Footer SAP-Logo**: SAP-Logo in allen HTML-Mails (inkl. Testmail-Vorlagen) um ca. 20% verkleinert, damit das Footer-Balancing mit dem ANG-Logo harmonischer wirkt.

### v1.6.248 (19. Mai 2026)

- **Header SAP-Logo Größe**: SAP-Logo im Header um ca. 30% vergrößert und gleichzeitig per Max-Height begrenzt, sodass es optisch nicht höher als das ANG-Logo wird.

### v1.6.247 (19. Mai 2026)

- **Mail-Templates (inkl. Testmails)**: Footer in allen HTML-Mailvorlagen erweitert: SAP-Logo jetzt links unten auf gleicher Höhe wie das bestehende ANG-Logo rechts unten (zentral über gemeinsame Footer-Helper-Funktion in `receiver.py`).

### v1.6.246 (19. Mai 2026)

- **Header Logo Placement**: SAP-Logo ohne Überlappung direkt links neben den Darkmode-Schalter verschoben (kleiner Abstand, stabile Größe im Header).

### v1.6.245 (19. Mai 2026)

- **Header Logo Fine-Tuning**: SAP-Logo im Top-Header aus dem normalen Layoutfluss genommen (kein Titel-Umbruch mehr) und visuell weiter Richtung Darkmode-Bereich verschoben; mobile Darstellung bleibt responsiv gestapelt.

### v1.6.244 (19. Mai 2026)

- **Header Logo Position**: SAP-Logo aus der Report-Navigation entfernt und im oberen Header zentriert zwischen Titelbereich links und Darkmode-Bereich rechts platziert; Größe maximal responsiv ohne Layoutbruch.

### v1.6.243 (19. Mai 2026)

- **SAP B1 Logo Position**: Logo aus dem SAP-B1-Card-Header entfernt und in der Report-Navigation (bei Zurück/Vor) zentriert zwischen linkem Steuerblock und rechter Datumsinfo platziert, mit responsiver Maximalgröße ohne Layoutbruch.

### v1.6.242 (19. Mai 2026)

- **Deploy (pull-server-only)**: `server/static/icons/sap.png` zur Download-Dateiliste hinzugefügt, damit das SAP-B1-Logo bei Server-Updates zuverlässig mitgezogen wird.

### v1.6.241 (19. Mai 2026)

- **SAP B1 UI Asset**: `server/static/icons/sap.png` versioniert und ausgeliefert, damit das im SAP-B1-Header eingebundene Logo zuverlässig sichtbar ist.

### v1.6.240 (19. Mai 2026)

- **SAP B1 UI**: Neues `sap.png` Logo im SAP-B1-Bereich als rechter Header-Akzent eingebunden (responsive, ohne Layout-Verzerrung).

### v1.6.239 (19. Mai 2026)

- **SAP B1 Lizenzinfos UI**: Bereich "Lizenzinfos" startet jetzt standardmäßig zugeklappt und kann bei Bedarf aufgeklappt werden.

### v1.6.231 (19. Mai 2026)

- **HANA AddOns Query**: Lightweight-Abfrage auf `INNER JOIN` umgestellt (`SLDDATA.EXTENSIONS` ↔ `SLDDATA.EXTENSIONDEPLOYMENTS`), damit nur Datensätze mit passendem Deployment geliefert werden. Deployment-Guide entsprechend aktualisiert.

### v1.6.230 (19. Mai 2026)

- **Windows SQL Query (SLDData.Extensions)**: JOIN von `LEFT JOIN` auf `INNER JOIN` umgestellt, damit nur AddOns mit passendem Deployment in den Payload übernommen werden.

### v1.6.229 (19. Mai 2026)

- **README erweitert**: Payload-Snapshot-Rotation (Default 4), Standardpfade fuer Linux/Windows, Konfig-Overrides (`PAYLOAD_ARCHIVE_DIR`, `PAYLOAD_ARCHIVE_KEEP`) sowie bereits vorhandene SQL/HANA-Fehlerfelder im Payload dokumentiert.

### v1.6.228 (19. Mai 2026)

- **Payload-Sicherung vor Versand**: Agenten speichern vor jedem Report-POST automatisch einen lokalen Payload-Snapshot und behalten standardmäßig die letzten 4 Dateien (ältere werden rotiert) für nachträgliche Fehleranalyse.

### v1.6.227 (19. Mai 2026)

- **Admin Login-Audit UI**: Web-Login-Liste im Admin-Bereich als auf- und zuklappbaren Bereich umgesetzt; standardmäßig zugeklappt.

### v1.6.226 (19. Mai 2026)

- **Windows SQL Hotfix (Extensions)**: JOIN-Abfrage auf Alias-Syntax umgestellt (`Extensions` = `e`, `ExtensionDeployments` = `ed`), damit die AddOn-Daten aus `SLDData` wieder korrekt geliefert werden.

### v1.6.225 (19. Mai 2026)

- **Extensions Query Update (Windows + Linux)**: Auslesen der AddOn-Infos aus `SLDData.Extensions` auf Join mit `ExtensionDeployments` umgestellt; in beiden Windows-Skripten, im Linux-Collector und in der Deployment-Doku konsistent nachgezogen.

n### v1.6.224 (19. Mai 2026)

- **Windows Agent**: Lizenzfile-Suchpfade korrigiert und erweitert: `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenz\B01.txt` und `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenzen\B01.txt` hinzugefügt.
n### v1.6.223 (19. Mai 2026)

- **Windows Agent**: Zusätzlicher Suchpfad für Lizenzfile (B01.txt) hinzugefügt: `C:Program Files (x86)SAPSAP Business One ServerB1_SHRB01.txt`
n### v1.6.222 (19. Mai 2026)

- **DB-Backup Remote-502 Hardening**: Backup-Start auf asynchronen Hintergrundjob umgestellt (schnelle Start-Antwort, kein Proxy-Timeout), Dateidownload auf Chunk-Streaming umgestellt und Status/Fehler-Handling für Backup-Job verbessert.
n### v1.6.221 (19. Mai 2026)

- **DB-Backup One-Shot**: Backup-Download-Jobs werden nach erfolgreichem Download sofort invalidiert und die temporäre Backup-Datei direkt gelöscht (kein stale Job-State).
n### v1.6.220 (19. Mai 2026)

- **DB-Backup Download**: Download-Flow im Admin-Bereich auf Fetch+Blob umgestellt (statt nativer Anchor-Navigation), damit Backup-Dateien zuverlässig vollständig heruntergeladen werden und Fehler sauber erkannt werden.
n### v1.6.219 (19. Mai 2026)

- **Hostkarten UI**: Unterste Reihe mit den drei Infochips (z. B. SAP/HANA/SID) aus der Hostkarte entfernt; Informationen bleiben in anderen Ansichten verfügbar.
n### v1.6.218 (19. Mai 2026)

- **Admin-Markierung SAP B1**: Admin-exklusive Unterpunkte bleiben für Admins sichtbar und werden nun optisch markiert (Badge + Akzent), während sie für Nicht-Admins weiterhin komplett ausgeblendet sind.
n### v1.6.217 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Admin-Unterpunkt 'SAP B1 Setup Roh-Output' wird für Nicht-Admins nun vollständig ausgeblendet (kein Hinweistext, kein Menüpunkt).
n### v1.6.216 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Unterpunkt 'SAP B1 Setup Roh-Output' auf Admin-Benutzer eingeschränkt; Nicht-Admins sehen nur einen Hinweistext.
n### v1.6.215 (19. Mai 2026)

- **SAP B1 Lizenzinfos**: Detailinhalte (HW-Key, Installationsnummer, Systemnummer, Kundennummer, Lizenznehmer, Gültigkeit, Datei-Stand) ausgeblendet; angezeigt werden nur noch die zwei SQL/HANA-Suchpfad-Infozeilen.
n### v1.6.214 (18. Mai 2026)

- **pull-server-only**: PNG-Icon-Downloads auf denselben Parallelwert wie Standarddateien umgestellt (MAX_PARALLEL_DOWNLOADS, standardmäßig 8).
- **Hostkarte**: Testweise eingebauten Versionsrückstands-Zahlenchip wieder ersatzlos entfernt.
n### v1.6.213 (18. Mai 2026)

- **Hostkarten Versionsindikator**: Roten Punkt durch runden Zahlen-Chip ersetzt; zeigt den Versionsrückstand (Anzahl Versionen) nur bei Rückstand > 0.
n### v1.6.212 (18. Mai 2026)

- **Hostkarten Layout**: Vertikalen Abstand zwischen Hostbezeichnung und der darunterliegenden IP-/Meta-Zeile reduziert.
n### v1.6.211 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte nochmals deutlich verkleinert (fast ohne Zusatzabstand).
n### v1.6.210 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte leicht reduziert (feineres Tuning).
n### v1.6.209 (18. Mai 2026)

- **License Card Layout-Fix**: Clipboard-Icon aus dem Grid-Flow entfernt und als Floating-Button oben rechts positioniert, damit die Kartenstruktur stabil bleibt.
n### v1.6.208 (18. Mai 2026)

- **License Card Datenlogik**: Lizenzkarte wird strikt nur bei selektiertem Host und vorhandenen Lizenzdaten angezeigt.
- **License Card Layout**: Spaltenabstand in der Lizenzkarte reduziert.
- **Clipboard Komfort**: Neues 📋-Icon kopiert HW-Key, Installationsnummer und Systemnummer in die Zwischenablage.
n### v1.6.207 (18. Mai 2026)

- **License Card Height**: Maximale Hoehe der Lizenzkarte von 150px auf 100px reduziert (overflow-y: auto).
n### v1.6.206 (18. Mai 2026)

- **License Card Position**: Lizenzkarte ins horizontale Zentrum des Headers verschoben; Karteninhalt linksbündig.
n### v1.6.205 (18. Mai 2026)

- **License Card Styling**: Lizenzkarte: Labels kleiner und leichter, Werte extra-fett (800), mehr Spaltenabstand, Inhalte horizontal zentriert.
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

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.168 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.167 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.166 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.165 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.164 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.163 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.162 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.161 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.160 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.159 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.158 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.157 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.156 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.155 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.154 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.153 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.152 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

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

- **Hostkarten-Hintergrund zurueckgesetzt**: Der eigentliche Kartenhintergrund wurde auf den Stand vor der letzten Farbumstellung zurueckgesetzt. Die aktuellen Pillenfarben (Kunde/SAP/HANA/SID) bleiben unveraendert.

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
- **Kundenchip verschoben**: Der Kunden-Chip wurde aus der oberen Titelzeile in die zweite Zeile an die frühere Position der Meldungsanzeige verschoben.

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
- **Benachrichtigungsbereich vereinfacht**: Der Bereich enthaelt nun nur noch Heads-Up-/Inaktiv-Logik und ist dadurch deutlich uebersichtlicher.

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

### v1.4.39 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.38 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.37 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.36 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.35 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.34 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.33 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.32 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.31 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.30 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.29 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.28 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.27 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.26 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.25 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.24 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.23 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.22 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.21 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.20 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.19 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.18 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.17 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.16 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.15 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.14 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.13 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.12 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.11 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.10 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.4.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.3.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.2.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.1.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.9 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.8 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.7 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.6 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.5 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.4 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.3 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.2 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.1 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.0.0 (11. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v-1.6.274 (20. Mai 2026)

- **Add customer management UI (edit/delete customers); prepare read-only user type with restricted permissions**

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
### v1.6.262 (20. Mai 2026)

- **DB-Maintenance Charts**: Popup-Drilldown für vergrößerte Graphen nun nur noch per Klick auf den jeweiligen Graphen (kein Hover-Trigger mehr).

### v1.6.261 (20. Mai 2026)

- **DB-Maintenance Charts**: Hover auf einen Kachel-Graph öffnet einen deutlich vergrößerten Chart im Popup (mit Schließen per `X`) für besser lesbare X-/Y-Achsenwerte.

### v1.6.260 (20. Mai 2026)

- **DB-Chart X-Achse**: In den DB-Maintenance-Kacheln werden jetzt Datum/Uhrzeit des ersten und letzten Datenpunkts auf der horizontalen Achse angezeigt.

### v1.6.259 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Gruppierungsansicht umgestellt auf 3 Ebenen: `AddOn-Name` -> `Version` -> `Kunde`.

### v1.6.258 (20. Mai 2026)

- **Systemübersicht Toolbar/Infos**: Einzeilige Informationen und Controls wieder als Chips dargestellt (u.a. Statistikzeile, Sortier-/Action-Buttons und Länderfilter).

### v1.6.257 (20. Mai 2026)

- **Alert Digest Mail**: Host-Detailzeile ergänzt um den Kundennamen (`Kunde: ...`) zusätzlich zur IP.

### v1.6.256 (20. Mai 2026)

- **Systemübersicht (Sort: AddOn)**: Beim Öffnen sind AddOn-Gruppen auf der obersten Ebene standardmäßig zugeklappt.

### v1.6.255 (20. Mai 2026)

- **Telegram Nachrichten erweitert**: Kundename ergänzt in allen relevanten Telegram-Texten (Inaktive Hosts, Instant Alert, Reminder und Host-Abo-Testnachricht).

### v1.6.254 (20. Mai 2026)

- **Daily Trend Digest Mail**: Detailzeile pro Host ergänzt um den Kundennamen (`Kunde: ...`) neben der IP.

### v1.6.253 (20. Mai 2026)

- **Systemübersicht UI vereinfacht**: Chip-/Pill-Optik (Hintergrund, Rahmen, Rundung) für Länderfilter, Sort-/AddOn-/Expand-/Reload-Buttons und Gruppen-Toggles in der Systemübersicht entfernt; Darstellung jetzt bewusst schlicht und flach.

### v1.6.252 (20. Mai 2026)

- **Inaktive Hosts Mail Reihenfolge**: In der Host-Detailzelle steht jetzt zuerst der Kunde, darunter der Anzeigename und danach Host/IP.

### v1.6.251 (20. Mai 2026)

- **Inaktive Hosts Mail**: Detailzeile pro Host erweitert um den Kundennamen (`Kunde: ...`) neben Host und IP.

### v1.6.250 (20. Mai 2026)

- **Header Session-Badge**: Sichtbaren Session-Countdown im Header entfernt; Session-Refresh- und Timeout-Logik bleiben weiterhin im Hintergrund aktiv.

### v1.6.249 (19. Mai 2026)

- **Mail-Footer SAP-Logo**: SAP-Logo in allen HTML-Mails (inkl. Testmail-Vorlagen) um ca. 20% verkleinert, damit das Footer-Balancing mit dem ANG-Logo harmonischer wirkt.

### v1.6.248 (19. Mai 2026)

- **Header SAP-Logo Größe**: SAP-Logo im Header um ca. 30% vergrößert und gleichzeitig per Max-Height begrenzt, sodass es optisch nicht höher als das ANG-Logo wird.

### v1.6.247 (19. Mai 2026)

- **Mail-Templates (inkl. Testmails)**: Footer in allen HTML-Mailvorlagen erweitert: SAP-Logo jetzt links unten auf gleicher Höhe wie das bestehende ANG-Logo rechts unten (zentral über gemeinsame Footer-Helper-Funktion in `receiver.py`).

### v1.6.246 (19. Mai 2026)

- **Header Logo Placement**: SAP-Logo ohne Überlappung direkt links neben den Darkmode-Schalter verschoben (kleiner Abstand, stabile Größe im Header).

### v1.6.245 (19. Mai 2026)

- **Header Logo Fine-Tuning**: SAP-Logo im Top-Header aus dem normalen Layoutfluss genommen (kein Titel-Umbruch mehr) und visuell weiter Richtung Darkmode-Bereich verschoben; mobile Darstellung bleibt responsiv gestapelt.

### v1.6.244 (19. Mai 2026)

- **Header Logo Position**: SAP-Logo aus der Report-Navigation entfernt und im oberen Header zentriert zwischen Titelbereich links und Darkmode-Bereich rechts platziert; Größe maximal responsiv ohne Layoutbruch.

### v1.6.243 (19. Mai 2026)

- **SAP B1 Logo Position**: Logo aus dem SAP-B1-Card-Header entfernt und in der Report-Navigation (bei Zurück/Vor) zentriert zwischen linkem Steuerblock und rechter Datumsinfo platziert, mit responsiver Maximalgröße ohne Layoutbruch.

### v1.6.242 (19. Mai 2026)

- **Deploy (pull-server-only)**: `server/static/icons/sap.png` zur Download-Dateiliste hinzugefügt, damit das SAP-B1-Logo bei Server-Updates zuverlässig mitgezogen wird.

### v1.6.241 (19. Mai 2026)

- **SAP B1 UI Asset**: `server/static/icons/sap.png` versioniert und ausgeliefert, damit das im SAP-B1-Header eingebundene Logo zuverlässig sichtbar ist.

### v1.6.240 (19. Mai 2026)

- **SAP B1 UI**: Neues `sap.png` Logo im SAP-B1-Bereich als rechter Header-Akzent eingebunden (responsive, ohne Layout-Verzerrung).

### v1.6.239 (19. Mai 2026)

- **SAP B1 Lizenzinfos UI**: Bereich "Lizenzinfos" startet jetzt standardmäßig zugeklappt und kann bei Bedarf aufgeklappt werden.

### v1.6.231 (19. Mai 2026)

- **HANA AddOns Query**: Lightweight-Abfrage auf `INNER JOIN` umgestellt (`SLDDATA.EXTENSIONS` ↔ `SLDDATA.EXTENSIONDEPLOYMENTS`), damit nur Datensätze mit passendem Deployment geliefert werden. Deployment-Guide entsprechend aktualisiert.

### v1.6.230 (19. Mai 2026)

- **Windows SQL Query (SLDData.Extensions)**: JOIN von `LEFT JOIN` auf `INNER JOIN` umgestellt, damit nur AddOns mit passendem Deployment in den Payload übernommen werden.

### v1.6.229 (19. Mai 2026)

- **README erweitert**: Payload-Snapshot-Rotation (Default 4), Standardpfade fuer Linux/Windows, Konfig-Overrides (`PAYLOAD_ARCHIVE_DIR`, `PAYLOAD_ARCHIVE_KEEP`) sowie bereits vorhandene SQL/HANA-Fehlerfelder im Payload dokumentiert.

### v1.6.228 (19. Mai 2026)

- **Payload-Sicherung vor Versand**: Agenten speichern vor jedem Report-POST automatisch einen lokalen Payload-Snapshot und behalten standardmäßig die letzten 4 Dateien (ältere werden rotiert) für nachträgliche Fehleranalyse.

### v1.6.227 (19. Mai 2026)

- **Admin Login-Audit UI**: Web-Login-Liste im Admin-Bereich als auf- und zuklappbaren Bereich umgesetzt; standardmäßig zugeklappt.

### v1.6.226 (19. Mai 2026)

- **Windows SQL Hotfix (Extensions)**: JOIN-Abfrage auf Alias-Syntax umgestellt (`Extensions` = `e`, `ExtensionDeployments` = `ed`), damit die AddOn-Daten aus `SLDData` wieder korrekt geliefert werden.

### v1.6.225 (19. Mai 2026)

- **Extensions Query Update (Windows + Linux)**: Auslesen der AddOn-Infos aus `SLDData.Extensions` auf Join mit `ExtensionDeployments` umgestellt; in beiden Windows-Skripten, im Linux-Collector und in der Deployment-Doku konsistent nachgezogen.

n### v1.6.224 (19. Mai 2026)

- **Windows Agent**: Lizenzfile-Suchpfade korrigiert und erweitert: `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenz\B01.txt` und `C:\Program Files (x86)\SAP\SAP Business One Server\B1_SHR\Lizenzen\B01.txt` hinzugefügt.
n### v1.6.223 (19. Mai 2026)

- **Windows Agent**: Zusätzlicher Suchpfad für Lizenzfile (B01.txt) hinzugefügt: `C:Program Files (x86)SAPSAP Business One ServerB1_SHRB01.txt`
n### v1.6.222 (19. Mai 2026)

- **DB-Backup Remote-502 Hardening**: Backup-Start auf asynchronen Hintergrundjob umgestellt (schnelle Start-Antwort, kein Proxy-Timeout), Dateidownload auf Chunk-Streaming umgestellt und Status/Fehler-Handling für Backup-Job verbessert.
n### v1.6.221 (19. Mai 2026)

- **DB-Backup One-Shot**: Backup-Download-Jobs werden nach erfolgreichem Download sofort invalidiert und die temporäre Backup-Datei direkt gelöscht (kein stale Job-State).
n### v1.6.220 (19. Mai 2026)

- **DB-Backup Download**: Download-Flow im Admin-Bereich auf Fetch+Blob umgestellt (statt nativer Anchor-Navigation), damit Backup-Dateien zuverlässig vollständig heruntergeladen werden und Fehler sauber erkannt werden.
n### v1.6.219 (19. Mai 2026)

- **Hostkarten UI**: Unterste Reihe mit den drei Infochips (z. B. SAP/HANA/SID) aus der Hostkarte entfernt; Informationen bleiben in anderen Ansichten verfügbar.
n### v1.6.218 (19. Mai 2026)

- **Admin-Markierung SAP B1**: Admin-exklusive Unterpunkte bleiben für Admins sichtbar und werden nun optisch markiert (Badge + Akzent), während sie für Nicht-Admins weiterhin komplett ausgeblendet sind.
n### v1.6.217 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Admin-Unterpunkt 'SAP B1 Setup Roh-Output' wird für Nicht-Admins nun vollständig ausgeblendet (kein Hinweistext, kein Menüpunkt).
n### v1.6.216 (19. Mai 2026)

- **Admin-Sichtbarkeit SAP B1**: Unterpunkt 'SAP B1 Setup Roh-Output' auf Admin-Benutzer eingeschränkt; Nicht-Admins sehen nur einen Hinweistext.
n### v1.6.215 (19. Mai 2026)

- **SAP B1 Lizenzinfos**: Detailinhalte (HW-Key, Installationsnummer, Systemnummer, Kundennummer, Lizenznehmer, Gültigkeit, Datei-Stand) ausgeblendet; angezeigt werden nur noch die zwei SQL/HANA-Suchpfad-Infozeilen.
n### v1.6.214 (18. Mai 2026)

- **pull-server-only**: PNG-Icon-Downloads auf denselben Parallelwert wie Standarddateien umgestellt (MAX_PARALLEL_DOWNLOADS, standardmäßig 8).
- **Hostkarte**: Testweise eingebauten Versionsrückstands-Zahlenchip wieder ersatzlos entfernt.
n### v1.6.213 (18. Mai 2026)

- **Hostkarten Versionsindikator**: Roten Punkt durch runden Zahlen-Chip ersetzt; zeigt den Versionsrückstand (Anzahl Versionen) nur bei Rückstand > 0.
n### v1.6.212 (18. Mai 2026)

- **Hostkarten Layout**: Vertikalen Abstand zwischen Hostbezeichnung und der darunterliegenden IP-/Meta-Zeile reduziert.
n### v1.6.211 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte nochmals deutlich verkleinert (fast ohne Zusatzabstand).
n### v1.6.210 (18. Mai 2026)

- **License Card Spacing**: Abstand zwischen erster und zweiter Spalte leicht reduziert (feineres Tuning).
n### v1.6.209 (18. Mai 2026)

- **License Card Layout-Fix**: Clipboard-Icon aus dem Grid-Flow entfernt und als Floating-Button oben rechts positioniert, damit die Kartenstruktur stabil bleibt.
n### v1.6.208 (18. Mai 2026)

- **License Card Datenlogik**: Lizenzkarte wird strikt nur bei selektiertem Host und vorhandenen Lizenzdaten angezeigt.
- **License Card Layout**: Spaltenabstand in der Lizenzkarte reduziert.
- **Clipboard Komfort**: Neues 📋-Icon kopiert HW-Key, Installationsnummer und Systemnummer in die Zwischenablage.
n### v1.6.207 (18. Mai 2026)

- **License Card Height**: Maximale Hoehe der Lizenzkarte von 150px auf 100px reduziert (overflow-y: auto).
n### v1.6.206 (18. Mai 2026)

- **License Card Position**: Lizenzkarte ins horizontale Zentrum des Headers verschoben; Karteninhalt linksbündig.
n### v1.6.205 (18. Mai 2026)

- **License Card Styling**: Lizenzkarte: Labels kleiner und leichter, Werte extra-fett (800), mehr Spaltenabstand, Inhalte horizontal zentriert.
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

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.168 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.167 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.166 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.165 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.164 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.163 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.162 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.161 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.160 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.159 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.158 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.157 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.156 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.155 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.154 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.153 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

### v1.6.152 (18. Mai 2026)

- **Hostkarten-Gradient vertikal**: Der Farbverlauf in den betroffenen Hostkarten-Kopfbereichen wurde von horizontal auf vertikal umgestellt (Light + Dark Theme).

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

- **Hostkarten-Hintergrund zurueckgesetzt**: Der eigentliche Kartenhintergrund wurde auf den Stand vor der letzten Farbumstellung zurueckgesetzt. Die aktuellen Pillenfarben (Kunde/SAP/HANA/SID) bleiben unveraendert.

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
- **Kundenchip verschoben**: Der Kunden-Chip wurde aus der oberen Titelzeile in die zweite Zeile an die frühere Position der Meldungsanzeige verschoben.

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
- **Benachrichtigungsbereich vereinfacht**: Der Bereich enthaelt nun nur noch Heads-Up-/Inaktiv-Logik und ist dadurch deutlich uebersichtlicher.

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

- **HANA SQL-Port Auto-Detection**: Wenn `HANA_ADDONS_PORT` noch auf Default `30015` steht, erkennt der Linux-Agent die lokale Instanznummer automatisch