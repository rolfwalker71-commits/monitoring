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
curl -sSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/linux/install_agent.sh | bash
```

**Windows (PowerShell als Admin):**

```powershell
irm https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/windows/install_agent.ps1 | iex
```

**Windows repair/bootstrap für bestehende Hosts:**

```powershell
& .\bootstrap_agent.ps1 -ServerUrl https://monitoring.rolfwalker.ch -DisableJitter
```

Der Wrapper zieht die aktuellen Windows-Skripte von `/updates`, repariert eine bestehende Installation in place und schaltet Jitter nur für diesen Lauf aus.

### Self-Update

Agents prüfen selbständig (alle ~6 Stunden, plus bei jedem Sammellauf wenn die Version veraltet ist) ob eine neue Version auf GitHub verfügbar ist und aktualisieren sich automatisch. Die aktuelle Agent-Version steht in `AGENT_VERSION`.

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

## Versionierung

- Applikations-Version: `BUILD_VERSION` (semantisch, z. B. `1.1.100`)
- Agent-Version: `AGENT_VERSION` (separat versioniert, z. B. `1.1.48`)
- API-Spec: `openapi.yaml` (OpenAPI 3.0.3, Version folgt BUILD_VERSION)

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

### v1.4.74 (11. Mai 2026)

- **Agent-Quelle Ansicht optisch verdichtet**: kleinere Schrift und kompaktere Zellen fuer mehr Host-Zeilen auf gleicher Hoehe.
- **Breite besser genutzt**: Tabellenlayout der "Agent Quelle"-Seite auf bessere Spaltenverteilung angepasst, weniger abgeschnittene Werte.
- **Lesbarkeit verbessert**: URL-Felder umbrechen nun kontrolliert statt frueh mit Ellipsis zu enden.

### v1.4.73 (11. Mai 2026)

- **agent.conf Migration fuer bestehende Agents**: Linux- und Windows-`self_update` schreiben relevante Source-Keys jetzt aktiv nach (`SERVER_URL`, `UPDATE_BASE_URL`, `RAW_BASE_URL`) und leeren `GITHUB_REPO`.
- **Neue Global-Seite "Agent Quelle"**: Tab mit Host-Tabelle fuer schnellen Umstellungsstatus auf server-only Quelle.
- **Ampel-Checks pro Host**: `SERVER_URL`, `UPDATE_BASE_URL`, `RAW_BASE_URL`, `GITHUB_REPO` werden pro Host ausgewertet; korrekte Werte sind gruen markiert.
- **Neuer API-Endpunkt**: `/api/v1/agent-source-status` liefert den Migrationsstatus aus der letzten gemeldeten `agent.conf` pro Host.

### v1.4.72 (11. Mai 2026)

- **Server-only Quelle fuer Install/Update**: Linux/Windows Update- und Bootstrap-Skripte nutzen jetzt ausschliesslich die konfigurierten Server-Updates (`SERVER_URL/updates` bzw. `UPDATE_BASE_URL`).
- **Kein GitHub-Fallback mehr im Agent-Pfad**: Download-Fallbacks auf `raw.githubusercontent.com`/GitHub wurden aus den Agent-Skripten entfernt.
- **Install-Beispiele angepasst**: Installer-Beispiele verweisen auf die eigene Server-Quelle.

### v1.4.71 (11. Mai 2026)

- **DB-Schema Guard fuer Host-Config**: Der Server stellt vor Host-Config-Tracking/Backfill jetzt runtime-sicher sicher, dass `host_config_snapshot.kernel_release` existiert.
- **Nutzen**: Alte/extern eingespielte DBs ohne neue Spalte brechen nicht mehr bei Host-Config-Operationen.

### v1.4.70 (11. Mai 2026)

- **HANA AddOn-Parser tolerant gemacht**: CSV-Extraktion faellt jetzt bei Mischformaten automatisch auf die Zeilenlogik zurueck, damit echte AddOn-Daten nicht mehr im `parse_failed` landen.
- **Ziel**: die bereits wieder ankommenden Daten auch bei leicht variierendem hdbsql-Output sauber als AddOns erfassen.

### v1.4.69 (11. Mai 2026)

- **1.4.42-Mehrfach-Commit Abgleich umgesetzt**: HANA-Abfragepfad wurde gegen die originale 1.4.42-Kette abgeglichen und robust gemacht.
- **Spaltennamen-Fallbacks fuer heterogene Hosts**: Query-Varianten fuer `Version/VERSION` sowie `AName/ANAME` werden automatisch probiert, um `invalid column name` auf einzelnen Hosts zu vermeiden.
- **Verbindungs-Fallback erweitert**: Bei Connect-Fehlern wird nicht nur der Port, sondern auch Host-Ziele (`127.0.0.1`, `localhost`, Hostname/FQDN) gegen aktive `3xx15`-Listener geprobt.

### v1.4.68 (11. Mai 2026)

- **HANA Query-Regression gefixt**: SQL-Statements werden fuer `su -c` jetzt shell-sicher escaped, damit quoted Identifier wie `"Version"` und `"AName"` korrekt bei hdbsql ankommen.
- **Fehlerbild behoben**: `invalid column name: VERSION/ANAME` durch verlorene Quotes in der Refaktorierung.

### v1.4.67 (11. Mai 2026)

- **Rueckkehr zur 1.4.42-Verbindungsstrategie**: HANA AddOn-Queries nutzen wieder zuerst den impliziten `hdbsql`-Modus (ohne `-n`), wie im frueh stabilen Stand.
- **Fallback bleibt erhalten**: Explizites `target` und lokale `3xx15`-Port-Probe bleiben als nachgelagerter Fallback aktiv.
- **Ziel**: Verhalten wieder an den urspruenglich funktionierenden Ablauf angleichen, ohne die neuen Diagnosepfade zu verlieren.

### v1.4.66 (11. Mai 2026)

- **Connection-Diagnose erweitert**: Bei `query_failed` mit Verbindungsfehler liefert der Agent jetzt zusaetzlich Runtime-Listener-Infos (`listener_target`, `listeners_3xx15`, `sid`) direkt im Fehlertext.
- **Ziel**: sofort sichtbar machen, ob auf dem Host zur Laufzeit wirklich ein SQL-Listener auf `:30015` aktiv ist.

### v1.4.65 (11. Mai 2026)

- **HANA Port-Fallback gehaertet**: SID-Erkennung passiert jetzt vor der SQL-Port-Autodetection, damit Instanz-basierte Ports (`3xx15`) korrekt berechnet werden.
- **Runtime-Probe bei `connection refused`**: Bei lokalem Ziel und fehlschlagendem `30015` testet der Agent automatisch aktive lokale `3xx15`-Ports (via `ss`) und nutzt den funktionierenden Port fuer beide AddOn-Queries.

### v1.4.64 (11. Mai 2026)

- **HANA SQL-Port Auto-Detection**: Wenn `HANA_ADDONS_PORT` noch auf Default `30015` steht, erkennt der Linux-Agent die lokale Instanznummer automatisch (z. B. `HDB90`) und nutzt den passenden SQL-Port (z. B. `39015`).
- **Verbindungs-Fix ohne manuelle Konfig**: Hosts mit abweichender Instanznummer brauchen damit kein manuelles Port-Override mehr fuer AddOn-Queries.

### v1.4.63 (11. Mai 2026)

- **HANA AddOns Regression-Hotfix**: Bei `connection failed` auf explizitem `HANA_ADDONS_HOST:HANA_ADDONS_PORT` faellt der Linux-Agent automatisch auf den frueheren impliziten `hdbsql`-Verbindungsmodus zurueck.
- **Diagnose erweitert**: Payload enthaelt jetzt `target_mode` sowie `mode=lw:...,lg:...` im Fehlertext, damit sichtbar ist, ob der Fallback aktiv war.

### v1.4.62 (11. Mai 2026)

- **Host-Config-Changelog erweitert**: `OS Release` und `Kernel` werden jetzt als eigene Metriken verfolgt und als Aenderungen geloggt.
- **Snapshot-Migration integriert**: Bestehende Datenbanken erhalten das neue Feld `kernel_release` automatisch beim Serverstart.

### v1.4.61 (11. Mai 2026)

- **HANA AddOns Connection-Fix**: `hdbsql` nutzt jetzt ein explizites Ziel (`HANA_ADDONS_HOST:HANA_ADDONS_PORT`) statt implizitem Default `localhost:30015`.
- **Stabilerer Standard**: neue Defaults `HANA_ADDONS_HOST=127.0.0.1`, `HANA_ADDONS_PORT=30015`.
- **Selbstheilung**: `self_update.sh` und `repair_agent_conf.sh` schreiben die neuen Felder automatisch in `agent.conf`.
- **Bessere Diagnose**: `error` enthält jetzt zusätzlich das verwendete `target=...`.

### v1.4.60 (11. Mai 2026)

- **Parse-Failed Diagnose erweitert**: Bei `reason=parse_failed` liefert der Linux-Agent jetzt ein kurzes hdbsql-Snippet (`LW`/`LEG`) im Fehlertext, damit das konkrete Rohformat direkt im UI sichtbar wird.

### v1.4.59 (11. Mai 2026)

- **Linux HANA AddOn Parser erweitert**: Fallback erkennt jetzt zusaetzlich tabellarische (`Mehrfach-Whitespace`) und `;`-getrennte hdbsql-Zeilen.
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
- **Fehlende AddOn-Daten behoben**: Betroffene Hosts mit kombiniertem hdbsql-Feld zeigen AddOn-Aenderungen nicht mehr als zusammengeklebten Namen mit `-` als Version.

### v1.4.49 (11. Mai 2026)

- **Changelog-Backfill sichtbar gemacht**: Der Button nutzt jetzt einen 30-Tage-Backfill und zeigt die resultierende 30d-Sicht direkt an, damit Hosts wie Rinco sofort auftauchen.
- **Changelog-Pfeile bereinigt**: Die nested Summary-Elemente im Changelog blenden den nativen Marker jetzt ebenfalls aus.

### v1.4.48 (11. Mai 2026)

- **Changelog-Backfill per Button**: Im Changelog gibt es jetzt einen Button, der gespeicherte Reports erneut auswertet und `host_config_changes` auffuellt.

### v1.4.47 (11. Mai 2026)

- **HANA AddOns bereinigt**: Der Agent und die UI entfernen jetzt hdbsql-Footer und doppelte Anführungszeichen aus AddOn-Zeilen.

### v1.4.46 (11. Mai 2026)
- **Deploy-Zielpfad robuster (`pull-server-only.sh`)**: Ohne Parameter wird das Ziel jetzt zuerst aus der bestehenden `monitoring.service` (`WorkingDirectory`) uebernommen.
- **Fallback-Logik verbessert**: Wenn keine Unit vorhanden ist, nutzt das Skript den lokalen Repo-Pfad (falls vorhanden) statt blind `$HOME/monitoring-server`.
- **Wirkung**: Verhindert Deploys in ein falsches Verzeichnis bei identischer UI trotz Restart/Reboot.

### v1.4.45 (11. Mai 2026)
- **Deploy-Fix (`pull-server-only.sh`)**: Der Service `monitoring` wird nach dem Update jetzt automatisch neu gestartet.
- **Sichtbarkeits-Fix fuer UI-Updates**: Durch den automatischen Restart greifen neue `receiver.py` Header-/Routing-Aenderungen direkt, statt bis zum manuellen Restart zu warten.

### v1.4.44 (11. Mai 2026)
- **Webclient-Update-Zuverlaessigkeit**: No-Cache Header fuer `app.js`, `styles.css`, `sw.js` und `manifest.json`; Service Worker wird versionsgebunden registriert.
- **Host-Changelog Sichtbarkeit**: HANA AddOns werden beim ersten Auftreten als `addon-init` Eintrag angezeigt (nicht erst bei spaeteren Delta-Aenderungen).
- **Darstellungsstabilitaet**: AddOn-Normalisierung fuer gemischte hdbsql-Formate bleibt erhalten, inklusive sauberer Werte ohne Timing-Footer-Artefakte.

### v1.4.43 (11. Mai 2026)
- **HANA AddOns Parsing verbessert**: Linux-Agent verarbeitet nun sowohl Pipe-Format (`A|B`) als auch CSV-Format (`"A","B"`) von hdbsql robust.
- **UI-Darstellung bereinigt**: Timing-Footer wie `rows selected (overall time...)` werden nicht mehr als AddOn-Zeile dargestellt.
- **Host-Changelog erweitert**: Aenderungen der HANA AddOns fliessen jetzt in die Host-Config-Changes ein (`HANA LW` / `HANA Legacy`) und werden sauber formatiert angezeigt.

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
