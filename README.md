# Monitoring MVP (Client + Server)

Dieses Projekt ist ein rudimentaerer Start fuer dein Server-Client-Monitoring:

- Linux-Agent sammelt Basisdaten (`hostname`, IPs, Filesysteme, Fuellgrad, Uptime) sowie CPU, RAM, Swap und Netzwerkdaten
- Agent sendet alle `x` Minuten per `cron` an einen HTTP-Webservice
- Agent prueft alle 6 Stunden selbststaendig auf neue Versionen auf GitHub und aktualisiert sich bei Bedarf
- Webservice nimmt Daten entgegen, speichert sie in SQLite und zeigt eine einfache Uebersicht

## Struktur

- `client/collect_and_send.sh`: sammelt Daten und POSTet JSON
- `client/self_update.sh`: prueft GitHub auf neue Agent-Version und aktualisiert lokale Skripte
- `client/install_agent.sh`: Install-Skript fuer Linux (per `curl` nutzbar), schreibt Cronjob
- `server/receiver.py`: einfacher HTTP-Receiver + API + statische Dashboard-Seite
- `server/static/*`: kleine Weboberflaeche

## Server starten

```bash
cd server
python3 receiver.py --host 0.0.0.0 --port 8080
```

Dann im Browser:

- Dashboard: `http://<server-ip>:8080/`
- Health: `http://<server-ip>:8080/health`

Nutzbare API-Endpunkte fuer die Auswertung:

- `GET /api/v1/latest?limit=50` letzte Meldungen global
- `GET /api/v1/hosts?limit=20&offset=0` Hosts gruppiert inkl. Anzahl und Last Seen
- `GET /api/v1/host-reports?hostname=<host>&limit=10&offset=0` Historie pro Host (zum Blaettern)
- `GET /api/v1/analysis?hostname=<host>&hours=24` Aggregation pro Host (Filesystem Min/Max/Avg/Delta)
- `GET /api/v1/alerts-summary?hostname=<host>` offene Alerts (kritisch/warn)
- `GET /api/v1/alerts?hostname=<host>&status=all&limit=15&offset=0` Alert-Historie

Dashboard-Funktionen:

- Host-Gruppierung links
- Blaettern durch Hosts und Host-Meldungen
- Analysebereich mit 24h-Trends je Mountpoint fuer den ausgewaehlten Host
- Analysebereich mit CPU/RAM/Swap-Trends im Zeitfenster
- Alert-Bereich mit offenen Warn/Kritisch-Events und letzter Historie je Host
- Agent-Version pro Host zur Nachverfolgung von Self-Updates

Alert-Schwellwerte (optional per Env am Receiver):

- `MONITORING_WARNING_THRESHOLD` (Default `80`)
- `MONITORING_CRITICAL_THRESHOLD` (Default `90`)

Optional API-Key Schutz aktivieren:

```bash
MONITORING_API_KEY='mein-geheimer-key' python3 receiver.py --host 0.0.0.0 --port 8080
```

## Agent per curl installieren

Auf einem Linux-Client:

```bash
curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/install_agent.sh \
  | sudo bash -s -- --server-url http://<server-ip>:8080 --interval-minutes 15
```

Bei der Installation fragt der Agent interaktiv nach einem sprechenden Anzeigenamen.
Dieser wird im Dashboard als Titel verwendet, waehrend der technische `hostname` weiterhin der wichtige Identifikator bleibt.

Optional kann der Anzeigename auch direkt uebergeben werden:

```bash
curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/install_agent.sh \
  | sudo bash -s -- --server-url http://<server-ip>:8080 --display-name "Vaultwarden Prod" --interval-minutes 15
```

Das Install-Skript versucht zuerst einen Eintrag in `/etc/cron.d/monitoring-agent` anzulegen.
Falls das auf dem Zielsystem nicht verfuegbar ist, wird automatisch ein Eintrag in der `root`-crontab gesetzt.

Eingerichtete Jobs:

- Datensammlung und Versand alle `x` Minuten
- Self-Update Check alle 6 Stunden gegen GitHub `main`

Mit API-Key:

```bash
curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/install_agent.sh \
  | sudo bash -s -- \
    --server-url http://<server-ip>:8080 \
    --api-key mein-geheimer-key \
    --interval-minutes 15
```

  Der Agent uebermittelt bei jedem Report auch seine `agent_version`, damit im Dashboard erkennbar ist, ob ein automatisches Update bereits erfolgt ist.

## Was als naechstes sinnvoll ist

- Token-basierte Agent-Authentifizierung pro Host
- Signierte Payloads (HMAC)
- Alarmierung (z. B. E-Mail), wenn Schwellwerte ueberschritten sind
- Aggregationen und Statistiken (z. B. Trends pro Host)
- Eigene Historien- und Filteransichten im Dashboard
