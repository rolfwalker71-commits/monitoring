# Monitoring MVP (Client + Server)

Dieses Projekt ist ein rudimentaerer Start fuer dein Server-Client-Monitoring:

- Linux-Agent sammelt Basisdaten (`hostname`, IPs, Filesysteme, Fuellgrad, Uptime)
- Agent sendet alle `x` Minuten per `cron` an einen HTTP-Webservice
- Webservice nimmt Daten entgegen, speichert sie in SQLite und zeigt eine einfache Uebersicht

## Struktur

- `client/collect_and_send.sh`: sammelt Daten und POSTet JSON
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

Dashboard-Funktionen:

- Host-Gruppierung links
- Blaettern durch Hosts und Host-Meldungen
- Analysebereich mit 24h-Trends je Mountpoint fuer den ausgewaehlten Host

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

Das Install-Skript versucht zuerst einen Eintrag in `/etc/cron.d/monitoring-agent` anzulegen.
Falls das auf dem Zielsystem nicht verfuegbar ist, wird automatisch ein Eintrag in der `root`-crontab gesetzt.

Mit API-Key:

```bash
curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/install_agent.sh \
  | sudo bash -s -- \
    --server-url http://<server-ip>:8080 \
    --api-key mein-geheimer-key \
    --interval-minutes 15
```

## Was als naechstes sinnvoll ist

- Token-basierte Agent-Authentifizierung pro Host
- Signierte Payloads (HMAC)
- Alarmierung (z. B. E-Mail), wenn Schwellwerte ueberschritten sind
- Aggregationen und Statistiken (z. B. Trends pro Host)
- Eigene Historien- und Filteransichten im Dashboard
