# ♻️ Backfill Prozess

Kurzbeschreibung: Rekonstruktion historischer Aenderungen aus alten Reports fuer Host-Config-Changes und Database-Lifecycle.

## ▶️ Trigger

- POST /api/v1/host-config-changes/backfill
- Optionales Parameterfeld: days (1..30)

## 🔄 Gesamtfluss

```mermaid
flowchart TD
    A[Admin startet Backfill API] --> B[days validieren]
    B --> C[Reports im Zeitfenster laden]
    C --> D[backfill_host_config_changes]
    C --> E[backfill_database_lifecycle]
    D --> F[Snapshots je Host vergleichen]
    F --> G[Diffs als source=backfill speichern]
    E --> H[DB Inventar je Host reportweise vergleichen]
    H --> I[create/delete Events als backfill speichern]
    G --> J[Ergebnisobjekt bauen]
    I --> J
    J --> K[Response mit counters]
```

## 🧠 Host Config Backfill

- Reihenfolge: pro Host chronologisch nach Report-ID.
- Snapshot pro Report extrahieren.
- Gegen letzten Snapshot vergleichen.
- Signifikante Aenderungen als host_config_changes schreiben.
- Danach host_config_snapshot auf letzten Stand bringen.

## 🗄 Database Lifecycle Backfill

- Reihenfolge: pro Host chronologisch.
- Aktuelles DB-Inventar aus Payload extrahieren.
- Mengenvergleich gegen vorherigen Zustand.
- Neue DB -> create Event, fehlende DB -> delete Event.

## ✅ Output

- reports_scanned
- inserted_changes
- inserted_events
- zusammengesetztes result Objekt in der API-Antwort
