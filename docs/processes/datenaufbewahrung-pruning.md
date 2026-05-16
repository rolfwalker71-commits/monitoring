# 🧹 Datenaufbewahrung und Pruning

Kurzbeschreibung: Wie Reports pro Host begrenzt werden und welche Auswirkungen auf referenzierende Daten bestehen.

## Kernregel

- MONITORING_REPORT_RETENTION_DAYS steuert die zeitliche Aufbewahrung der Einzelmeldungen pro Host (Standard: 42 Tage = 6 Wochen).
- MONITORING_MAX_REPORTS_PER_HOST ist optional als zusaetzliche Obergrenze aktiv (0 = deaktiviert).
- Pruning laeuft im Report-Ingest direkt nach dem Insert.

## Ablauf

```mermaid
flowchart TD
    A[Neuer Report INSERT] --> B[prune_reports_for_host]
    B --> C[cutoff auf jetzt minus Retention-Tage]
    C --> D[alerts.report_id fuer ablaufende ids auf NULL]
    D --> E[reports aelter als cutoff loeschen]
    E --> F{optional count cap aktiv?}
    F -->|ja| G[zusaetzlich auf keep_count kuerzen]
    F -->|nein| H[neueste Reports innerhalb Retention bleiben erhalten]
    G --> H
```

## Warum zuerst report_id auf NULL?

Damit Alerts bei Loeschung alter Reports keine ungueltigen Fremdbezuege behalten.

## Auswirkungen

- Trend- und Verlaufsauswertungen nutzen nur verbleibende Reports.
- Alert-Lifecycle bleibt konsistent, auch wenn historische report_id entfaellt.
- Speicherverbrauch bleibt begrenzt und vorhersehbar.
