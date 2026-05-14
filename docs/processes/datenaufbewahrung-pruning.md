# 🧹 Datenaufbewahrung und Pruning

Kurzbeschreibung: Wie Reports pro Host begrenzt werden und welche Auswirkungen auf referenzierende Daten bestehen.

## Kernregel

- MONITORING_MAX_REPORTS_PER_HOST steuert, wie viele Reports pro Host erhalten bleiben.
- Pruning laeuft im Report-Ingest direkt nach dem Insert.

## Ablauf

```mermaid
flowchart TD
    A[Neuer Report INSERT] --> B[prune_reports_for_host]
    B --> C[alte report ids bestimmen]
    C --> D[alerts.report_id fuer alte ids auf NULL]
    D --> E[alte reports loeschen]
    E --> F[neueste Reports bleiben erhalten]
```

## Warum zuerst report_id auf NULL?

Damit Alerts bei Loeschung alter Reports keine ungueltigen Fremdbezuege behalten.

## Auswirkungen

- Trend- und Verlaufsauswertungen nutzen nur verbleibende Reports.
- Alert-Lifecycle bleibt konsistent, auch wenn historische report_id entfaellt.
- Speicherverbrauch bleibt begrenzt und vorhersehbar.
