# 🗃️ Schreiben in die Datenbank

Kurzbeschreibung: Was nach einem gueltigen Agent-Report in SQLite geschrieben und aktualisiert wird.

## 🔄 Schreibpipeline nach /agent-report

```mermaid
flowchart TD
    A[Gueltiger Report] --> B[INSERT reports]
    B --> C[_track_host_config_changes]
    C --> D[_track_database_lifecycle]
    D --> E[prune_reports_for_host]
    E --> F{Host hidden?}
    F -->|Ja| G[resolve_open_alerts_for_host]
    F -->|Nein| H[update_alerts_for_report]
    H --> I[maybe_send_alert_reminders]
    I --> J[maybe_send_scheduled_user_mails]
    G --> I
    J --> K[COMMIT]
```

## 🧩 Haupttabellen

- reports: Rohpayload pro Empfang
- alerts: aktiver/aufgeloester Alert-Status je Mountpoint
- alert_debounce: Warning Debounce Zustand
- host_config_changes + host_config_snapshot: Konfig-Aenderungen
- database_lifecycle: create/delete Events fuer DB-Inventar
- agent_commands: Queue und Ausfuehrungsstatus von Remote-Commands

## 🧹 Datenhygiene

- Reports werden pro Host auf MAX_REPORTS_PER_HOST begrenzt.
- Beim Prune werden report_id Referenzen in alerts vorher auf NULL gesetzt.
- Aufloesungen fuer alte/open Alerts laufen automatisch im Reportfluss.

## ✅ Transaktionale Sicht

Alle Schritte laufen innerhalb einer SQLite-Transaktion und werden am Ende gemeinsam committed.
