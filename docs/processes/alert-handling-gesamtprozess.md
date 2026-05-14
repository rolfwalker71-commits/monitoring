# 🚨 Alert Handling Gesamtprozess

Kurzbeschreibung: End-to-End Ablauf vom eingehenden Filesystem-Wert bis zu Open/Escalated/Resolved inkl. Mute, Ack, Close und Benachrichtigung.

## 🧭 Ablaufuebersicht

```mermaid
flowchart TD
    A[Neuer Agent Report] --> B[update_alerts_for_report]
    B --> C[Je Mountpoint: hidden/blacklist/mute pruefen]
    C --> D{suppressed?}
    D -->|Ja| E[Offene Alerts resolve + Debounce loeschen]
    D -->|Nein| F[used_percent -> severity]
    F --> G{severity == ok?}
    G -->|Ja| H[Open Alert resolve + resolved Nachricht]
    G -->|Nein| I[Debounce/Hit Count oder Critical Immediate]
    I --> J{Alert starten?}
    J -->|Nein| K[Warten auf naechste Hits]
    J -->|Ja| L{Open Alert vorhanden?}
    L -->|Nein| M[Neuen Alert OPEN anlegen]
    L -->|Ja| N[Alert aktualisieren]
    N --> O{warning -> critical?}
    O -->|Ja| P[ESCALATED Nachricht]
    O -->|Nein| Q[Keine Eskalationsnachricht]
    M --> R[OPEN Nachricht]
    H --> S[Status resolved]
    E --> S
```

## 🔔 Notification Flow

```mermaid
flowchart LR
    A[Event: opened/escalated/resolved] --> B[maybe_send_alert_message]
    B --> C[Global Telegram optional]
    B --> D[Instant Telegram pro User optional]
    B --> E[Instant Mail pro User optional]
    E --> F[Host Subscription + Severity + OAuth + Recipient]
```

## 🧷 Web-Aktionen auf Alerts

- Mute: POST /api/v1/alert-mute
- Unmute: POST /api/v1/alert-unmute
- Ack: POST /api/v1/alert-ack
- Unack: POST /api/v1/alert-unack
- Close: POST /api/v1/alert-close
- Unclose: POST /api/v1/alert-unclose

## 📌 Regeln

- Warning wird debounced (Hit Count + Zeitfenster).
- Critical kann sofort triggern (critical_trigger_immediate).
- Hidden/Blacklisted/Muted Mountpoints erzeugen keine offenen Alerts.
- Nicht mehr gemeldete Mountpoints werden automatisch resolved.
