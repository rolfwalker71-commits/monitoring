# 📧 Mailversand Prozess

Kurzbeschreibung: Dieser Ablauf beschreibt, wie das System Mails ueber Microsoft Graph versendet (Test, Instant-Alerts, Reminder, Daily Digests, Kundenalarm).

## 🎯 Entry Points

- POST /api/v1/mail-test
- POST /api/v1/mail-test/trends
- POST /api/v1/mail-test/alerts
- POST /api/v1/mail-test/backup
- maybe_send_alert_message -> send_instant_alert_mails_to_users
- maybe_send_alert_reminders
- maybe_send_scheduled_user_mails
- POST /api/v1/customer-alert/test

## 🔄 Hauptfluss

```mermaid
flowchart TD
    A[Mail Trigger] --> B[User Settings + Recipient(s) laden]
    B --> C[OAuth Access Token pruefen/refreshen]
    C --> D{Token verfuegbar?}
    D -->|Nein| E[Abbruch ohne Versand]
    D -->|Ja| F[Subject + HTML/Text Body bauen]
    F --> G{Ein oder mehrere Empfaenger?}
    G -->|Ein| H[send_microsoft_mail]
    G -->|Mehrere| I[send_microsoft_mail_multi]
    H --> J[POST /me/sendMail]
    I --> J
    J --> K{HTTP 2xx?}
    K -->|Ja| L[Erfolg loggen/Status updaten]
    K -->|Nein| M[Fehlerdetails zurueckgeben]
```

## 🧩 Wichtige Entscheidungen

- OAuth ist benutzerbezogen: Versand laeuft immer mit dem verbundenen Konto des Users.
- Alert-Digest kann je nach Schweregrad an unterschiedliche Alert-Empfaenger gehen.
- Instant-Alerts respektieren Host-Subscriptions und Mindest-Schweregrad.
- Scheduled Digests setzen last_sent nur bei erfolgreichem Versand.

## 🛠 Technische Bausteine

- Token und Refresh: ensure_microsoft_access_token
- Einzelempfaenger: send_microsoft_mail
- Mehrfachempfaenger: send_microsoft_mail_multi
- Digest Scheduler: maybe_send_scheduled_user_mails
- Reminder Scheduler: maybe_send_alert_reminders

## ✅ Beobachtbare Ergebnisse

- Erfolgreiche Aufrufe liefern status sent.
- Fehler liefern status failed plus details.
- Bei Daily Digests wird der last_sent Tag nur bei Erfolg fortgeschrieben.
