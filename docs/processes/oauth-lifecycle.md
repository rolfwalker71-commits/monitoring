# 🔐 OAuth Lifecycle (Microsoft)

Kurzbeschreibung: End-to-End Verbindung eines Benutzers mit Microsoft OAuth inklusive Token-Refresh fuer Graph Mailversand.

## Wichtige Endpunkte

- GET /api/v1/oauth/microsoft/start
- GET /oauth/microsoft/callback
- POST /api/v1/oauth-settings
- POST /api/v1/oauth/microsoft/disconnect

## Verbindungsfluss

```mermaid
flowchart LR
    A[User klickt Connect] --> B[/api/v1/oauth/microsoft/start]
    B --> C[create_oauth_state]
    C --> D[Redirect zu Microsoft Authorize URL]
    D --> E[/oauth/microsoft/callback]
    E --> F{state + code gueltig?}
    F -->|Nein| G[oauth_status=error]
    F -->|Ja| H[exchange code for tokens]
    H --> I[upsert_oauth_connection]
    I --> J[oauth_status=success]
```

## Token-Nutzung zur Laufzeit

```mermaid
flowchart TD
    A[Mail Versand angefordert] --> B[ensure_microsoft_access_token]
    B --> C{Token noch gueltig?}
    C -->|Ja| D[send_microsoft_mail(_multi)]
    C -->|Nein| E[refresh_token grant]
    E --> F{Refresh ok?}
    F -->|Nein| G[Versand abbrechen]
    F -->|Ja| D
    D --> H[Graph: POST /me/sendMail]
```

## Hinweise

- OAuth ist benutzerbezogen, nicht global fuer alle User.
- Admin konfiguriert App-Daten, jeder User verbindet sein eigenes Konto.
- Disconnect entfernt die gespeicherte OAuth-Verbindung des Benutzers.
