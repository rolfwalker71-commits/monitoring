# 🎛 Remote-Command Lifecycle

Kurzbeschreibung: Dieser Ablauf beschreibt, wie Befehle fuer Agents gequeued, ausgeliefert, ausgefuehrt und als Resultat zurueckgeschrieben werden.

## Wichtige Endpunkte

- GET /api/v1/agent-commands
- POST /api/v1/agent-command
- POST /api/v1/agent-command-bulk
- POST /api/v1/agent-command-result

## Hauptfluss

```mermaid
flowchart TD
    A[Web User queued command] --> B[queue_agent_command_once]
    B --> C[status=pending, expires_at_utc gesetzt]
    C --> D[Agent pollt /api/v1/agent-commands]
    D --> E[expire_old_agent_commands]
    E --> F[pending commands fuer hostname]
    F --> G[Agent fuehrt lokal aus]
    G --> H[POST /api/v1/agent-command-result]
    H --> I{status completed/failed?}
    I -->|Nein| J[400]
    I -->|Ja| K[agent_commands update]
    K --> L[status + executed_at_utc + result_json]
```

## Sonderregeln

- Doppelte pending Commands werden via queue_agent_command_once verhindert.
- TTL wird begrenzt und abgelaufene Commands werden auf expired gesetzt.
- Bei set-api-key wird command_payload_json nach Rueckmeldung auf {} gesetzt.
- Resultate fuer bereits behandelte Commands werden als ignored beantwortet.

## Datenmodell

- Tabelle: agent_commands
- Kernfelder: command_type, command_payload_json, status, expires_at_utc, executed_at_utc, result_json
