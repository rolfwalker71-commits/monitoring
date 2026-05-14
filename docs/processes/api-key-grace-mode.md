# 🛡 API-Key und Grace-Mode

Kurzbeschreibung: Authentisierung fuer Agent-Endpunkte mit optionalem Grace-Modus fuer bekannte Hosts.

## Entscheidungslogik

```mermaid
flowchart TD
    A[Request auf Agent-Endpoint] --> B{Server API_KEY gesetzt?}
    B -->|Nein| C[zulassen]
    B -->|Ja| D[X-Api-Key == API_KEY?]
    D -->|Ja| C
    D -->|Nein| E{kein Key + hostname + Grace aktiv?}
    E -->|Nein| F[401 invalid api key]
    E -->|Ja| G{hostname bekannt?}
    G -->|Ja| C
    G -->|Nein| F
```

## Betroffene Endpunkte

- POST /api/v1/agent-report
- GET /api/v1/agent-commands
- POST /api/v1/agent-command-result

## Wichtige Parameter

- API_KEY
- MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS

## Zweck des Grace-Modus

- Ermoeglicht Weiterbetrieb bereits bekannter Hosts waehrend Key-Rotation.
- Neue/unbekannte Hosts bleiben ohne gueltigen Key blockiert.
