# 🔄 Agent Self-Update End-to-End

Kurzbeschreibung: Wie Linux- und Windows-Agenten Updates von /updates beziehen und lokal anwenden.

## Linux Flow

```mermaid
flowchart LR
    A[self_update.sh] --> B[agent.conf laden]
    B --> C[UPDATE_BASE_URL aus SERVER_URL/updates]
    C --> D[Remote AGENT_VERSION/BUILD_VERSION lesen]
    D --> E[collect_and_send.sh + self_update.sh laden]
    E --> F[Dateien nach /opt/monitoring-agent installieren]
    F --> G[AGENT_VERSION schreiben]
    G --> H[Config-Werte migrieren/normalisieren]
```

## Windows Flow

```mermaid
flowchart LR
    A[self_update.ps1] --> B[agent.conf parsen]
    B --> C[Update-Base aus SERVER_URL/updates]
    C --> D[Dateien mit Validierung laden]
    D --> E[collect_and_send.ps1/self_update.ps1 ersetzen]
    E --> F[AGENT_VERSION aktualisieren]
    F --> G[Task-basierter Betrieb laeuft weiter]
```

## Bootstrap-Sonderfall (Windows)

```mermaid
flowchart TD
    A[bootstrap_agent.ps1] --> B{Bestehende Installation + Tasks?}
    B -->|Ja| C[Scripts in place refresh]
    B -->|Nein| D[install_agent.ps1 von /updates ziehen]
    D --> E[Neuinstallation + Tasks]
```

## Kernaussagen

- Update-Quelle ist serverzentrisch auf /updates ausgelegt.
- Linux und Windows aktualisieren Kernskripte in place.
- Bootstrap repariert bestehende Installationen oder installiert neu.
