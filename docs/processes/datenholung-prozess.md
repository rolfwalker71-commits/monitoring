# 📥 Datenholung Prozess (Agent -> Server)

Kurzbeschreibung: Wie Reports und Command-Resultate vom Agent geholt bzw. empfangen werden.

## 🧭 Report Ingest

```mermaid
flowchart LR
    A[Agent sendet POST /api/v1/agent-report] --> B[JSON und Pflichtfelder validieren]
    B --> C[API-Key/Grace pruefen]
    C --> D{authorized?}
    D -->|Nein| E[401/403]
    D -->|Ja| F[Payload anreichern: agent_api_key status]
    F --> G[Weiter in DB-Schreibpipeline]
```

## 🧭 Command Poll/Result

```mermaid
flowchart LR
    A[Agent GET /api/v1/agent-commands] --> B[Pending Command ausliefern]
    B --> C[Agent fuehrt Command lokal aus]
    C --> D[POST /api/v1/agent-command-result]
    D --> E[status completed/failed validieren]
    E --> F[Command Status und Resultat speichern]
```

## 🔍 Validierungen

- hostname muss vorhanden sein.
- filesystems muss ein Array sein.
- command_id und result status muessen gueltig sein.
- Agent-Endpunkte sind von Web-Session-Login ausgenommen, aber durch Agent-Auth geschuetzt.

## 📌 Warum getrennt von DB-Write?

Datenholung beschreibt Transport, Auth und API-Vertrag. Die persistente Verarbeitung steht im separaten Dokument zum DB-Schreiben.
