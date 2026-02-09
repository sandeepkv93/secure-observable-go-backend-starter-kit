# Architecture and Flow Diagrams

This document contains Mermaid sources for major repository workflows.
The same diagrams are also summarized in `README.md`.

## System Architecture

```mermaid
flowchart LR
    Client[Client] --> Router[Chi Router + Middleware]
    Router --> Handlers[HTTP Handlers]
    Handlers --> Services[Service Layer]
    Services --> Repos[Repository Layer]
    Repos --> DB[(PostgreSQL)]

    Router -. emits telemetry .-> OTel[OTel SDK]
    OTel --> Collector[OTel Collector]
    Collector --> Tempo[Tempo]
    Collector --> Loki[Loki]
    Collector --> Mimir[Mimir]
    Grafana[Grafana] --> Tempo
    Grafana --> Loki
    Grafana --> Mimir
```

Source: `docs/diagrams/architecture.mmd`

## OAuth Login and Session Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as API Server
    participant G as Google OAuth
    participant DB as PostgreSQL

    U->>API: GET /api/v1/auth/google/login
    API-->>U: Redirect to Google
    U->>G: Consent + login
    G-->>U: Redirect with code
    U->>API: GET /api/v1/auth/google/callback?code=...
    API->>G: Exchange code for tokens/user profile
    API->>DB: Upsert user + oauth account + session
    API-->>U: Set access/refresh cookies + csrf cookie
    U->>API: GET /api/v1/me (cookie auth)
    API->>DB: Resolve session/user
    API-->>U: User profile
```

Source: `docs/diagrams/auth-flow.mmd`

## Observability Data Flow

```mermaid
flowchart TD
    API[API + OTel SDK]\nMetrics/Traces/Logs --> COL[OTel Collector]
    COL --> MIMIR[Mimir\nmetrics + exemplars]
    COL --> TEMPO[Tempo\ntraces]
    COL --> LOKI[Loki\nlogs]

    LOADGEN[cmd/loadgen] --> API
    OBSCHECK[cmd/obscheck] --> GRAFANA[Grafana API]
    GRAFANA --> MIMIR
    GRAFANA --> TEMPO
    GRAFANA --> LOKI
```

Source: `docs/diagrams/observability-flow.mmd`

## CI and Local Quality Gate Flow

```mermaid
flowchart LR
    PR[Push / Pull Request] --> GHA[GitHub Actions CI]
    GHA --> B1[task bazel:build]
    GHA --> B2[task bazel:test]
    GHA --> GZ[task gazelle:check]
    GHA --> TD[task tidy-check]
    GHA --> WR[task wire-check]

    DEV[git push] --> PRE[pre-push hook]
    PRE --> LOCALCI[task ci]
```

Source: `docs/diagrams/ci-flow.mmd`

## Taskfile and Command Entry Flow

```mermaid
flowchart LR
    T[Taskfile.yaml] --> APP[taskfiles/app.yaml]
    T --> BAZEL[taskfiles/bazel.yaml]
    T --> GO[taskfiles/go.yaml]
    T --> OBS[taskfiles/obs.yaml]
    T --> CI[taskfiles/ci.yaml]

    APP --> CMDAPI[cmd/api]
    APP --> CMDMIG[cmd/migrate]
    APP --> CMDSEED[cmd/seed]
    OBS --> CMDLOAD[cmd/loadgen]
    OBS --> CMDOBS[cmd/obscheck]
```

Source: `docs/diagrams/tooling-flow.mmd`
