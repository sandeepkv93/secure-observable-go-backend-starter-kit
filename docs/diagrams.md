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

## Session Device Management Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as API Server
    participant DB as PostgreSQL

    U->>API: GET /api/v1/me/sessions
    API->>DB: List active sessions for authenticated user
    API-->>U: [{id, user_agent, ip, is_current, ...}]
    U->>API: DELETE /api/v1/me/sessions/{session_id}
    API->>DB: Revoke single session by user+session scope
    API-->>U: {status: revoked}
    U->>API: POST /api/v1/me/sessions/revoke-others
    API->>DB: Revoke all except current session
    API-->>U: {revoked_count: N}
```

Source: `docs/diagrams/session-management-flow.mmd`

## Local Email Verification Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as API Server
    participant DB as PostgreSQL
    participant N as Dev Notifier

    U->>API: POST /api/v1/auth/local/register
    API->>DB: Create user + local credential (unverified)
    API-->>U: {requires_verification: true}
    U->>API: POST /api/v1/auth/local/verify/request (email)
    API->>DB: Invalidate prior active verify tokens
    API->>DB: Store hashed one-time token (purpose=email_verify, expires_at)
    API->>N: Send verification link/token
    U->>API: POST /api/v1/auth/local/verify/confirm (token)
    API->>DB: Consume token and mark local credential email_verified
    API-->>U: {status: email_verified}
    U->>API: POST /api/v1/auth/local/login
    API-->>U: Access/refresh cookies
```

Source: `docs/diagrams/email-verification-flow.mmd`

## Local Password Reset Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant API as API Server
    participant DB as PostgreSQL
    participant N as Dev Notifier

    U->>API: POST /api/v1/auth/local/password/forgot (email)
    API->>DB: Resolve user (if exists) without disclosure
    API->>DB: Invalidate active password_reset tokens
    API->>DB: Store hashed one-time token (short TTL)
    API->>N: Send reset link/token
    API-->>U: Generic 200 response

    U->>API: POST /api/v1/auth/local/password/reset (token,new_password)
    API->>DB: Validate active token + consume
    API->>DB: Update password hash
    API->>DB: Revoke all sessions
    API-->>U: Password reset success
```

Source: `docs/diagrams/password-reset-flow.mmd`

## Observability Data Flow

```mermaid
flowchart TD
    API[API + OTel SDK<br/>Metrics/Traces/Logs] --> COL[OTel Collector]
    COL --> MIMIR[Mimir<br/>metrics + exemplars]
    COL --> TEMPO[Tempo<br/>traces]
    COL --> LOKI[Loki<br/>logs]

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
