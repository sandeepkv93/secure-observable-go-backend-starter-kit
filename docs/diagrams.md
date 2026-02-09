# Architecture and Flow Diagrams

This document contains Mermaid sources for major repository workflows.
The same diagrams are also summarized in `README.md`.
For canonical audit event schema and query taxonomy, see `docs/audit-taxonomy.md`.

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

## Admin RBAC Write and Sync Flow

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant API as API Server
    participant DB as PostgreSQL
    participant AUD as Audit Log
    participant MET as OTel Metrics

    A->>API: PATCH /api/v1/admin/roles/{id}
    API->>DB: Validate protected/self-lockout rules + update role/permissions
    API->>AUD: Emit admin.role.updated (before/after summary)
    API->>MET: admin.rbac.mutations{entity=role,action=update,status=*}
    API-->>A: Updated role

    A->>API: POST /api/v1/admin/rbac/sync
    API->>DB: Idempotent seed reconcile
    API->>AUD: Emit admin.rbac.sync (actor + report)
    API->>MET: admin.rbac.mutations{entity=sync,action=sync,status=*}
    API-->>A: {created_permissions, created_roles, bound_permissions, noop}
```

Source: `docs/diagrams/rbac-admin-flow.mmd`

## RBAC Permission Cache Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant MW as RBAC Middleware
    participant R as Permission Resolver
    participant PC as Permission Cache (Redis/In-Memory)
    participant DB as PostgreSQL
    participant H as Protected Handler

    C->>MW: Authenticated request to protected route
    MW->>R: ResolvePermissions(claims.user_id, claims.jti)
    R->>PC: Get(user_id + session_jti)
    alt cache hit
        PC-->>R: permission set
        R-->>MW: permissions
    else cache miss
        R->>DB: Load user roles + permissions
        DB-->>R: permissions
        R->>PC: Set(user_id + session_jti, permissions, ttl=RBAC_PERMISSION_CACHE_TTL)
        R-->>MW: permissions
    end
    MW->>MW: Check required permission
    alt authorized
        MW->>H: Continue
        H-->>C: 2xx response
    else forbidden
        MW-->>C: 403 FORBIDDEN
    end

    Note over H,PC: On RBAC mutations, cache invalidates user or all entries
```

Source: `docs/diagrams/rbac-permission-cache-flow.mmd`

## Idempotency Key Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant API as API + Idempotency MW
    participant S as Store (Redis/DB)
    participant H as Handler

    C->>API: POST/PATCH with Idempotency-Key
    API->>S: Begin(scope,key,fingerprint)
    alt state=new
        API->>H: Execute handler once
        H-->>API: status + body
        API->>S: Complete(scope,key,fingerprint,response)
        API-->>C: Original response
    else state=replay
        S-->>API: Cached status + body
        API-->>C: Replayed response (X-Idempotency-Replayed: true)
    else state=conflict
        API-->>C: 409 CONFLICT
    end
```

Source: `docs/diagrams/idempotency-flow.mmd`

## Admin List Pagination and Filtering Flow

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant API as API Server
    participant DB as PostgreSQL

    A->>API: GET /api/v1/admin/users?page=1&page_size=20&sort_by=created_at&sort_order=desc
    API->>API: Validate page/page_size/sort/filter params
    API->>DB: Apply indexed filters + stable sort + offset/limit
    DB-->>API: items + total count
    API-->>A: {data:{items,pagination}}
```

Source: `docs/diagrams/admin-list-query-flow.mmd`

## Admin List Read-Through Cache Flow

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant API as Admin Handler
    participant C as Admin List Cache (Redis)
    participant DB as PostgreSQL

    A->>API: GET /api/v1/admin/roles?...
    API->>C: Get(namespace=admin.roles.list,key=actor+query)
    alt cache hit
        C-->>API: cached JSON payload
        API-->>A: 200 cached response
    else cache miss
        API->>DB: ListPaged(query)
        DB-->>API: items + pagination
        API->>C: Set(namespace,key,payload,ttl=ADMIN_LIST_CACHE_TTL)
        API-->>A: 200 fresh response
    end

    A->>API: POST/PATCH/DELETE admin RBAC mutation
    API->>C: InvalidateNamespace(affected namespaces)
    API-->>A: mutation response
```

Source: `docs/diagrams/admin-list-cache-flow.mmd`

## Admin List Singleflight Dedupe Flow

```mermaid
sequenceDiagram
    participant A1 as Admin Client 1
    participant A2 as Admin Client 2
    participant API as Admin Handler
    participant SF as singleflight Group
    participant C as Admin List Cache
    participant DB as PostgreSQL

    A1->>API: GET /api/v1/admin/roles?...
    A2->>API: GET /api/v1/admin/roles?...
    API->>C: Cache Get(key)
    C-->>API: miss
    API->>SF: Do(namespace|cacheKey)
    API->>SF: Do(namespace|cacheKey)

    alt leader
        SF->>DB: ListPaged(...)
        DB-->>SF: payload
        SF->>C: Cache Set(key,payload,ttl)
        SF-->>API: payload (leader)
    else shared waiter
        SF-->>API: payload (shared)
    end

    API-->>A1: 200 + payload
    API-->>A2: 200 + same payload
```

Source: `docs/diagrams/admin-list-singleflight-flow.mmd`

## Admin List Conditional ETag Flow

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant API as Admin Handler
    participant C as Admin List Cache
    participant DB as PostgreSQL

    A->>API: GET /api/v1/admin/roles (no If-None-Match)
    API->>C: Get(query-scoped payload)
    alt miss
        API->>DB: Query roles + pagination
        DB-->>API: payload
        API->>C: Set(payload, ttl)
    else hit
        C-->>API: payload
    end
    API->>API: Compute ETag from payload bytes
    API-->>A: 200 + ETag + Cache-Control: private, no-cache + JSON body

    A->>API: GET /api/v1/admin/roles (If-None-Match: previous ETag)
    API->>API: Recompute ETag from current payload
    alt same payload
        API-->>A: 304 Not Modified + ETag
    else changed payload
        API-->>A: 200 + new ETag + JSON body
    end
```

Source: `docs/diagrams/admin-list-etag-flow.mmd`

## Error Negotiation Flow (Envelope vs RFC7807)

```mermaid
sequenceDiagram
    participant C as Client
    participant API as API Handler
    participant RESP as response.Error

    C->>API: Request that fails
    API->>RESP: response.Error(status, code, message, details)
    RESP->>RESP: Inspect Accept header

    alt Accept includes application/problem+json
        RESP-->>C: application/problem+json
        Note over C,RESP: type,title,status,detail,instance,code,request_id
    else Default / application/json
        RESP-->>C: application/json envelope
        Note over C,RESP: success:false,error:{code,message},meta:{request_id,timestamp}
    end
```

Source: `docs/diagrams/problem-details-flow.mmd`

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
    GHA --> RUNALL[bash scripts/ci/run_all.sh]
    GHA --> MIGSMOKE[bash scripts/ci/run_migration_smoke.sh]

    DEV[git push] --> PRE[pre-push hook]
    PRE --> LOCALCI[bash scripts/ci/run_all.sh]
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
