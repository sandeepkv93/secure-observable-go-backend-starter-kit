# Secure Observable Go Backend Starter Kit

[![CI](https://github.com/sandeepkv93/secure-observable-go-backend-starter-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeepkv93/secure-observable-go-backend-starter-kit/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24.13-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Production-oriented Go backend starter with:

- Google OAuth login
- Cookie-based JWT session flow (access + refresh)
- Session/device management APIs (`/api/v1/me/sessions`)
- RBAC authorization
- OpenTelemetry metrics, traces, and logs
- Local tri-signal stack (Grafana + Tempo + Loki + Mimir + OTel Collector)
- Bazel + Gazelle + Task + Wire development workflow

## What This Repository Provides

- API server in `cmd/api`
- Operational CLIs in `cmd/migrate`, `cmd/seed`, `cmd/loadgen`, `cmd/obscheck`
- Layered internal packages (`internal/*`) with DI composition through Wire
- Docker compose local stack for DB + observability
- CI + local hooks enforcing build/test/generation hygiene

## Repository Layout

```text
.
├── api/                          # OpenAPI spec
├── cmd/
│   ├── api/                      # HTTP server entrypoint
│   ├── migrate/                  # DB migration CLI
│   ├── seed/                     # seed/bootstrap CLI
│   ├── loadgen/                  # traffic generation CLI
│   └── obscheck/                 # observability validation CLI
├── configs/                      # collector, Grafana, Loki, Tempo, Mimir configs
├── internal/
│   ├── app/                      # app container
│   ├── config/                   # env config + validation
│   ├── database/                 # DB open/migrate/seed
│   ├── di/                       # Wire providers and injectors
│   ├── domain/                   # entities/models
│   ├── http/                     # handlers, middleware, router
│   ├── observability/            # OTel setup and instrumentation helpers
│   ├── repository/               # data access layer
│   ├── security/                 # JWT, cookies, hashing, state
│   ├── service/                  # business logic layer
│   └── tools/                    # shared CLI tool logic (Cobra + Bubble Tea)
├── migrations/                   # SQL migrations (bootstrap)
├── docs/                         # architecture and workflow diagrams
├── taskfiles/                    # modular Task definitions
├── test/integration/             # integration tests
├── docker-compose.yml            # local stack
├── Taskfile.yaml                 # root task loader
└── MODULE.bazel / BUILD.bazel    # Bazel and Gazelle config
```

## Architecture Overview

Request path:

1. Chi router + middleware chain (`internal/http/router`)
2. Handler layer (`internal/http/handler`)
3. Service layer (`internal/service`)
4. Repository layer (`internal/repository`)
5. GORM + Postgres (`internal/database`)

Cross-cutting:

- Security middleware for headers, CSRF, request ID, rate limiting
- Structured logging with trace/span correlation fields
- OTel tracing, metrics (with exemplars), and logs export via collector

Dependency Injection:

- Providers and wiring in `internal/di`
- Regenerated via `task wire`
- Checked via `task wire-check`

## Architecture and Flow Visuals

Additional diagrams are available in `docs/diagrams.md`.

### System Architecture

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

### OAuth Login and Session Flow

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

### Session Device Management Flow

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

### Local Email Verification Flow

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

### Observability Data Flow

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

## Prerequisites

- Go `1.24.13`
- [Task](https://taskfile.dev/)
- [Bazelisk](https://github.com/bazelbuild/bazelisk)
- Docker and Docker Compose (for local stack)

## Taskfile Organization

Root `Taskfile.yaml` includes modular files with `flatten: true`:

- `taskfiles/app.yaml`
- `taskfiles/bazel.yaml`
- `taskfiles/go.yaml`
- `taskfiles/obs.yaml`
- `taskfiles/security.yaml`
- `taskfiles/ci.yaml`

Your command surface stays simple, for example:

- `task run`
- `task ci`
- `task bazel:build`
- `task migrate`
- `task migrate:smoke`
- `task obs-validate`
- `task test:auth-lifecycle`
- `task test:session-management`
- `task test:email-verification`
- `task test:password-reset`
- `task test:admin-rbac-write`
- `task test:admin-list`
- `task test:problem-details`
- `task test:idempotency`
- `task test:audit`
- `task security`

## Auth Lifecycle Integration Tests

The repo now includes end-to-end auth lifecycle integration coverage in `test/integration/auth_lifecycle_test.go`.

Run only lifecycle tests:

- `task test:auth-lifecycle`

Run only session management tests:

- `task test:session-management`

Run only email verification tests:

- `task test:email-verification`

Run only password reset tests:

- `task test:password-reset`

Run only RBAC write API tests:

- `task test:admin-rbac-write`

Run only admin list pagination/filter/sort tests:

- `task test:admin-list`

Run only problem-details negotiation tests:

- `task test:problem-details`

Run all tests:

- `task test`

## Quickstart

1. Create environment file:
   - `cp .env.example .env`
2. Fill required secrets and OAuth values in `.env`.
3. Run local dependencies:
   - `task docker-up`
4. Apply schema:
   - `task migrate`
5. Run API:
   - `task run`
6. Open API and observability endpoints:
   - API: `http://localhost:8080`
   - Grafana: `http://localhost:3000` (`admin/admin`)

## Configuration

Configuration is loaded and validated in `internal/config/config.go`.

## Required Environment Variables

- `DATABASE_URL`
- `JWT_ACCESS_SECRET` (>= 32 chars)
- `JWT_REFRESH_SECRET` (>= 32 chars and different from access secret)
- `REFRESH_TOKEN_PEPPER` (>= 16 chars)
- `OAUTH_STATE_SECRET` (>= 16 chars)
- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`

## Common Optional Environment Variables

- `APP_ENV` (default `development`)
- `HTTP_PORT` (default `8080`)
- `GOOGLE_OAUTH_REDIRECT_URL` (default callback URL)
- `AUTH_LOCAL_REQUIRE_EMAIL_VERIFICATION` (default `false`)
- `AUTH_EMAIL_VERIFY_TOKEN_TTL` (default `30m`)
- `AUTH_EMAIL_VERIFY_BASE_URL` (optional frontend verify URL)
- `AUTH_PASSWORD_RESET_TOKEN_TTL` (default `15m`)
- `AUTH_PASSWORD_RESET_BASE_URL` (optional frontend reset URL)
- `AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_MIN` (default `5`)
- `BOOTSTRAP_ADMIN_EMAIL`
- `RBAC_PROTECTED_ROLES` (default `admin,user`)
- `RBAC_PROTECTED_PERMISSIONS` (default includes core admin permissions)
- `AUTH_RATE_LIMIT_PER_MIN` (default `30`)
- `API_RATE_LIMIT_PER_MIN` (default `120`)
- `RATE_LIMIT_REDIS_ENABLED` (default `true`)
- `IDEMPOTENCY_ENABLED` (default `true`)
- `IDEMPOTENCY_REDIS_ENABLED` (default `true`, falls back to DB store when disabled)
- `IDEMPOTENCY_TTL` (default `24h`)
- `ADMIN_LIST_CACHE_ENABLED` (default `true`)
- `ADMIN_LIST_CACHE_TTL` (default `30s`)
- `REDIS_ADDR`, `REDIS_PASSWORD`, `REDIS_DB`, `RATE_LIMIT_REDIS_PREFIX`
- `IDEMPOTENCY_REDIS_PREFIX` (default `idem`)
- `ADMIN_LIST_CACHE_REDIS_PREFIX` (default `admin_list_cache`)
- `READINESS_PROBE_TIMEOUT` (default `1s`)
- `SERVER_START_GRACE_PERIOD` (default `2s`)
- `SHUTDOWN_TIMEOUT` (default `20s`)
- `SHUTDOWN_HTTP_DRAIN_TIMEOUT` (default `10s`)
- `SHUTDOWN_OBSERVABILITY_TIMEOUT` (default `8s`)
- `COOKIE_DOMAIN`, `COOKIE_SECURE`, `COOKIE_SAMESITE`
- `CORS_ALLOWED_ORIGINS`

OTel:

- `OTEL_SERVICE_NAME`
- `OTEL_ENVIRONMENT`
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_INSECURE`
- `OTEL_METRICS_ENABLED`
- `OTEL_TRACING_ENABLED`
- `OTEL_LOGS_ENABLED`
- `OTEL_METRICS_EXPORT_INTERVAL`
- `OTEL_TRACE_SAMPLING_RATIO`
- `OTEL_LOG_LEVEL`

## `.env.example` Service Naming

`.env.example` is aligned with current defaults and uses:
- `JWT_ISSUER=secure-observable-go-backend-starter-kit`
- `JWT_AUDIENCE=secure-observable-go-backend-starter-kit-api`
- `OTEL_SERVICE_NAME=secure-observable-go-backend-starter-kit`

## Production Hardening

- Graceful shutdown uses phased timeouts:
- `SHUTDOWN_HTTP_DRAIN_TIMEOUT` for HTTP server drain.
- `SHUTDOWN_OBSERVABILITY_TIMEOUT` for OTel provider shutdown.
- `SHUTDOWN_TIMEOUT` as total ceiling.
- Readiness is dependency-backed (`/health/ready`) and checks DB and Redis with `READINESS_PROBE_TIMEOUT`.
- Startup grace can be controlled via `SERVER_START_GRACE_PERIOD`; during grace, readiness returns unready.
- Config enforces stricter production/staging rules:
- secure cookies (`COOKIE_SECURE=true`)
- restricted samesite (`lax` or `strict`)
- Redis-backed rate limiting enabled
- non-loopback Redis address
- bounded sampling ratio (`OTEL_TRACE_SAMPLING_RATIO <= 0.2`)
- non-placeholder secrets

## API Surface

Key routes are in `internal/http/router/router.go`.

Public/health:

- `GET /health/live`
- `GET /health/ready`

Auth:

- `GET /api/v1/auth/google/login`
- `GET /api/v1/auth/google/callback`
- `POST /api/v1/auth/local/register` (requires `Idempotency-Key`)
- `POST /api/v1/auth/local/login`
- `POST /api/v1/auth/local/verify/request`
- `POST /api/v1/auth/local/verify/confirm`
- `POST /api/v1/auth/local/password/forgot` (requires `Idempotency-Key`)
- `POST /api/v1/auth/local/password/reset`
- `POST /api/v1/auth/local/change-password` (auth + CSRF required)
- `POST /api/v1/auth/refresh` (CSRF required)
- `POST /api/v1/auth/logout` (auth + CSRF required)

User:

- `GET /api/v1/me` (auth required)
- `GET /api/v1/me/sessions` (auth required)
- `DELETE /api/v1/me/sessions/{session_id}` (auth + CSRF required)
- `POST /api/v1/me/sessions/revoke-others` (auth + CSRF required)

Admin (auth + permission checks):

- `GET /api/v1/admin/users` (`users:read`, supports `page,page_size,sort_by,sort_order,email,status,role`)
- `PATCH /api/v1/admin/users/{id}/roles` (`users:write`, requires `Idempotency-Key`)
- `GET /api/v1/admin/roles` (`roles:read`, supports `page,page_size,sort_by,sort_order,name`)
- `POST /api/v1/admin/roles` (`roles:write`, requires `Idempotency-Key`)
- `PATCH /api/v1/admin/roles/{id}` (`roles:write`)
- `DELETE /api/v1/admin/roles/{id}` (`roles:write`)
- `GET /api/v1/admin/permissions` (`permissions:read`, supports `page,page_size,sort_by,sort_order,resource,action`)
- `POST /api/v1/admin/permissions` (`permissions:write`)
- `PATCH /api/v1/admin/permissions/{id}` (`permissions:write`)
- `DELETE /api/v1/admin/permissions/{id}` (`permissions:write`)
- `POST /api/v1/admin/rbac/sync` (`roles:write`)

OpenAPI spec:

- `api/openapi.yaml`

## Security Model

- Access/refresh tokens are managed via secure HTTP-only cookies.
- CSRF token validation is enforced for mutating cookie-auth endpoints.
- Request IDs are attached through middleware for log correlation.
- RBAC is permission-based and enforced in route middleware.
- Auth and API endpoints use separate fixed-window rate limiters.
- Scoped mutating endpoints enforce idempotency keys with replay/conflict semantics (`Idempotency-Key`).
- Admin list endpoints (`/admin/users`, `/admin/roles`, `/admin/permissions`) use read-through Redis cache with actor-scoped query keys and short TTL.
- RBAC/admin mutations invalidate affected admin list cache namespaces to prevent stale list responses.

## Admin List Cache Policy

- Key shape: `namespace + actor_user_id + normalized_query_params`
- Default TTL: `30s` (`ADMIN_LIST_CACHE_TTL`)
- Namespaces:
  - `admin.users.list`
  - `admin.roles.list`
  - `admin.permissions.list`
- Invalidation matrix:
  - `PATCH /admin/users/{id}/roles` -> `admin.users.list`
  - `POST/PATCH/DELETE /admin/roles/{id?}` -> `admin.roles.list`, `admin.users.list`
  - `POST/PATCH/DELETE /admin/permissions/{id?}` -> `admin.permissions.list`, `admin.roles.list`
  - `POST /admin/rbac/sync` -> all three namespaces

## Audit Taxonomy

- Audit logs now use a typed per-route schema with stable keys:
- `event_name,event_version,actor_user_id,actor_ip,target_type,target_id,action,outcome,reason,request_id,trace_id,span_id,ts`
- Event catalog and query examples are documented in:
- `docs/audit-taxonomy.md`

## Error Negotiation

- Default error format remains the existing JSON envelope:
- `Content-Type: application/json`
- Body shape: `{success:false,error:{code,message,details?},meta:{request_id,timestamp}}`
- Clients can request RFC7807 problem details with:
- `Accept: application/problem+json`
- Problem response fields:
- `type,title,status,detail,instance,code,request_id`

## Command-Line Tools (`cmd/*`)

All tools use Cobra and default to TUI output via Bubble Tea/Lip Gloss.
Use `--ci` for non-interactive JSON output.

Detailed command docs now live next to each command:
- API server: `cmd/api/README.md`
- Migration CLI: `cmd/migrate/README.md`
- Seed CLI: `cmd/seed/README.md`
- Load generation CLI: `cmd/loadgen/README.md`
- Observability validation CLI: `cmd/obscheck/README.md`

Quick examples:

```bash
go run ./cmd/api
go run ./cmd/migrate status --ci
go run ./cmd/seed dry-run --ci
go run ./cmd/loadgen run --profile mixed --duration 10s --ci
go run ./cmd/obscheck run --ci
```

## Task Reference

App/runtime:

- `task run`
- `task migrate`
- `task migrate:smoke`
- `task migrate:status`
- `task migrate:plan`
- `task seed`
- `task seed:dry-run`
- `task seed:verify-local-email`
- `task docker-up`
- `task docker-down`

Bazel:

- `task bazel:build`
- `task bazel:test`
- `task bazel:run`
- `task gazelle`
- `task gazelle:check`

Go checks:

- `task test`
- `task lint`
- `task tidy-check`
- `task wire`
- `task wire-check`
- `task cli:smoke`

Observability:

- `task obs-generate-traffic`
- `task obs-validate`

Quality gate:

- `task ci`
- `task security`

## Build and Test Strategy

Bazel-first workflow:

- Build all: `task bazel:build`
- Test all Bazel tests: `task bazel:test`

Go-native checks:

- `task test`
- `task lint`

Generation checks:

- `task gazelle:check`
- `task wire-check`
- `task tidy-check`

Pinned versions:

- Go toolchain pinned to `1.24.13` in `go.mod` and Bazel module setup.

## CI Pipeline

GitHub Actions workflow: `.github/workflows/ci.yml`
Direct CI command scripts: `scripts/ci/run_all.sh`, `scripts/ci/run_migration_smoke.sh`

Pipeline steps:

1. Checkout
2. Setup Go from `go.mod`
3. Setup Bazelisk
4. Run `bash scripts/ci/run_all.sh`
5. Run migration smoke job (`bash scripts/ci/run_migration_smoke.sh`) against CI Postgres service

## Git Hooks

Install repository hooks:

- `task hooks-install`

Hooks:

- `.githooks/pre-commit`
  - formats staged `.go` files with `gofmt`
  - runs `go mod tidy`
- `.githooks/pre-push`
  - runs `bash scripts/ci/run_all.sh`

## Local Observability Stack

`docker-compose.yml` starts:

- Postgres
- OTel Collector
- Tempo
- Loki
- Mimir
- Grafana
- API

Ports:

- API: `8080`
- Grafana: `3000`
- Tempo: `3200`
- Loki: `3100`
- Mimir: `9009`
- Collector OTLP gRPC: `4317`
- Collector OTLP HTTP: `4318`
- Collector health: `13133`

Validation flow:

- `task obs-generate-traffic`
- `task obs-validate`

The validation command checks:

- metric exemplar exists
- trace retrievable in Tempo
- correlated trace log retrievable in Loki

## Troubleshooting

### App fails to start with config validation errors

- Check required env vars in `.env`.
- Ensure secret lengths satisfy validation rules.

### Bazel/Gazelle check fails

- Run:
  - `task gazelle`
  - `task tidy-check`
  - `task wire-check`

### `obs-validate` fails with no trace/log correlation

- Ensure stack is up: `task docker-up`
- Confirm Grafana auth (`admin/admin` unless changed)
- Re-run with fresh traffic:
  - `task obs-generate-traffic`
  - `task obs-validate`

### OAuth callback issues

- Verify Google OAuth app redirect URI exactly matches:
  - `http://localhost:8080/api/v1/auth/google/callback`

## License

MIT License. See `LICENSE`.

Copyright (c) Sandeep Vishnu.
