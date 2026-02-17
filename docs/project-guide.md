# Project Guide

Detailed operational and development reference for this repository.

For product overview and architecture summary, see `README.md`.
For architecture and flow diagrams, see `docs/diagrams.md`.

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

## Prerequisites

- Go `1.26.0`
- [Task](https://taskfile.dev/)
- [Bazelisk](https://github.com/bazelbuild/bazelisk) (uses Bazel `9.0.0` from `.bazelversion`)
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
- `task test:admin-list-cache`
- `task test:admin-list-singleflight`
- `task test:admin-list-etag`
- `task test:rbac-permission-cache`
- `task test:negative-lookup-cache`
- `task test:forgot-rate-limiter`
- `task test:problem-details`
- `task test:idempotency`
- `task test:redis-race`
- `task test:audit`
- `task security`
- `task integration:reset-db`
- `task integration:backup-db`
- `task integration:restore-db FILE=backups/backup_<timestamp>.sql`

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

Run only admin list conditional ETag tests:

- `task test:admin-list-etag`

Run only admin list singleflight dedupe tests:

- `task test:admin-list-singleflight`

Run only RBAC permission cache tests:

- `task test:rbac-permission-cache`

Run only negative lookup cache store tests:

- `task test:negative-lookup-cache`

Run only forgot-password distributed limiter wiring tests:

- `task test:forgot-rate-limiter`

Run only problem-details negotiation tests:

- `task test:problem-details`

Run only Redis race/replay integration tests (requires Docker):

- `task test:redis-race`

Run all tests:

- `task test`

## Local Postgres Snapshot Workflows

Use these commands when your local DB state is corrupted or when you need to share/replay data snapshots.
They rely on Docker Compose service `db` and its managed data volume.

- Reset DB container + data volume and start fresh Postgres:
  - `task integration:reset-db`
- Backup DB to SQL file (default location: `backups/backup_<timestamp>.sql`):
  - `task integration:backup-db`
  - Optional custom output: `task integration:backup-db FILE=backups/my_snapshot.sql`
- Restore DB from SQL file:
  - `task integration:restore-db FILE=backups/backup_<timestamp>.sql`

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
- `RATE_LIMIT_LOGIN_PER_MIN` (default `20`)
- `RATE_LIMIT_REFRESH_PER_MIN` (default `30`)
- `RATE_LIMIT_ADMIN_WRITE_PER_MIN` (default `30`)
- `RATE_LIMIT_ADMIN_SYNC_PER_MIN` (default `10`)
- `RATE_LIMIT_BURST_MULTIPLIER` (default `1.5`, minimum `1`)
- `RATE_LIMIT_SUSTAINED_WINDOW` (default `1m`)
- `RATE_LIMIT_REDIS_ENABLED` (default `true`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_API` (default `fail_open`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_AUTH` (default `fail_closed`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_FORGOT` (default `fail_closed`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_LOGIN` (default `fail_closed`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_REFRESH` (default `fail_closed`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_ADMIN_WRITE` (default `fail_closed`, options: `fail_open|fail_closed`)
- `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_ADMIN_SYNC` (default `fail_closed`, options: `fail_open|fail_closed`)
- `AUTH_ABUSE_PROTECTION_ENABLED` (default `true`)
- `AUTH_ABUSE_FREE_ATTEMPTS` (default `3`)
- `AUTH_ABUSE_BASE_DELAY` (default `2s`)
- `AUTH_ABUSE_MULTIPLIER` (default `2.0`)
- `AUTH_ABUSE_MAX_DELAY` (default `5m`)
- `AUTH_ABUSE_RESET_WINDOW` (default `30m`)
- `AUTH_BYPASS_INTERNAL_PROBES` (default `true`; bypasses limiter/abuse checks for `/health/live` and `/health/ready`)
- `AUTH_BYPASS_TRUSTED_ACTORS` (default `false`; requires trusted CIDRs and/or subjects)
- `AUTH_BYPASS_TRUSTED_ACTOR_CIDRS` (CSV CIDRs, default empty)
- `AUTH_BYPASS_TRUSTED_ACTOR_SUBJECTS` (CSV JWT subject IDs, default empty)
- `IDEMPOTENCY_ENABLED` (default `true`)
- `IDEMPOTENCY_REDIS_ENABLED` (default `true`, falls back to DB store when disabled)
- `IDEMPOTENCY_TTL` (default `24h`)
- `IDEMPOTENCY_DB_CLEANUP_ENABLED` (default `true`; applies only to DB fallback store)
- `IDEMPOTENCY_DB_CLEANUP_INTERVAL` (default `5m`; applies only to DB fallback store)
- `IDEMPOTENCY_DB_CLEANUP_BATCH_SIZE` (default `500`; applies only to DB fallback store)
- `ADMIN_LIST_CACHE_ENABLED` (default `true`)
- `ADMIN_LIST_CACHE_TTL` (default `30s`)
- `NEGATIVE_LOOKUP_CACHE_ENABLED` (default `true`)
- `NEGATIVE_LOOKUP_CACHE_TTL` (default `15s`)
- `RBAC_PERMISSION_CACHE_ENABLED` (default `true`)
- `RBAC_PERMISSION_CACHE_TTL` (default `5m`)
- `REDIS_KEY_NAMESPACE` (default `v1`; prepended to Redis feature prefixes, e.g. `v1:rl:*`, `v1:idem:*`)
- `REDIS_ADDR`, `REDIS_USERNAME`, `REDIS_PASSWORD`, `REDIS_DB`, `RATE_LIMIT_REDIS_PREFIX`, `AUTH_ABUSE_REDIS_PREFIX`
- `REDIS_TLS_ENABLED` (default `false`)
- `REDIS_TLS_SERVER_NAME` (required in non-local env when Redis-backed features are enabled)
- `REDIS_TLS_CA_CERT_FILE` (optional PEM CA bundle path)
- `REDIS_TLS_INSECURE_SKIP_VERIFY` (default `false`, blocked in non-local env)
- `REDIS_DIAL_TIMEOUT` (default `5s`)
- `REDIS_READ_TIMEOUT` (default `3s`)
- `REDIS_WRITE_TIMEOUT` (default `3s`)
- `REDIS_MAX_RETRIES` (default `3`, allowed `-1..20`)
- `REDIS_MIN_RETRY_BACKOFF` (default `8ms`)
- `REDIS_MAX_RETRY_BACKOFF` (default `512ms`)
- `REDIS_POOL_SIZE` (default `10`)
- `REDIS_MIN_IDLE_CONNS` (default `2`)
- `REDIS_POOL_TIMEOUT` (default `4s`)
- `IDEMPOTENCY_REDIS_PREFIX` (default `idem`)
- `ADMIN_LIST_CACHE_REDIS_PREFIX` (default `admin_list_cache`)
- `NEGATIVE_LOOKUP_CACHE_REDIS_PREFIX` (default `negative_lookup_cache`)
- `RBAC_PERMISSION_CACHE_REDIS_PREFIX` (default `rbac_perm`)
- `READINESS_PROBE_TIMEOUT` (default `1s`)
- `SERVER_START_GRACE_PERIOD` (default `2s`)
- `SHUTDOWN_TIMEOUT` (default `20s`)
- `SHUTDOWN_HTTP_DRAIN_TIMEOUT` (default `10s`)
- `SHUTDOWN_OBSERVABILITY_TIMEOUT` (default `8s`)
- `COOKIE_DOMAIN`, `COOKIE_SECURE`, `COOKIE_SAMESITE`
- `CORS_ALLOWED_ORIGINS`
- `MINIO_ENDPOINT` (default `localhost:9000`)
- `MINIO_ACCESS_KEY` (required for production profile)
- `MINIO_SECRET_KEY` (required for production profile)
- `MINIO_BUCKET_NAME` (default `avatars`)
- `MINIO_USE_SSL` (default `false`)

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
- `JWT_ISSUER=everything-backend-starter-kit`
- `JWT_AUDIENCE=everything-backend-starter-kit-api`
- `OTEL_SERVICE_NAME=everything-backend-starter-kit`

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
- Redis ACL and TLS are enforced for non-local environments (`REDIS_USERNAME`, `REDIS_PASSWORD`, `REDIS_TLS_ENABLED=true`, `REDIS_TLS_SERVER_NAME`)
- sensitive Redis outage policies are fail-closed in production/staging (`RATE_LIMIT_REDIS_OUTAGE_POLICY_AUTH`, `RATE_LIMIT_REDIS_OUTAGE_POLICY_FORGOT`, `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_LOGIN`, `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_ADMIN_WRITE`, `RATE_LIMIT_REDIS_OUTAGE_POLICY_ROUTE_ADMIN_SYNC`)
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
- `POST /api/v1/me/avatar` (auth + CSRF required, max 6MB body, accepts JPEG/PNG only)
- `DELETE /api/v1/me/avatar` (auth + CSRF required)

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
- RBAC permission checks use a short-lived user/session cache with invalidation on RBAC mutations.
- Auth and API endpoints use hybrid token-bucket + sliding-window rate limiters.
- Redis outage behavior for rate limiting is configurable per scope (`api`, `auth`, `forgot`, `route_login`, `route_refresh`, `route_admin_write`, `route_admin_sync`) via `RATE_LIMIT_REDIS_OUTAGE_POLICY_*`.
- Rate-limited responses include `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` response headers.
- Route policy map applies endpoint-specific sustained limits with burst capacity for:
  - login (`/api/v1/auth/local/login`)
  - refresh (`/api/v1/auth/refresh`)
  - admin writes (`PATCH /admin/users/{id}/roles`, role/permission write routes)
  - RBAC sync (`POST /api/v1/admin/rbac/sync`)
- Local auth abuse controls apply exponential cooldown per normalized identity (email) and per client IP for:
  - local login failures (`POST /api/v1/auth/local/login`)
  - password forgot requests (`POST /api/v1/auth/local/password/forgot`)
- Internal health probes (`/health/live`, `/health/ready`) can bypass limiter and abuse checks when `AUTH_BYPASS_INTERNAL_PROBES=true`.
- Trusted system actors can bypass limiter/abuse checks via explicit allowlist on CIDR and/or JWT subject (`AUTH_BYPASS_TRUSTED_ACTORS=true` with trusted values configured).
- Redis-backed features use namespaced versioned keys (`REDIS_KEY_NAMESPACE`, default `v1`) to support safe key schema evolution.
- API limiter keys authenticated requests by access-token subject (`sub:<user_id>`) and falls back to client IP when no valid access token is present.
- Forgot-password rate limiting is Redis-distributed when `RATE_LIMIT_REDIS_ENABLED=true`, with fail-closed fallback semantics for backend errors.
- Scoped mutating endpoints enforce idempotency keys with replay/conflict semantics (`Idempotency-Key`).
- When idempotency uses DB fallback (`IDEMPOTENCY_REDIS_ENABLED=false`), a bounded background cleanup removes expired records by `expires_at` to prevent unbounded growth.
- Admin list endpoints (`/admin/users`, `/admin/roles`, `/admin/permissions`) use read-through Redis cache with actor-scoped query keys and short TTL.
- RBAC/admin mutations invalidate affected admin list cache namespaces to prevent stale list responses.
- Safe non-auth-critical RBAC entity lookups (`role/permission by id` in admin write flows) use short-lived negative caching for repeated not-found IDs.
- `GET /api/v1/admin/roles` and `GET /api/v1/admin/permissions` also support conditional HTTP caching with `ETag` and `If-None-Match` (`304 Not Modified` on match).
- Cache-miss bursts are protected with in-process `singleflight` dedupe for admin list reads and RBAC permission resolution.

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
- HTTP conditional caching:
  - `GET /admin/roles` and `GET /admin/permissions` return `ETag` and `Cache-Control: private, no-cache`
  - Clients may send `If-None-Match`; unchanged payloads return `304 Not Modified`

## RBAC Permission Cache Policy

- Key scope: `actor_user_id + access_token_jti` (per user/session)
- Default TTL: `5m` (`RBAC_PERMISSION_CACHE_TTL`)
- Backend: Redis when configured, in-memory fallback in tests/local wiring
- Invalidation:
  - `PATCH /admin/users/{id}/roles` -> invalidate target user
  - RBAC role/permission create/update/delete and `POST /admin/rbac/sync` -> invalidate all
- Failure mode: fail closed on permission resolution errors (`503 RBAC_UNAVAILABLE`)

## Negative Lookup Cache Policy

- Purpose: reduce repeated DB reads for known-missing RBAC entities on safe admin paths.
- Default TTL: `15s` (`NEGATIVE_LOOKUP_CACHE_TTL`)
- Namespaces:
  - `admin.role.not_found`
  - `admin.permission.not_found`
- Read path usage:
  - `PATCH /admin/roles/{id}`, `DELETE /admin/roles/{id}`
  - `PATCH /admin/permissions/{id}`, `DELETE /admin/permissions/{id}`
- Invalidation:
  - role create/update/delete -> invalidate `admin.role.not_found`
  - permission create/update/delete -> invalidate `admin.permission.not_found`
  - `POST /admin/rbac/sync` -> invalidate both namespaces

## Audit Taxonomy

- Audit logs now use a typed per-route schema with stable keys:
- `event_name,event_version,actor_user_id,actor_ip,target_type,target_id,action,outcome,reason,request_id,trace_id,span_id,ts`
- Event catalog and query examples are documented in:
- `docs/audit-taxonomy.md`
- Cache flow and architecture diagrams are in:
- `docs/diagrams.md`

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

- Go toolchain pinned to `1.26.0` in `go.mod` and Bazel module setup.
- Bazel version pinned to `9.0.0` in `.bazelversion` (used by Bazelisk locally and in CI).

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
- `task hooks-run-all`

Hooks:

- `.githooks/pre-commit`
  - delegates to `pre-commit` when available
  - fallback behavior formats staged `.go` files with `gofmt` and runs `go mod tidy`
- `.githooks/pre-push`
  - runs `pre-commit run --hook-stage pre-push --all-files` when available
  - runs `bash scripts/ci/run_all.sh`

Pre-commit usage:

- `task hooks-run-all`
- `pre-commit run --all-files` (if pre-commit is already on PATH)
- Hook suite: `gofmt`, `goimports`, `go mod tidy`, `golangci-lint`, `hadolint`, `yamllint`, `detect-secrets`

## Local Development Stack

`docker-compose.yml` starts:

- Postgres
- Redis
- MinIO
- OTel Collector
- Tempo
- Loki
- Mimir
- Grafana
- API

Ports:

- API: `8080`
- Postgres: `5432`
- Redis: `6379`
- MinIO API: `9000`
- MinIO Console: `9001`
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

### Redis Observability Metrics

Redis client instrumentation exports:

- `redis.command.duration` (histogram, seconds) with `command` and `status` labels
- `redis.command.total` (counter)
- `redis.command.errors` (counter) with error type labels
- `redis.command.error_rate` (gauge)
- `redis.pool.saturation` (gauge, used/total connections)
- `redis.keyspace.hits` / `redis.keyspace.misses` (counters)
- `redis.keyspace.hit_ratio` (gauge)

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
