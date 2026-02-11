# Metrics Catalog

Comprehensive inventory of metrics emitted by this repository.

Scope:
- Metrics emitted by application code in `internal/observability/*` and call sites across handlers/middleware/services.
- Redis client metrics emitted by Redis hook instrumentation.
- HTTP server auto-metrics emitted by `otelhttp` middleware wrapper.

Non-scope:
- Logs and audit events (documented in `docs/audit-taxonomy.md`).

## Emission Pipeline

- Metrics are initialized in `internal/observability/metrics.go` via `InitMetrics`.
- Metrics export uses OTLP/gRPC to `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Metric resource attributes always include:
  - `service.name`
  - `deployment.environment`
- App metric instrument namespace/meter: `secure-observable-go-backend-starter-kit`.
- Redis metrics are enabled through `observability.InstrumentRedisClient` in `internal/di/providers.go` when a Redis client is created.
- HTTP auto-metrics are enabled when router is wrapped with `otelhttp.NewHandler` (`internal/http/router/router.go`).

## Application Metrics (Explicit)

| Metric name | Type | Unit | Attributes | Emitted from |
|---|---|---|---|---|
| `auth.login.attempts` | Counter (int64) | 1 | `provider`, `status` | `RecordAuthLogin` calls in `internal/http/handler/auth_handler.go` |
| `auth.refresh.attempts` | Counter (int64) | 1 | `status` | `RecordAuthRefresh` calls in `internal/http/handler/auth_handler.go` |
| `auth.logout.attempts` | Counter (int64) | 1 | `status` | `RecordAuthLogout` calls in `internal/http/handler/auth_handler.go` |
| `auth.access_token.validation.events` | Counter (int64) | 1 | `outcome`, `source` | `RecordAccessTokenValidation` calls in `internal/http/middleware/auth_middleware.go` |
| `security.csrf.validation.events` | Counter (int64) | 1 | `outcome`, `path_group` | `RecordCSRFValidation` calls in `internal/http/middleware/security_middleware.go` |
| `http.rate_limit.decisions` | Counter (int64) | 1 | `scope`, `outcome`, `mode`, `key_type` | `RecordRateLimitDecision` calls in `internal/http/middleware/rate_limit_middleware.go` |
| `http.rate_limit.retry_after` | Histogram (float64) | `s` | `scope`, `reason` | `RecordRateLimitRetryAfter` calls in `internal/http/middleware/rate_limit_middleware.go` |
| `auth.abuse_guard.events` | Counter (int64) | 1 | `scope`, `action`, `outcome` | `RecordAuthAbuseGuardEvent` calls in `internal/service/auth_abuse_guard*.go` and `internal/http/handler/auth_handler.go` |
| `auth.abuse_guard.cooldown` | Histogram (float64) | `s` | `scope`, `action` | `RecordAuthAbuseCooldown` calls in `internal/service/auth_abuse_guard*.go` |
| `auth.refresh.security.events` | Counter (int64) | 1 | `outcome` | `RecordRefreshSecurityEvent` calls in `internal/service/token_service.go` |
| `session.management.events` | Counter (int64) | 1 | `action`, `status` | `RecordSessionManagementEvent` calls in `internal/http/handler/user_handler.go` |
| `session.revoked.count` | Histogram (float64) | 1 | `action` | `RecordSessionRevokedCount` calls in `internal/http/handler/user_handler.go` |
| `user.profile.events` | Counter (int64) | 1 | `outcome` | `RecordUserProfileEvent` calls in `internal/http/handler/user_handler.go` |
| `auth.local.flow.events` | Counter (int64) | 1 | `flow`, `outcome` | `RecordAuthLocalFlowEvent` calls in `internal/http/handler/auth_handler.go` |
| `admin.list.request.duration` | Histogram (float64) | `s` | `endpoint`, `status` | `RecordAdminListRequestDuration` calls in `internal/http/handler/admin_handler.go` |
| `admin.list.page_size` | Histogram (float64) | 1 | `endpoint` | `RecordAdminListPageSize` calls in `internal/http/handler/admin_handler.go` |
| `health.check.results` | Counter (int64) | 1 | `check`, `outcome` | `RecordHealthCheckResult` calls in `internal/health/checker.go` |
| `health.check.duration` | Histogram (float64) | `s` | `check` | `RecordHealthCheckDuration` calls in `internal/health/checker.go` |
| `database.startup.events` | Counter (int64) | 1 | `phase`, `outcome` | `RecordDatabaseStartupEvent` calls in `internal/database/*.go` |
| `database.startup.duration` | Histogram (float64) | `s` | `phase` | `RecordDatabaseStartupDuration` calls in `internal/database/*.go` |
| `idempotency.cleanup.runs` | Counter (int64) | 1 | `outcome` | `RecordIdempotencyCleanupRun` calls in `internal/service/idempotency_store_db.go` |
| `idempotency.cleanup.deleted_rows` | Histogram (float64) | 1 | none | `RecordIdempotencyCleanupDeletedRows` calls in `internal/service/idempotency_store_db.go` |
| `admin.rbac.mutations` | Counter (int64) | 1 | `entity`, `action`, `status` | `RecordAdminRBACMutation` calls in `internal/http/handler/admin_handler.go` |
| `admin.list.cache.events` | Counter (int64) | 1 | `endpoint`, `outcome` | `RecordAdminListCacheEvent` calls in `internal/http/handler/admin_handler.go` |
| `auth.rbac.permission.cache.events` | Counter (int64) | 1 | `outcome` | `RecordRBACPermissionCacheEvent` calls in `internal/http/middleware/rbac_middleware.go`, `internal/service/rbac_permission_resolver.go`, `internal/http/handler/admin_handler.go` |
| `http.idempotency.events` | Counter (int64) | 1 | `scope`, `outcome` | `RecordIdempotencyEvent` calls in `internal/http/middleware/idempotency_middleware.go` |
| `auth.request.duration` | Histogram (float64) | `s` | `endpoint`, `status` | `RecordAuthRequestDuration` calls in `internal/http/handler/auth_handler.go` |

### Attribute Values Observed in Code

`auth.login.attempts`
- `provider`: `google`, `local`
- `status`: `success`, `failure`

`auth.refresh.attempts`
- `status`: `success`, `failure`, `reuse_detected`

`auth.logout.attempts`
- `status`: `success`, `failure`

`auth.access_token.validation.events`
- `outcome`: `missing`, `invalid`, `valid`
- `source`: `none`, `cookie`, `bearer`

`security.csrf.validation.events`
- `outcome`: `missing_cookie`, `mismatch`, `valid`
- `path_group` examples: `api/auth`, `api/admin`, `api/me`, `root`

`http.rate_limit.decisions`
- `outcome`: `allow`, `deny`, `backend_error`, `bypass`
- `mode`: `fail_open`, `fail_closed`
- `key_type`: `ip`, `subject`

`http.rate_limit.retry_after`
- `reason`: `window`, `bucket`, `backend`

`auth.abuse_guard.events`
- `scope`: `login`, `forgot`
- `action`: `check`, `register_failure`, `reset`
- `outcome`: `ok`, `cooldown`, `error`, `bypass`

`auth.abuse_guard.cooldown`
- `scope`: `login`, `forgot`
- `action`: `check`, `register_failure`

`auth.refresh.security.events`
- `outcome`: `invalid`, `reuse_detected`, `lineage_backfilled`, `rotated`

`session.management.events`
- `action`: `list`, `revoke_one`, `revoke_others`
- `status`: `success`, `not_found`, `error`

`session.revoked.count`
- `action` currently emitted: `revoke_others`

`user.profile.events`
- `outcome`: `success`, `not_found`, `unauthorized`

`auth.local.flow.events`
- `flow`: `verify_request`, `verify_confirm`, `password_forgot`, `password_reset`, `password_change`
- `outcome` values used: `accepted`, `success`, `failure`, `not_enabled`, `invalid_token`, `weak_password`, `rate_limited`, `unauthorized`

`admin.list.request.duration`
- `endpoint`: `admin.users`, `admin.roles`, `admin.permissions`
- `status`: `success`, `not_modified`, `bad_request`, `error`

`admin.list.page_size`
- `endpoint`: `admin.users`, `admin.roles`, `admin.permissions`

`health.check.results`
- `check` values currently emitted: `startup_grace`, `db`, `redis`
- `outcome`: `healthy`, `unhealthy`, `timeout`

`health.check.duration`
- `check` values currently emitted: `startup_grace`, `db`, `redis`

`database.startup.events`
- `phase`: `open`, `migrate`, `seed`
- `outcome`: `success`, `error`

`database.startup.duration`
- `phase`: `open`, `migrate`, `seed`

`idempotency.cleanup.runs`
- `outcome`: `success`, `error`

`idempotency.cleanup.deleted_rows`
- no attributes

`admin.rbac.mutations`
- `entity`: `user_role`, `role`, `permission`, `sync`
- `action`: `set_user_roles`, `create`, `update`, `delete`, `sync`
- `status`: `success`, `rejected`, `error`

`admin.list.cache.events`
- `outcome` values used: `hit`, `miss`, `store`, `store_error`, `encode_error`, `invalidate`, `invalidate_error`, `singleflight_leader`, `singleflight_shared`, `error`, `negative_hit`, `negative_miss`, `negative_store`, `negative_store_error`, `negative_invalidate`, `negative_invalidate_error`, `etag_ok`, `etag_not_modified`
- `endpoint` is a namespace string (examples): `admin.users.list`, `admin.roles.list`, `admin.permissions.list`, `admin.lookup.roles.missing`, `admin.lookup.permissions.missing`

`auth.rbac.permission.cache.events`
- `outcome` values used: `allowed`, `resolve_error`, `singleflight_leader`, `singleflight_shared`, `invalidate_user`, `invalidate_user_error`, `invalidate_user_skipped`, `invalidate_all`, `invalidate_all_error`, `invalidate_all_skipped`

`http.idempotency.events`
- `outcome` values used: `missing_key`, `invalid_key`, `read_error`, `store_error`, `conflict`, `in_progress`, `replayed`, `created`
- `scope` examples: `auth.local.register`, `auth.local.password.forgot`, `admin.users.roles.patch`, `admin.roles.create`

`auth.request.duration`
- `endpoint` values used: `google_login`, `google_callback`, `refresh`, `logout`, `local_register`, `local_login`, `local_verify_request`, `local_verify_confirm`, `local_password_forgot`, `local_password_reset`, `local_change_password`
- `status` values used in handler code: `success`, `failure`

## Redis Metrics (Explicit)

Defined in `internal/observability/redis_metrics.go` and emitted by go-redis hooks.

| Metric name | Type | Unit | Attributes | Notes |
|---|---|---|---|---|
| `redis.command.total` | Counter (int64) | 1 | `command`, `status` | Incremented for each command and pipeline subcommand |
| `redis.command.errors` | Counter (int64) | 1 | `command`, `error_type` | Excludes `redis.Nil` misses |
| `redis.command.duration` | Histogram (float64) | `s` | `command`, `status` | Per command and per pipeline call (`command=pipeline`) |
| `redis.keyspace.hits` | Counter (int64) | 1 | none | Client-observed hits for `get/hget/lindex/zscore/exists/mget/hmget` |
| `redis.keyspace.misses` | Counter (int64) | 1 | none | Client-observed misses for same command set |
| `redis.pool.saturation` | Observable gauge (float64) | `1` | none | Computed as used/total connections |
| `redis.keyspace.hit_ratio` | Observable gauge (float64) | `1` | none | Computed as hits/(hits+misses) |
| `redis.command.error_rate` | Observable gauge (float64) | `1` | none | Computed as errors/total commands |

### Redis Attribute Conventions

- `status` for Redis command metrics: `success`, `miss`, `error`
- `error_type` classification: `timeout`, `connection`, `other`

## HTTP Auto-Metrics (Conditional)

When `EnableOTelHTTP` is true, router is wrapped by `otelhttp.NewHandler(r, "http.server")` in `internal/http/router/router.go`.

Inference:
- This emits standard OpenTelemetry HTTP server metrics from `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`.
- Names and attribute sets follow OTel semantic conventions for that library version and may change across dependency upgrades.

The exact auto-generated metric names are not hardcoded in this repository; they are produced by the otelhttp instrumentation package at runtime.

## Metric Enablement Conditions

- `OTEL_METRICS_ENABLED=false`:
  - App metric instruments are not initialized, and explicit `Record*` calls no-op.
- Redis metrics require a Redis client to be created and instrumented in DI.
- HTTP auto-metrics require `EnableOTelHTTP=true` (wired as `OTELMetricsEnabled || OTELTracingEnabled` in providers).

## Source References

- `internal/observability/metrics.go`
- `internal/observability/redis_metrics.go`
- `internal/http/handler/auth_handler.go`
- `internal/http/handler/admin_handler.go`
- `internal/http/handler/user_handler.go`
- `internal/database/postgres.go`
- `internal/database/migrate.go`
- `internal/database/seed.go`
- `internal/health/checker.go`
- `internal/http/middleware/auth_middleware.go`
- `internal/http/middleware/security_middleware.go`
- `internal/http/middleware/rate_limit_middleware.go`
- `internal/http/middleware/idempotency_middleware.go`
- `internal/http/middleware/rbac_middleware.go`
- `internal/service/auth_abuse_guard.go`
- `internal/service/auth_abuse_guard_redis.go`
- `internal/service/idempotency_store_db.go`
- `internal/service/rbac_permission_resolver.go`
- `internal/service/token_service.go`
- `internal/http/router/router.go`
- `internal/di/providers.go`
