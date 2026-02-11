# Test Gaps

## Scope and Method

This gap analysis covers the full repository (all `internal/**`, `cmd/**`, and `test/integration/**`) using:

- Source inventory (`*.go` excluding generated tests)
- Test inventory from `docs/test_catalog.md`
- Route map from `internal/http/router/router.go`
- CI/task test commands from `scripts/ci/run_all.sh` and `taskfiles/go.yaml`

Current baseline from catalog:

- Test files: 45
- Unit test files: 27
- Integration test files: 18
- Declared test functions: 164

## High-Level Coverage Posture

Strong coverage already exists for:

- Local auth lifecycle, email verification, password reset flows
- Session management API flows
- RBAC forbidden path and permission-cache invalidation flow
- Admin list pagination/cache/singleflight/etag flows
- Idempotency and Redis race/replay scenarios
- Core middleware primitives (auth, RBAC, security headers/body limit, rate limiter behavior)

Most meaningful gaps are concentrated in:

- Handler branch matrices (especially admin mutations)
- Service business logic (`AuthService`, `SessionService`, `UserService`)
- Repository CRUD/filter/sort semantics (except session repository)
- Redis-backed cache/guard/store implementations (direct unit tests)
- Router and health endpoint behavior
- CLI/tooling and startup wiring smoke paths

## P1 Gaps (Important)

### 5) Handler-level branch/unit coverage gaps

#### `internal/http/handler/auth_handler.go`

Missing scenarios:

- `LocalChangePassword` success/error mapping across credentials and auth context conditions.
- Abuse bypass conditions (`trusted_subnet`, trusted actor) and fallback behavior.
- Verify/forgot/reset payload parse failures and service error classification branches.
- Cookie/header side effects for refresh/logout/change-password branches.

#### `internal/http/handler/user_handler.go`

Missing scenarios:

- `Me` user-service error mapping.
- `Sessions` current-session resolve fallback semantics and repo-not-found behavior.
- `RevokeSession` parse error vs not-found vs already-revoked vs success.
- `RevokeOtherSessions` unauthorized/resolve error/internal error branches.

#### `internal/http/handler/admin_handler.go`

Missing scenarios:

- Conditional ETag 304 branch validation with exact cache payload hash.
- Negative lookup cache false-positive handling (`stale_false_positive`).
- Cache invalidation on each mutation type.
- Lockout-protection helper logic (`wouldLockOut*`) across role/permission combinations.
- Sort/filter/page parser failure combinations across admin list endpoints.

### 6) Router and health endpoint behavior (integration + unit)

Current state:

- Health internals have unit tests; no API-level health endpoint tests.
- Router registration/composition itself has no tests.

Missing scenarios:

- `/health/live` always 200 + stable payload.
- `/health/ready` with `nil` runner (ready) and unready dependency branch (503).
- Router fallback rate limiter wiring when custom/global limiter not provided.
- Route-policy overrides are applied per named route policy.
- CSRF protection route scoping around refresh/logout/change-password and session revocation endpoints.

### 7) Repository layer has sparse direct coverage (unit/integration)

Current state:

- Only `session_repository_test.go` exists.

Missing scenarios:

- `user_repository.go`: filters (`email`, `status`, `role`), sort combinations, pagination boundaries, role association semantics.
- `role_repository.go`: create/update with permission sets, conflict paths, delete not-found handling.
- `permission_repository.go`: list-paged filters/sorts, `FindByPairs` completeness and dedupe behavior, conflict/not-found branches.
- `local_credential_repository.go`: find-by-email join semantics, mark verified timestamp behavior, update password.
- `verification_token_repository.go`: invalidate-active semantics, consume idempotency/concurrency safety.
- `oauth_repository.go`: find/create uniqueness behavior.
- `pagination.go`: bounds and normalization for invalid inputs.

### 8) Redis-backed service stores are not directly tested (unit)

Missing scenarios:

- `admin_list_cache_redis.go`: namespace index integrity, missing meta timestamp behavior, `GetWithAge` parse-failure behavior, namespace invalidation idempotency.
- `negative_lookup_cache_redis.go`: set/get/invalidate and stale entry behavior.
- `auth_abuse_guard_redis.go`: cooldown growth/reset semantics, malformed redis value handling, key dimension isolation.
- `idempotency_store_redis.go`: begin conflict/in-progress/replay transitions, TTL refresh, malformed hash payload handling.
- `rbac_permission_cache_store_redis.go`: cache keying, invalidate-by-user and invalidate-all coverage.

### 9) Observability utility surfaces with little/no tests (unit)

Missing scenarios:

- `internal/observability/metrics.go`: each metric helper does not panic and sets expected label cardinality constraints.
- `internal/observability/logging.go`: request log field extraction and fallback values.
- `internal/observability/tracing.go`: tracer init no-op/fallback branches.
- `internal/observability/runtime.go`: runtime metrics start/stop behavior.

### 10) Security and middleware adjunct gaps (unit)

Missing scenarios:

- `security/cookie.go`: secure/samesite/domain cookie flags and clear-token semantics.
- `middleware/bypass_policy.go`: trusted CIDR parsing failures, actor bypass list behavior, method/path classification.
- `middleware/request_logging_middleware.go`: status/error logging fields and duration boundaries.
- `middleware/rate_limit_redis.go`: redis backend failure vs allow/deny policy semantics.

## P2 Gaps (Useful but Lower Immediate Risk)

### 11) Database/startup/tooling paths

Missing scenarios:

- `internal/database/postgres.go`: DSN handling, connect timeout, migration invocation failures.
- `internal/database/migrate.go`, `internal/database/seed.go`: command execution/reporting branches.
- `internal/app/app.go`: bootstrap/startup wiring smoke tests.
- `internal/tools/common/*`, `internal/tools/{migrate,seed,obscheck,ui}/command.go`: CLI arg validation, error propagation, output formatting.

### 12) Domain model tests

Current state:

- `internal/domain/*.go` has no tests.

Missing scenarios:

- Struct tag/backfill expectations (if relied upon by JSON/API contracts).
- Field defaults and status constants (if behaviorally significant).

Note:

- Domain models are mostly passive; prioritize above only if model logic/validation is added.

## Cross-Cutting Quality Gaps

- No fuzz tests (`Fuzz*`) currently present.
- No benchmark tests (`Benchmark*`) currently present.
- Redis race integration tests are skipped when docker unavailable; CI may miss these if environment lacks docker.
- No explicit flaky-test quarantine strategy in repo.

## Recommended Implementation Sequence

1. P1-5/6: Add user/admin/auth handler unit tests and health/router integration tests.
2. P1-7/8: Fill repository and Redis-store unit tests.
3. P1-9/10 and P2: Observability/security/tooling hardening coverage.

## Concrete New Test Files to Add

- `test/integration/health_endpoints_test.go`
- `internal/http/handler/auth_handler_test.go`
- `internal/http/handler/user_handler_test.go`
- `internal/http/handler/admin_handler_test.go`
- `internal/http/router/router_test.go`
- `internal/repository/user_repository_test.go`
- `internal/repository/role_repository_test.go`
- `internal/repository/permission_repository_test.go`
- `internal/repository/local_credential_repository_test.go`
- `internal/repository/verification_token_repository_test.go`
- `internal/repository/oauth_repository_test.go`
- `internal/service/idempotency_store_redis_test.go`
- `internal/service/auth_abuse_guard_redis_test.go`
- `internal/service/admin_list_cache_redis_test.go`
- `internal/service/negative_lookup_cache_redis_test.go`
- `internal/service/rbac_permission_cache_store_redis_test.go`
- `internal/security/cookie_test.go`
- `internal/http/middleware/bypass_policy_test.go`
- `internal/http/middleware/request_logging_middleware_test.go`
- `internal/http/middleware/rate_limit_redis_test.go`

## Assumptions and Unknowns

Assumptions:

- Existing integration harness (`newIntegrationHarness`) is the canonical API integration entrypoint.
- Redis race tests are intended to run in environments with docker available.

Unknowns:

- No explicit historical incident list is present; regression priorities are inferred from code complexity/security impact.
- Not all observability side effects are externally assertable without test hooks.
