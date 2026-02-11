# Test Gaps

## Scope and Method

This gap analysis covers the full repository (all `internal/**`, `cmd/**`, and `test/integration/**`) using:

- Source inventory (`*.go` excluding generated tests)
- Test inventory from `docs/test_catalog.md`
- Route map from `internal/http/router/router.go`
- CI/task test commands from `scripts/ci/run_all.sh` and `taskfiles/go.yaml`

Current baseline from catalog:

- Test files: 72
- Unit test files: 53
- Integration test files: 19
- Declared test functions: 225

## High-Level Coverage Posture

Strong coverage already exists for:

- Local auth lifecycle, email verification, password reset flows
- Session management API flows
- RBAC forbidden path and permission-cache invalidation flow
- Admin list pagination/cache/singleflight/etag flows
- Idempotency and Redis race/replay scenarios
- Core middleware primitives (auth, RBAC, security headers/body limit, rate limiter behavior)
- Repository CRUD/filter/sort semantics for user/role/permission/local credential/verification token/oauth/session layers
- Redis-backed cache/guard/store semantics for admin-list, negative lookup, auth abuse, idempotency, and RBAC permission caches
- Observability helpers for metrics emission, logging trace-context enrichment, tracing init, and runtime startup/shutdown branches
- Security/middleware adjunct branches covering cookie semantics, bypass policy edges, request logging fields, and Redis limiter adapter behavior

Most meaningful gaps are concentrated in:

- Service business logic (`SessionService`, `UserService`)
- CLI/tooling and startup wiring smoke paths

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

1. P2: Database/startup/tooling hardening coverage.
2. P2: Consider focused `SessionService`/`UserService` unit test expansion.

## Concrete New Test Files to Add

- `internal/database/postgres_test.go`
- `internal/database/migrate_test.go`
- `internal/database/seed_test.go`
- `internal/app/app_test.go`

## Assumptions and Unknowns

Assumptions:

- Existing integration harness (`newIntegrationHarness`) is the canonical API integration entrypoint.
- Redis race tests are intended to run in environments with docker available.

Unknowns:

- No explicit historical incident list is present; regression priorities are inferred from code complexity/security impact.
- Not all observability side effects are externally assertable without test hooks.
