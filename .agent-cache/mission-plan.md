# Mission Plan

## Objective
Add Redis outage policy controls per feature so fail-open/fail-closed behavior is configurable by route scope.

## Scope
- internal/config/config.go
- internal/di/providers.go
- internal/config/config_profile_test.go
- internal/di/providers_test.go
- README.md
- .env.example

## Success Criteria
- New env/config controls exist for API/auth/forgot/login/refresh/admin-write/admin-sync outage mode.
- Modes are validated (`fail_open|fail_closed`).
- DI wiring uses per-scope mode values.
- Tests cover validation + runtime behavior for Redis outage mode.
- `go test ./...` passes.

## DAG
- T1: Config fields + load + validate.
- T2: DI mode mapping + per-scope wiring. Depends on T1.
- T3: Test updates (config + DI). Depends on T1,T2.
- T4: Docs/env updates. Depends on T1.
- T5: Full validation + commit + push. Depends on T3,T4.
