# cmd/api

API server entrypoint for the backend.

## Run

```bash
go run ./cmd/api
```

## What It Does
- Loads configuration and dependency graph via Wire (`internal/di`).
- Starts HTTP server on `HTTP_PORT` (default `8080`).
- Installs phased graceful shutdown on `SIGINT`/`SIGTERM`.
- Shuts down HTTP server, observability providers, Redis client, and DB connection pool before exit.
- Exposes health probes:
- `GET /health/live` (process liveness)
- `GET /health/ready` (dependency readiness with DB/Redis checks)

## Hardening-Related Env Vars
- `READINESS_PROBE_TIMEOUT`
- `SERVER_START_GRACE_PERIOD`
- `SHUTDOWN_TIMEOUT`
- `SHUTDOWN_HTTP_DRAIN_TIMEOUT`
- `SHUTDOWN_OBSERVABILITY_TIMEOUT`

## Idempotency Controls
- `IDEMPOTENCY_ENABLED`
- `IDEMPOTENCY_REDIS_ENABLED`
- `IDEMPOTENCY_TTL`
- `IDEMPOTENCY_REDIS_PREFIX`

Scoped endpoints requiring `Idempotency-Key`:
- `POST /api/v1/auth/local/register`
- `POST /api/v1/auth/local/password/forgot`
- `POST /api/v1/admin/roles`
- `PATCH /api/v1/admin/users/{id}/roles`

## RBAC Admin Write Endpoints
- `PATCH /api/v1/admin/roles/{id}`
- `DELETE /api/v1/admin/roles/{id}`
- `POST /api/v1/admin/permissions`
- `PATCH /api/v1/admin/permissions/{id}`
- `DELETE /api/v1/admin/permissions/{id}`
- `POST /api/v1/admin/rbac/sync`

Policy and safety controls:
- Protected entities via `RBAC_PROTECTED_ROLES` and `RBAC_PROTECTED_PERMISSIONS`.
- Self-lockout prevention for role/permission mutation paths.

## Admin List Query Endpoints
- `GET /api/v1/admin/users` with query params:
- `page,page_size,sort_by,sort_order,email,status,role`
- `GET /api/v1/admin/roles` with query params:
- `page,page_size,sort_by,sort_order,name`
- `GET /api/v1/admin/permissions` with query params:
- `page,page_size,sort_by,sort_order,resource,action`

Paginated response shape:
- `data.items`
- `data.pagination { page, page_size, total, total_pages }`

## Expected Startup Output (example)

```text
{"level":"INFO","msg":"server starting","addr":":8080",...}
```

## Related
- Router and endpoints: `internal/http/router/router.go`
- DI composition: `internal/di`
- Root docs: `README.md`
