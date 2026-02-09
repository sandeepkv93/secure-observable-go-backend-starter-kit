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

## Expected Startup Output (example)

```text
{"level":"INFO","msg":"server starting","addr":":8080",...}
```

## Related
- Router and endpoints: `internal/http/router/router.go`
- DI composition: `internal/di`
- Root docs: `README.md`
