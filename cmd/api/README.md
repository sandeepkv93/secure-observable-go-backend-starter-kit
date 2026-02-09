# cmd/api

API server entrypoint for the backend.

## Run

```bash
go run ./cmd/api
```

## What It Does
- Loads configuration and dependency graph via Wire (`internal/di`).
- Starts HTTP server on `HTTP_PORT` (default `8080`).
- Installs graceful shutdown on `SIGINT`/`SIGTERM`.
- Shuts down observability providers before exit.

## Expected Startup Output (example)

```text
{"level":"INFO","msg":"server starting","addr":":8080",...}
```

## Related
- Router and endpoints: `internal/http/router/router.go`
- DI composition: `internal/di`
- Root docs: `README.md`
