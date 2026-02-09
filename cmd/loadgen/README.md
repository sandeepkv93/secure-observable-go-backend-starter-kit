# cmd/loadgen

Traffic generation CLI for local testing and observability validation.

## Subcommands
- `run`: generate request load against API endpoints

## Examples

```bash
go run ./cmd/loadgen run
go run ./cmd/loadgen run --profile mixed --duration 10s --rps 20 --concurrency 6 --ci
```

## Flags
- `--base-url` (default `http://localhost:8080`)
- `--profile` (`auth`, `mixed`, `error-heavy`)
- `--duration`
- `--rps`
- `--concurrency`
- `--seed`
- `--ci` (non-interactive JSON output)

## Expected `--ci` Output Shape

```json
{
  "ok": true,
  "title": "loadgen run",
  "details": ["total_requests=...", "failures=...", "status_2xx=...", "status_4xx=...", "status_5xx=..."]
}
```

## Related
- Load logic: `internal/tools/loadgen`
- Task alias: `task obs-generate-traffic`
