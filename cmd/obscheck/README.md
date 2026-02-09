# cmd/obscheck

Observability validation CLI for local tri-signal verification.

## Subcommands
- `run`: generates traffic and validates exemplar -> trace -> log correlation

## Examples

```bash
go run ./cmd/obscheck run
go run ./cmd/obscheck run --ci
```

## Flags
- `--grafana-url` (default `http://localhost:3000`)
- `--grafana-user` / `--grafana-password`
- `--service-name`
- `--window`
- `--base-url`
- `--ci` (non-interactive JSON output)

## Expected `--ci` Output Shape

```json
{
  "ok": true,
  "title": "obscheck run",
  "details": ["traffic generated total=... failures=...", "exemplar trace_id=...", "tempo trace lookup: ok", "loki trace correlation: ok"]
}
```

## Related
- Implementation: `internal/tools/obscheck`
- Task alias: `task obs-validate`
