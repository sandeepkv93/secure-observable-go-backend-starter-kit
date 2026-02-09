# cmd/migrate

Database migration CLI.

## Subcommands
- `up`: apply schema migrations
- `status`: check migration prerequisites and DB connectivity
- `plan`: dry-run style migration plan output (no schema mutation)

## Examples

```bash
go run ./cmd/migrate up
go run ./cmd/migrate status --ci
go run ./cmd/migrate plan --ci
```

## Flags
- `--env-file` (default `.env`)
- `--timeout` (default `30s`)
- `--ci` (non-interactive JSON output)

## Expected `--ci` Output Shape

```json
{
  "ok": true,
  "title": "migrate status",
  "details": ["database reachable", "service: secure-observable-go-backend-starter-kit", "migrations: ready"]
}
```

## Related
- Migration implementation: `internal/database/migrate.go`
- Config loading/validation: `internal/config/config.go`
- Task alias: `task migrate`
