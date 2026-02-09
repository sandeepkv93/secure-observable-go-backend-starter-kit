# cmd/seed

Seed/bootstrap data CLI for RBAC defaults and optional admin bootstrap.

## Subcommands
- `apply`: writes default permissions/roles and optional admin role assignment
- `dry-run`: prints what would be seeded
- `verify-local-email`: marks a local auth credential as verified (for local/dev verification-required mode)

## Examples

```bash
go run ./cmd/seed apply
go run ./cmd/seed dry-run --ci
go run ./cmd/seed apply --bootstrap-admin-email=admin@example.com --ci
go run ./cmd/seed verify-local-email --email=user@example.com --ci
```

## Flags
- `--env-file` (default `.env`)
- `--bootstrap-admin-email` (override env bootstrap email)
- `--ci` (non-interactive JSON output)

## Expected `--ci` Output Shape

```json
{
  "ok": true,
  "title": "seed apply",
  "details": ["seeded default roles and permissions", "bootstrap admin role assignment attempted for: admin@example.com"]
}
```

## Related
- Seed implementation: `internal/database/seed.go`
- Task aliases: `task seed`, `task seed:dry-run`, `task seed:verify-local-email`
