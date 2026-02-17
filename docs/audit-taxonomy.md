# Audit Taxonomy

This project emits typed, stable audit logs for security and operations workflows.

## Canonical Schema

All audit events are emitted with these fields:

- `event_name`
- `event_version`
- `actor_user_id`
- `actor_ip`
- `target_type`
- `target_id`
- `action`
- `outcome`
- `reason`
- `request_id`
- `trace_id`
- `span_id`
- `ts` (RFC3339 UTC)

## Event Naming Rules

- Use domain-prefixed names: `auth.*`, `admin.*`, `session.*`, `idempotency.*`.
- Keep names stable; evolve via `event_version`.
- Use machine-readable `action` and `outcome`; keep human context in `reason`.

## Event Catalog

Auth:
- `auth.google.login` (`oauth_login`)
- `auth.google.callback` (`oauth_callback`)
- `auth.login` (`login`)
- `auth.refresh` (`refresh`)
- `auth.logout` (`logout`)
- `auth.local.register` (`register`)
- `auth.local.login` (`login`)
- `auth.local.verify.request` (`verify_request`)
- `auth.local.verify.confirm` (`verify_confirm`)
- `auth.local.password.forgot` (`password_forgot`)
- `auth.local.password.reset` (`password_reset`)
- `auth.local.change_password` (`password_change`)

Sessions:
- `session.list` (`list`)
- `session.revoke.single` (`revoke`)
- `session.revoke.others` (`revoke`)

Admin RBAC:
- `admin.user_roles.update` (`set_roles`)
- `admin.role.create` (`create`)
- `admin.role.update` (`update`)
- `admin.role.delete` (`delete`)
- `admin.permission.create` (`create`)
- `admin.permission.update` (`update`)
- `admin.permission.delete` (`delete`)
- `admin.rbac.sync` (`sync`)

Idempotency:
- `idempotency.check` (`check`)
- `idempotency.replay` (`replay`)
- `idempotency.complete` (`complete`)

## Query Examples (Loki)

All successful admin role mutations:

```logql
{service_name="everything-backend-starter-kit"} | json | event_name=~"admin\\.role\\..*" | outcome="success"
```

Authentication failures with reasons:

```logql
{service_name="everything-backend-starter-kit"} | json | event_name=~"auth\\..*" | outcome!="success" | line_format "{{.event_name}} {{.outcome}} {{.reason}}"
```

Trace-correlated audit events:

```logql
{service_name="everything-backend-starter-kit"} | json | trace_id!="" | event_name=~"(auth|admin|session)\\..*"
```
