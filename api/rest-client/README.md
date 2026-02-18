# REST Client Collections

Detailed VS Code REST Client collections for this API are split by domain.

Extension:
- https://marketplace.visualstudio.com/items?itemName=humao.rest-client

Recommended settings:
- `rest-client.rememberCookiesForSubsequentRequests: true`

Run order:
1. `00-quickstart.rest` (health + auth bootstrap)
2. `01-auth.rest`
3. `02-user-me-sessions-avatar.rest`
4. `03-products.rest`
5. `04-feature-flags.rest`
6. `05-admin-rbac.rest`

Coverage map (router source of truth: `internal/http/router/router.go`):
- Health: `GET /health/live`, `GET /health/ready`
- Auth:
  - `GET /api/v1/auth/google/login`
  - `GET /api/v1/auth/google/callback`
  - `POST /api/v1/auth/local/register`
  - `POST /api/v1/auth/local/login`
  - `POST /api/v1/auth/local/verify/request`
  - `POST /api/v1/auth/local/verify/confirm`
  - `POST /api/v1/auth/local/password/forgot`
  - `POST /api/v1/auth/local/password/reset`
  - `POST /api/v1/auth/refresh`
  - `POST /api/v1/auth/logout`
  - `POST /api/v1/auth/local/change-password`
- User/session/avatar:
  - `GET /api/v1/me`
  - `GET /api/v1/me/sessions`
  - `DELETE /api/v1/me/sessions/{session_id}`
  - `POST /api/v1/me/sessions/revoke-others`
  - `POST /api/v1/me/avatar`
  - `DELETE /api/v1/me/avatar`
- Products:
  - `GET /api/v1/products`
  - `GET /api/v1/products/{id}`
  - `POST /api/v1/products`
  - `PUT /api/v1/products/{id}`
  - `DELETE /api/v1/products/{id}`
- Feature flags (user + admin):
  - `GET /api/v1/feature-flags`
  - `GET /api/v1/feature-flags/{key}`
  - `GET /api/v1/admin/feature-flags`
  - `GET /api/v1/admin/feature-flags/{id}`
  - `POST /api/v1/admin/feature-flags`
  - `PATCH /api/v1/admin/feature-flags/{id}`
  - `DELETE /api/v1/admin/feature-flags/{id}`
  - `GET /api/v1/admin/feature-flags/{id}/rules`
  - `POST /api/v1/admin/feature-flags/{id}/rules`
  - `PATCH /api/v1/admin/feature-flags/{id}/rules/{rule_id}`
  - `DELETE /api/v1/admin/feature-flags/{id}/rules/{rule_id}`
- Admin RBAC:
  - `GET /api/v1/admin/users`
  - `PATCH /api/v1/admin/users/{id}/roles`
  - `GET /api/v1/admin/roles`
  - `POST /api/v1/admin/roles`
  - `PATCH /api/v1/admin/roles/{id}`
  - `DELETE /api/v1/admin/roles/{id}`
  - `GET /api/v1/admin/permissions`
  - `POST /api/v1/admin/permissions`
  - `PATCH /api/v1/admin/permissions/{id}`
  - `DELETE /api/v1/admin/permissions/{id}`
  - `POST /api/v1/admin/rbac/sync`

Maintenance rule:
- When any route in `internal/http/router/router.go` changes, update the corresponding `.rest` file(s) in this folder in the same PR.
