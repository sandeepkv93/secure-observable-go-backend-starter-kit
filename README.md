# go-oauth-rbac-service

REST API service in Go with Google OAuth login, JWT auth, secure cookie sessions, RBAC authorization, and OpenTelemetry observability.

## Prerequisites
- Go `1.25.4`
- [Task](https://taskfile.dev/)
- Docker (optional for local stack)

## Setup
1. Copy env file:
   - `cp .env.example .env`
2. Fill Google OAuth credentials in `.env`.
3. Ensure Google OAuth redirect URL is: `http://localhost:8080/api/v1/auth/google/callback`

## Dependency Injection
- Composition uses Google Wire in `internal/di`.
- Regenerate injectors:
  - `task wire`
- Verify generated graph is up to date:
  - `task wire-check`

## Run
- `task migrate`
- `task run`

## Local Observability Stack
- Start local stack with collector + prometheus:
  - `task docker-up`
- Services:
  - API: `http://localhost:8080`
  - OTel Collector health: `http://localhost:13133`
  - Prometheus: `http://localhost:9090`
- Collector receives OTLP on:
  - gRPC `localhost:4317`
  - HTTP `localhost:4318`

## Test and Checks
- `task ci` (recommended full local gate)
- `task wire-check`
- `task test`
- `task lint`

## Docker
- `task docker-up`
- `task docker-down`

## API
- Health: `/health/live`, `/health/ready`
- OpenAPI: `api/openapi.yaml`

## Notes
- Access and refresh tokens are set as secure HTTP-only cookies.
- Auth and API routes use fixed-window IP rate limiting (configurable via env).
- Mutating cookie-auth endpoints require `X-CSRF-Token` matching `csrf_token` cookie.
- First admin can be bootstrapped with `BOOTSTRAP_ADMIN_EMAIL`.
- OTel metrics, tracing, and logs are powered by the OpenTelemetry Go SDK and exported through the collector.
