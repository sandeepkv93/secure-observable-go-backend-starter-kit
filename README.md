# Everything Backend Starter Kit

[![CI](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/ci.yml)
[![Fuzz Nightly](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/fuzz-nightly.yml/badge.svg)](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/fuzz-nightly.yml)
[![K8s Kind Smoke](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/k8s-kind-smoke.yml/badge.svg)](https://github.com/sandeepkv93/everything-backend-starter-kit/actions/workflows/k8s-kind-smoke.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26.0-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Bazel Version](https://img.shields.io/badge/Bazel-9.0.0-43A047?style=flat&logo=bazel)](https://bazel.build/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Architecture at a Glance](#architecture-at-a-glance)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [License](#license)

## Overview

This repository is a production-oriented Go backend starter that brings together authentication, authorization, observability, and delivery tooling in one baseline:

- Google OAuth login
- Cookie-based JWT session flow (access + refresh)
- Session/device management APIs (`/api/v1/me/sessions`)
- RBAC authorization
- Redis-backed caching for admin list, RBAC permission, and negative lookup flows
- Redis-backed rate limiting and abuse-protection controls
- OpenTelemetry metrics, traces, and logs
- Local tri-signal stack (Grafana + Tempo + Loki + Mimir + OTel Collector)
- Bazel + Gazelle + Task + Wire development workflow
- API server in `cmd/api`
- Operational CLIs in `cmd/migrate`, `cmd/seed`, `cmd/loadgen`, `cmd/obscheck`
- Layered internal packages (`internal/*`) with DI composition through Wire
- Docker Compose local stack for DB + observability
- CI + local hooks enforcing build/test/generation hygiene

## Tech Stack

- Language/runtime: [![Go](https://img.shields.io/badge/Go-1.26.0-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
- HTTP framework: [![Chi](https://img.shields.io/badge/Chi-v5-1f6feb?style=flat)](https://github.com/go-chi/chi)
- Persistence: [![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/) [![GORM](https://img.shields.io/badge/GORM-v2-00ADD8?style=flat&logo=go&logoColor=white)](https://gorm.io/)
- Cache/rate limiting/idempotency backend: [![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io/)
- Object storage: [![MinIO](https://img.shields.io/badge/MinIO-S3%20Compatible-C72E49?style=flat)](https://min.io/)
- Auth: [![Google OAuth](https://img.shields.io/badge/Google%20OAuth-Enabled-4285F4?style=flat&logo=google&logoColor=white)](https://developers.google.com/identity/protocols/oauth2) [![JWT](https://img.shields.io/badge/JWT-Access%20%2B%20Refresh-000000?style=flat&logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
- Observability: [![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-Enabled-6929C4?style=flat&logo=opentelemetry&logoColor=white)](https://opentelemetry.io/) [![OTel Collector](https://img.shields.io/badge/OTel%20Collector-Included-425CC7?style=flat)](https://opentelemetry.io/docs/collector/) [![Grafana](https://img.shields.io/badge/Grafana-Stack-F46800?style=flat&logo=grafana&logoColor=white)](https://grafana.com/) [![Tempo](https://img.shields.io/badge/Tempo-Traces-F46800?style=flat)](https://grafana.com/oss/tempo/) [![Loki](https://img.shields.io/badge/Loki-Logs-F46800?style=flat)](https://grafana.com/oss/loki/) [![Mimir](https://img.shields.io/badge/Mimir-Metrics-F46800?style=flat)](https://grafana.com/oss/mimir/)
- Tooling: [![Task](https://img.shields.io/badge/Task-Runner-4A90E2?style=flat)](https://taskfile.dev/) [![Bazelisk](https://img.shields.io/badge/Bazelisk-Bazel%209.0.0-43A047?style=flat&logo=bazel&logoColor=white)](https://github.com/bazelbuild/bazelisk) [![Gazelle](https://img.shields.io/badge/Gazelle-Build%20files-76D275?style=flat)](https://github.com/bazelbuild/bazel-gazelle) [![Wire](https://img.shields.io/badge/Wire-DI-00ADD8?style=flat&logo=go&logoColor=white)](https://github.com/google/wire) [![golangci-lint](https://img.shields.io/badge/golangci--lint-Enabled-00ADD8?style=flat)](https://golangci-lint.run/) [![gosec](https://img.shields.io/badge/gosec-Enabled-5C2D91?style=flat)](https://github.com/securego/gosec) [![govulncheck](https://img.shields.io/badge/govulncheck-Enabled-007D9C?style=flat)](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) [![gitleaks](https://img.shields.io/badge/gitleaks-Enabled-121212?style=flat)](https://github.com/gitleaks/gitleaks)

## Architecture at a Glance

- Request path: `internal/http` ==> `internal/service` ==> `internal/repository` ==> `internal/database`
- Cross-cutting concerns: `internal/security`, `internal/observability`, middleware, and Redis-backed controls
- Dependency injection: `internal/di` (Wire-generated injectors validated in CI)

```mermaid
flowchart LR
    User[Web or API Client] --> Router[Chi Router + Middleware]
    Router --> Handlers[HTTP Handlers]
    Handlers --> Services[Service Layer]
    Services --> Repos[Repository Layer]
    Repos --> DB[(PostgreSQL)]
    Services --> Redis[(Redis)]
    Services --> MinIO[(MinIO/S3)]

    Handlers --> OAuth[Google OAuth Provider]
    OAuth --> Handlers

    Router -. request logs, metrics, traces .-> OTelSDK[OTel SDK]
    Services -. cache and auth metrics .-> OTelSDK
    Repos -. db telemetry .-> OTelSDK

    OTelSDK --> Collector[OTel Collector]
    Collector --> Tempo[Tempo Traces]
    Collector --> Loki[Loki Logs]
    Collector --> Mimir[Mimir Metrics]

    Grafana[Grafana] --> Tempo
    Grafana --> Loki
    Grafana --> Mimir

    Loadgen[cmd/loadgen] --> Router
    Obscheck[cmd/obscheck] --> Grafana
```

## Quick Start

### Prerequisites:

- [Go `1.26.0`](https://go.dev/dl/)
- [Task](https://taskfile.dev/)
- [Bazelisk](https://github.com/bazelbuild/bazelisk) (uses Bazel `9.0.0` from `.bazelversion`)
- [Docker](https://docs.docker.com/get-docker/) + [Docker Compose](https://docs.docker.com/compose/)

### Clone the repo and cd into it

```bash
git clone git@github.com:sandeepkv93/everything-backend-starter-kit.git
cd everything-backend-starter-kit
```

### Configure environment

```bash
cp .env.example .env
```

### Start local dependencies and run API

```bash
task docker-up
task migrate
task seed
task run
```

### Database reset/backup/restore (local)

These commands operate on the Docker Compose-managed Postgres service (`db`) and its data volume.

```bash
# reset Postgres container + DB volume and start fresh db service
task integration:reset-db

# create SQL backup (default: backups/backup_<timestamp>.sql)
task integration:backup-db

# restore from backup file
task integration:restore-db FILE=backups/backup_20260217_103000.sql
```

### Expected success checks

```bash
curl -sSf http://localhost:8080/health/live
curl -sSf http://localhost:8080/health/ready
```

### REST Client Collection (Manual API Verification)

Use the checked-in VS Code REST Client collections to exercise all APIs (including detailed RBAC/admin flows) end-to-end.

1. Install the REST Client extension: `https://marketplace.visualstudio.com/items?itemName=humao.rest-client`
2. Open the detailed split collections in `api/rest-client/` (recommended):
   - `00-quickstart.rest`
   - `01-auth.rest`
   - `02-user-me-sessions-avatar.rest`
   - `03-products.rest`
   - `04-feature-flags.rest`
   - `05-admin-rbac.rest`
3. Optionally use `api/everything-backend-starter-kit.rest` as a monolithic fallback
4. Update variables at the top (`@baseUrl`, user credentials, IDs) for your local environment
4. Run requests in sequence:
   - health checks
   - local login/register
   - CSRF-protected endpoints (`/auth/refresh`, `/auth/logout`, `/auth/local/change-password`, `/me/*` mutating routes)
   - admin RBAC endpoints with a user that has required permissions

Notes:
- Cookie-based auth is used, so enable REST Client cookie persistence (`rest-client.rememberCookiesForSubsequentRequests`).
- Idempotency-key headers are included for routes that can be wrapped by idempotency middleware.
- When routes change in `internal/http/router/router.go`, update `api/rest-client/*.rest` (and monolithic file if used) in the same PR.

### Pre-commit workflow

Install hooks and local tooling:

```bash
task hooks-install
```

Run the full hook suite manually:

```bash
task hooks-run-all
# or, if pre-commit is already on PATH:
pre-commit run --all-files
```

Hook coverage includes Go formatting/linting (`gofmt`, `goimports`, `golangci-lint`, `go mod tidy`), Dockerfile linting (`hadolint`), YAML linting (`yamllint`), and secret scanning (`detect-secrets`).

### Feature flags

Runtime feature toggles support user evaluation and RBAC-gated admin management.

- User evaluation endpoints:
  - `GET /api/v1/feature-flags`
  - `GET /api/v1/feature-flags/{key}`
- Admin endpoints (require `feature_flags:read` / `feature_flags:write`):
  - `GET|POST /api/v1/admin/feature-flags`
  - `GET|PATCH|DELETE /api/v1/admin/feature-flags/{id}`
  - `GET|POST /api/v1/admin/feature-flags/{id}/rules`
  - `PATCH|DELETE /api/v1/admin/feature-flags/{id}/rules/{rule_id}`

Rule matching precedence during evaluation:
`user` > `role` > `org` > `environment` > `percent` > flag default.

### Products Blueprint Module

Sample `products` CRUD module demonstrates domain/repository/service/handler layering with RBAC-protected routes and paginated list responses.

- Endpoints:
  - `GET /api/v1/products` (requires `products:read`)
  - `GET /api/v1/products/{id}` (requires `products:read`)
  - `POST /api/v1/products` (requires `products:write`)
  - `PUT /api/v1/products/{id}` (requires `products:write`)
  - `DELETE /api/v1/products/{id}` (requires `products:delete`)
- Pagination defaults:
  - `page=1`, `page_size=20`, max `page_size=100`

Endpoints:

- API base URL: `http://localhost:8080`
- Grafana UI: `http://localhost:3000` (`admin` / `admin`)
- MinIO Console: `http://localhost:9001` (`minioadmin` / `minioadmin`)

## Documentation

- [Project guide (full documentation)](docs/project-guide.md)
- [Architecture and flow diagrams](docs/diagrams.md)
- [Kubernetes deployment guide](k8s/README.md)
- [Audit Taxonomy](docs/audit-taxonomy.md)

## License

MIT. See [LICENSE](LICENSE) for details.
