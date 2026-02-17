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
