# Secure Observable Go Backend Starter Kit

[![CI](https://github.com/sandeepkv93/secure-observable-go-backend-starter-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeepkv93/secure-observable-go-backend-starter-kit/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24.13-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Starter Overview

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

Architecture overview:

- Request path:
  Chi router + middleware chain (`internal/http/router`) -> handler layer (`internal/http/handler`) -> service layer (`internal/service`) -> repository layer (`internal/repository`) -> GORM + Postgres (`internal/database`)
- Cross-cutting:
  security middleware for headers, CSRF, request ID, and rate limiting; Redis-backed caching and limiter policies; structured logging with trace/span correlation fields; OTel tracing, metrics (with exemplars), and logs export via collector
- Dependency injection:
  providers and wiring in `internal/di`, with generated wiring verified in CI

```mermaid
flowchart LR
    User[Web or API Client] --> Router[Chi Router + Middleware]
    Router --> Handlers[HTTP Handlers]
    Handlers --> Services[Service Layer]
    Services --> Repos[Repository Layer]
    Repos --> DB[(PostgreSQL)]
    Services --> Redis[(Redis)]

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

Prerequisites:

- Go `1.24.13`
- [Task](https://taskfile.dev/)
- [Bazelisk](https://github.com/bazelbuild/bazelisk)
- Docker + Docker Compose

Run locally:

```bash
task docker-up
task migrate
task seed
task run
```

Useful commands:

```bash
task test
task ci
task obs-generate-traffic
task obs-validate
```

## Documentation

- Project guide (full documentation): `docs/project-guide.md`
- Architecture and flow diagrams: `docs/diagrams.md`
- Audit taxonomy: `docs/audit-taxonomy.md`

Key folders:

- API server: `cmd/api`
- Internal app packages: `internal/`
- Configuration and observability stack: `configs/`
- Integration tests: `test/integration/`
- Task definitions: `taskfiles/`

## License

MIT. See `LICENSE`.
