# go-oauth-rbac-service
[![CI](https://github.com/sandeepkv93/go-oauth-rbac-service/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeepkv93/go-oauth-rbac-service/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

REST API service in Go with Google OAuth login, JWT auth, secure cookie sessions, RBAC authorization, and OpenTelemetry observability.

## Prerequisites
- Go `1.25.4`
- [Task](https://taskfile.dev/)
- [Bazelisk](https://github.com/bazelbuild/bazelisk) (Bazel-first build/test)
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
- `task bazel:run`

## Bazel
- Build all targets:
  - `task bazel:build`
- Run all Bazel tests:
  - `task bazel:test`
- Regenerate BUILD files with Gazelle:
  - `task gazelle`
- Verify Gazelle left no diffs:
  - `task gazelle:check`

Notes:
- Bazel uses a pinned supported Go SDK (`1.24.11`) via `rules_go`.
- Host `go` remains `1.25.4` for local Go-native tooling.

## Local Observability Stack
- Start local stack with collector + Grafana + Tempo + Loki + Mimir:
  - `task docker-up`
- Services:
  - API: `http://localhost:8080`
  - Grafana: `http://localhost:3000` (default `admin/admin`)
  - Tempo: `http://localhost:3200`
  - Loki: `http://localhost:3100`
  - Mimir: `http://localhost:9009`
  - OTel Collector health: `http://localhost:13133`
- Collector receives OTLP on:
  - gRPC `localhost:4317`
  - HTTP `localhost:4318`

## Test and Checks
- `task ci` (recommended full local gate, Bazel-first)
- `task tidy-check`
- `task wire-check`
- `task test`
- `task lint`
- `task obs-validate` (generates traffic and verifies metric exemplar -> Tempo trace -> Loki log correlation)

## Git Hooks
- Install repository-managed hooks:
  - `task hooks-install`
- Hooks provided:
  - `pre-commit`: gofmt staged `.go` files and `go mod tidy` (stages `go.mod`/`go.sum`)
  - `pre-push`: runs `task ci`

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
- Mimir exemplar ingestion is explicitly enabled via `limits.max_global_exemplars_per_user`.
