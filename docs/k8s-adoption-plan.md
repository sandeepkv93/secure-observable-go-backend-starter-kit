# Kubernetes + Kind Adoption Plan

## 1) Objective
Adopt a production-aware Kubernetes deployment model for this repository, with first-class local development on Kind, while preserving this repo's current strengths:
- secure auth/session/RBAC behavior
- Redis-backed reliability controls
- tri-signal observability (metrics/logs/traces)
- deterministic CI quality gates

This plan is based on a full review of `sandeepkv93/cloudnative-observable-fullstack`, especially its `k8s/` stack, scripts, overlays, and Task automation, and tuned for this repo's architecture.

## 1.1) Current Status (as of 2026-02-12)
- ✅ Phase 0 complete (design, scaffold, naming, docs)
- ✅ Phase 1 complete (base API+Postgres+Redis manifests)
- ✅ Phase 2 complete (Kind scripts + full Task alias parity)
- ✅ Phase 3 complete (observability overlays: base/dev/ci/prod-like/prod-like-ha)
- ✅ Phase 4 baseline complete (k8s-kind-smoke, manifest validation, OPA policy checks)
- ✅ OPA scoped exemptions burned down to zero
- ✅ `kubeconform` runs in strict mode without `-ignore-missing-schemas`
- 🔄 Remaining hardening is operational/SRE depth (retention/capacity tuning, rollout strategy, secret manager adoption)


## 2) What The Reference Repo Does Well (to reuse)
The reference setup already demonstrates a complete local-Kubernetes experience:
- `k8s/` split into `base/` + `overlays/development/` with Kustomize
- Kind cluster configs and setup script (`k8s/kind-config*.yaml`, `k8s/scripts/kind-setup.sh`)
- script automation for deploy/status/cleanup/secrets
- task aliases for one-command workflows (`task k8s:setup-full`, `task k8s:status`, etc.)
- observability stack components wired together (Grafana, Mimir, Loki, Tempo, OTel Collector)
- optional NodePort and ingress flows for easy local access

## 3) What To Improve Over The Reference (recommended)
Some reference choices are convenient but not ideal for this repo. Improve these from day one:
- Pin image versions (avoid `:latest`) for reproducibility.
- Avoid storing generated secret manifests in workspace by default; prefer `kubectl create secret` from env/file or encrypted manifests (SOPS/age).
- Avoid hard-coded admin passwords in ConfigMaps.
- Minimize root/privileged containers unless strictly required.
- Keep local dev profile lean: API + Postgres + Redis mandatory, observability optional overlay.
- Use readiness/liveness/startup probes aligned to this app's real endpoints (`/health/live`, `/health/ready`, `/metrics`).
- Add a CI Kind smoke test that validates manifests and startup (not full platform e2e every PR).

## 4) Target Architecture For This Repo
This repo is backend-only, so the Kubernetes architecture should be slimmer than the reference fullstack.

### Mandatory (MVP)
- Namespace: `secure-observable`
- API Deployment + Service
- Postgres StatefulSet + Service + PVC
- Redis StatefulSet + Service + PVC
- ConfigMap + Secret wiring for `.env.example` equivalents
- Optional ingress for `/` -> API service

### Optional overlays
- `overlays/observability`: OTel Collector + Tempo + Loki + Mimir + Grafana
- `overlays/dev`: NodePort access, reduced resources, debug toggles
- `overlays/ci`: minimal resources and stricter startup/wait behavior for CI

## 5) Proposed Repository Structure
Create:

```text
k8s/
  README.md
  kind-config.yaml
  kind-config-simple.yaml
  base/
    kustomization.yaml
    namespace.yaml
    configmaps/
      app-config.yaml
      otel-collector-config.yaml
      kustomization.yaml
    secrets/
      app-secrets.env.template
      db-secrets.env.template
      kustomization.yaml
    deployments/
      api.yaml
      postgres.yaml
      redis.yaml
      kustomization.yaml
    services/
      api-service.yaml
      postgres-service.yaml
      redis-service.yaml
      kustomization.yaml
    persistentvolumes/
      local-storage-class.yaml
      claims/
        postgres-pvc.yaml
        redis-pvc.yaml
        kustomization.yaml
      kustomization.yaml
    ingress/
      ingress.yaml
      kustomization.yaml
  overlays/
    development/
      kustomization.yaml
      patches/
        resources.yaml
        replicas.yaml
        nodeports.yaml
        env-debug.yaml
    observability/
      kustomization.yaml
      configmaps/
      deployments/
      services/
      pvc/
    ci/
      kustomization.yaml
      patches/
  scripts/
    kind-setup.sh
    deploy.sh
    status.sh
    cleanup.sh
    setup-secrets.sh
```

## 6) Config + Secret Mapping Strategy
Split environment variables by sensitivity and operational ownership.

### ConfigMap candidates (non-sensitive)
- `APP_ENV`, `HTTP_PORT`
- feature toggles (`AUTH_GOOGLE_ENABLED`, `AUTH_LOCAL_ENABLED`, cache/rate-limit toggles)
- timeout/rate values
- OTEL non-secret values (`OTEL_SERVICE_NAME`, `OTEL_ENVIRONMENT`, sampling ratio)
- `REDIS_ADDR` host/port (without credential)

### Secret candidates
- `DATABASE_URL` (or DB user/pass components)
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `REFRESH_TOKEN_PEPPER`, `OAUTH_STATE_SECRET`
- `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`
- Redis auth material (`REDIS_PASSWORD`, optional TLS cert references)

### Better-than-reference secret flow
Prefer one of:
1. `kubectl create secret generic ... --from-env-file=.secrets/k8s/app.env`
2. SOPS-encrypted secret files committed safely

Avoid plaintext secret YAML in git.

## 7) Phased Implementation Plan

## Phase 0: Design + Guardrails (Completed)
- Add `docs/k8s-adoption-plan.md` (this doc).
- Decide local namespace (`secure-observable`) and service DNS names.
- Decide whether observability ships in MVP or separate overlay.

Deliverables:
- finalized folder scaffold under `k8s/`
- naming conventions doc in `k8s/README.md`

## Phase 1: Base Kubernetes MVP (API + DB + Redis) (Completed)
- Create `k8s/base` manifests with Kustomize entrypoints.
- API Deployment uses existing image and env wiring from ConfigMap/Secret.
- Add probes:
  - liveness: `/health/live`
  - readiness: `/health/ready`
  - optional metrics endpoint checks via ServiceMonitor later
- Postgres/Redis StatefulSets + PVCs (local storage class for Kind/dev).
- Add Service resources and optional base ingress.

Validation:
- `kubectl apply -k k8s/base`
- `kubectl rollout status` for api/postgres/redis
- `curl` health endpoints through port-forward/NodePort

## Phase 2: Kind Local Workflow (Completed)
- Add `k8s/kind-config.yaml` with ingress-ready control-plane and required port mappings.
- Add `k8s/scripts/kind-setup.sh`:
  - prereq checks (`kind`, `kubectl`, docker)
  - cluster create/reset
  - ingress-nginx install + wait
  - optional metrics-server install
- Add `k8s/scripts/setup-secrets.sh` for local secret bootstrap (env-file based).
- Add `taskfiles/k8s.yaml` and root Taskfile include + aliases:
  - `task k8s:cluster-create`
  - `task k8s:secrets-apply`
  - `task k8s:deploy-dev`
  - `task k8s:status`
  - `task k8s:cleanup`

Validation:
- one-command local bring-up (`task k8s:setup-full`)
- deterministic teardown/recreate

## Phase 3: Observability Overlay (Completed)
- Implement `k8s/overlays/observability` for:
  - OTel Collector
  - Tempo/Loki/Mimir
  - Grafana + provisioning configs
- Keep this overlay optional in local dev to reduce resource pressure.
- Reuse existing compose config files where possible (`configs/otel-collector-config.yaml`, `configs/tempo.yaml`, `configs/loki.yaml`, `configs/mimir.yaml`) by translating to ConfigMaps.

Validation:
- telemetry from API reaches collector and backends
- Grafana dashboards load and query traces/logs/metrics

## Phase 4: CI and Policy Integration (Completed baseline)
- Add CI job: `k8s-kind-smoke` (manual trigger + PR optional/nightly):
  - create Kind cluster
  - apply `k8s/overlays/ci` (lean profile)
  - wait for readiness
  - run smoke checks (`/health/live`, `/health/ready`)
  - destroy cluster
- Add lint/validation:
  - `kustomize build` checks for all overlays
  - schema validation (`kubeconform`/`kubeval`)
- Optional: policy checks with `conftest`/OPA for baseline hardening.

## 8) Taskfile Additions (proposed)
In `taskfiles/k8s.yaml`:
- `k8s:cluster-create`, `k8s:cluster-delete`, `k8s:cluster-reset`
- `k8s:secrets-generate`, `k8s:secrets-apply`
- `k8s:deploy-base`, `k8s:deploy-dev`, `k8s:deploy-observability`
- `k8s:status`, `k8s:logs-api`, `k8s:port-forward-api`, `k8s:port-forward-grafana`
- `k8s:health-check`, `k8s:cleanup`
- `k8s:setup-full` (cluster + ingress + secrets + deploy + wait)

## 9) Key Decisions Required Before Implementation
- Whether observability stack is in default local deploy or separate overlay.
- Secret management approach for repo policy (env-file only vs SOPS).
- API ingress strategy for local (`NodePort` only vs ingress + hostnames).
- CI scope: PR smoke only or nightly full Kind integration.

## 10) Risks and Mitigations
- Resource pressure on local machines:
  - Mitigation: default lean overlay, optional observability overlay, reduced requests/limits in dev.
- Secret leakage risk:
  - Mitigation: no plaintext secret YAML committed; use env-file or encrypted secrets.
- Config drift between compose and k8s:
  - Mitigation: single source configs under `configs/` and generated ConfigMaps.
- Operational complexity:
  - Mitigation: script + task wrappers with clear status and troubleshooting commands.

## 11) Acceptance Criteria
The migration is successful when:
- `task k8s:setup-full` creates cluster and deploys base stack end-to-end locally.
- API is reachable and healthy via Kubernetes path.
- Postgres/Redis are stable with persistent volumes in local mode.
- Optional observability overlay works and receives telemetry.
- CI has at least one automated Kind smoke validation path.
- Documentation under `k8s/README.md` is sufficient for a fresh clone setup.

## 12) Recommended Execution Order
1. Phase 1 (base manifests)
2. Phase 2 (kind + scripts + task automation)
3. Phase 4 minimal CI smoke
4. Phase 3 observability overlay (optional but recommended)

This order gets reliable Kubernetes parity quickly, then layers observability complexity safely.

## 13) Phase 5: Operational Hardening Backlog (Next)

### 13.1 In progress (this batch)
- Added app `prod-like` overlay at `k8s/overlays/prod-like`.
- Added API rollout hardening:
  - replicas: 2
  - rolling update: `maxUnavailable: 0`, `maxSurge: 1`
- Added API PodDisruptionBudget (`minAvailable: 1`).
- Wired `prod-like` into deployment automation and task aliases.
- Extended CI manifest/policy target lists to include `k8s/overlays/prod-like`.

### 13.2 Remaining backlog
- Secret lifecycle hardening:
  - ✅ added optional `k8s/overlays/secrets/external-secrets` path with CI validation hook.
  - ✅ added concrete ClusterSecretStore overlays for AWS and Vault with CI validation.
  - ✅ added environment-scoped ExternalSecret overlays (`dev|staging|prod`) using explicit remote key paths.
  - ✅ added auth-mode-specific ClusterSecretStore overlays (AWS IRSA/static, Vault Kubernetes/token) with CI validation.
  - next: wire environment-specific IAM/Vault roles and secret names per cluster in platform IaC.
  - keep SOPS as fallback for non-cloud local workflows.
- Capacity and retention hardening:
  - ✅ finalized baseline retention and storage sizing defaults for Tempo/Loki/Mimir in `observability-prod-like`.
  - ✅ added operational threshold check (`task k8s:obs-capacity-check`) for PVC capacity floor and restart/backpressure proxy signals.
  - next: integrate metric-native alerting (PVC usage %, ingestion queue pressure) with cluster Prometheus stack.
- Availability hardening:
  - ✅ default API replica policy set for non-dev baseline (`prod-like`: replicas 2, maxUnavailable 0, maxSurge 1).
  - ✅ defined PDB strategy for stateful data services (`postgres` and `redis`: minAvailable 1 in prod-like).
  - next: extend availability profiles for environment-specific maintenance windows (e.g., staging vs prod).
- Rollout safety:
  - ✅ implemented staged rollout overlays by environment (`staging` and `production`) with guarded rollout windows.
  - next: evaluate canary/blue-green controller adoption (e.g., Argo Rollouts) if progressive traffic shifting is required.
