# Kubernetes Deployment (Phase 1 + Phase 2 Local Workflow)

This directory contains the initial Kubernetes baseline for:
- API (`secure-observable-api`)
- Postgres
- Redis

The manifests are organized with Kustomize and target local/dev workflows first.

## Prerequisites

- `kubectl` (with Kustomize support)
- Kubernetes cluster (local or remote)
- Docker (if building image locally)
- Optional: `kind` for local cluster workflows
- Optional: `sops` + age keys for encrypted secret workflow

## Layout

```text
k8s/
  kind-config.yaml
  kind-config-simple.yaml
  base/
    kustomization.yaml
    namespace.yaml
    configmaps/
    secrets/
    deployments/
    services/
    persistentvolumes/
    ingress/
  overlays/
    development/
    observability-base/
    observability/
      dev/
      ci/
      prod-like/
      prod-like-ha/
  scripts/
    kind-setup.sh
    setup-secrets.sh
    deploy.sh
    status.sh
    cleanup.sh
    health-check.sh
```

## 1) Create/reset Kind cluster

```bash
task k8s:cluster-create
```

Reset flow:

```bash
task k8s:cluster-reset
```

The setup script installs ingress-nginx and can optionally install metrics-server:

```bash
INSTALL_METRICS_SERVER=true task k8s:cluster-create
```

## 2) Build API image

For local clusters (for example Kind), build the app image first:

```bash
docker build -t secure-observable-api:dev .
```

Or use automation:

```bash
task k8s:image-build-load-kind
```

## 3) Create app secret from template

A template is provided at:

`k8s/base/secrets/app-secrets.env.template`

Create a local copy and set strong values:

```bash
cp k8s/base/secrets/app-secrets.env.template .secrets.k8s.app.env
```

Create/replace Kubernetes secret:

```bash
kubectl -n secure-observable create secret generic app-secrets \
  --from-env-file=.secrets.k8s.app.env \
  --dry-run=client -o yaml | kubectl apply -f -
```

Task wrapper:

```bash
task k8s:secrets-generate
task k8s:secrets-apply
```

External Secrets optional overlays (environment-scoped remote keys):

```bash
task k8s:validate-external-secrets
task k8s:apply-external-secrets-dev
# or
task k8s:apply-external-secrets-staging
# or
task k8s:apply-external-secrets-prod
```

ClusterSecretStore overlays (pick exactly one auth mode per cluster):

```bash
task k8s:validate-secret-stores
# AWS (recommended identity mode)
task k8s:apply-secret-store-aws-irsa
# AWS fallback (static credentials secret)
task k8s:apply-secret-store-aws-static
# Vault (recommended Kubernetes auth mode)
task k8s:apply-secret-store-vault-kubernetes
# Vault fallback (token secret)
task k8s:apply-secret-store-vault-token
```

Encrypted secret path (recommended):

```bash
export SOPS_AGE_RECIPIENTS='age1yourrecipientpublickey'
task k8s:secrets-encrypt
```

When `k8s/secrets/app-secrets.enc.env` exists, `task k8s:secrets-apply`
decrypts and applies that secret instead of plaintext env file.

## 4) Apply manifests

```bash
kubectl apply -k k8s/base
kubectl -n secure-observable rollout status statefulset/postgres
kubectl -n secure-observable rollout status statefulset/redis
kubectl -n secure-observable rollout status deployment/secure-observable-api
```

Task wrappers:

```bash
task k8s:deploy-base
task k8s:rollout
```

Development overlay deploy (NodePort API service):

```bash
task k8s:deploy-dev
```

Production-like app overlay deploy (replicas, rollout strategy, and API PDB):

```bash
task k8s:deploy-prod-like
task k8s:deploy-staging
task k8s:deploy-production
```

Observability overlay deploy:

```bash
task k8s:deploy-observability
task k8s:deploy-observability-dev
task k8s:deploy-observability-ci
task k8s:deploy-observability-prod-like
task k8s:deploy-observability-prod-like-ha
task k8s:obs-status
task k8s:obs-capacity-check
task k8s:port-forward-grafana
```

Observability profile notes:
- `observability` (default) and `observability-dev`: single-replica local profile.
- `observability-ci`: reduced resources for CI-like environments.
- `observability-prod-like`: PVC-backed storage + retention/resource tuning.
- `observability-prod-like-ha`: optional HA knobs for stateless components.

Telemetry correlation validation:

```bash
kubectl -n secure-observable port-forward svc/secure-observable-api 8080:8080
kubectl -n secure-observable port-forward svc/grafana 3000:3000
go run ./cmd/obscheck run --ci --grafana-url http://localhost:3000 --base-url http://localhost:8080
```

## 5) Verify health

```bash
kubectl -n secure-observable port-forward svc/secure-observable-api 8080:8080
curl -sSf http://localhost:8080/health/live
curl -sSf http://localhost:8080/health/ready
```

Task wrapper:

```bash
task k8s:health-check
```

## 6) Common operations

```bash
task k8s:status
task k8s:logs-api
task k8s:port-forward-api
task k8s:cleanup
task k8s:cluster-delete
```

## Notes

- `AUTH_GOOGLE_ENABLED` is disabled in this Phase 1 baseline.
- OPA workload policy currently has zero scoped exemptions (all managed workloads satisfy baseline controls).
- CI manifest schema validation runs in strict mode (no `-ignore-missing-schemas`).
- Observability components are optional overlays and not part of default `k8s:setup-full`.
- Ingress is enabled in base (`secure-observable.local`, `ingressClassName: nginx`).
- One-command local setup is available:

```bash
task k8s:setup-full
```

Observability capacity/retention baseline:
- `observability-prod-like` sets retention defaults to 7 days for Tempo/Loki/Mimir.
- PVC minimum requested storage thresholds:
  - Tempo: `2Gi`
  - Loki: `4Gi`
  - Mimir: `5Gi`
  - Grafana: `2Gi`
- Use `task k8s:obs-capacity-check` to validate PVC size floor and restart/backpressure proxy thresholds.

prod-like availability defaults:
- API runs with `replicas: 2` and rolling strategy `maxUnavailable: 0`, `maxSurge: 1`.
- PodDisruptionBudgets in prod-like:
  - API: `minAvailable: 1`
  - Postgres: `minAvailable: 1`
  - Redis: `minAvailable: 1`

staged rollout strategy:
- `staging` overlay: API `replicas: 2`, `minReadySeconds: 20`, `progressDeadlineSeconds: 600`.
- `production` overlay: API `replicas: 3`, `minReadySeconds: 30`, `progressDeadlineSeconds: 900`.
- both keep `maxUnavailable: 0` and `maxSurge: 1` to avoid capacity drops during rollout.
