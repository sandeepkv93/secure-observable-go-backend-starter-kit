# Direct Cutover Plan: Grafana Dashboards to Jsonnet/Grafonnet

## Summary
Switch immediately to Jsonnet as the only authored format for Grafana dashboards.
Static JSON dashboard files become generated artifacts only (still committed and still consumed by Docker Compose + k8s ConfigMaps).

## Goal
Replace hand-maintained files in:
- `configs/grafana/dashboards/*.json`
- `k8s/overlays/observability-base/configmaps/dashboards/*.json`

with generated outputs from Jsonnet/Grafonnet sources, while keeping runtime behavior unchanged.

## Scope
### In scope
- Dashboard IaC source tree (`jsonnet`, `libsonnet`).
- Dashboard generation script + CI checks.
- Task commands for local generation/validation.
- Runtime verification in existing k8s smoke flow.
- Documentation in `docs/`.

### Out of scope
- Prometheus alert-rule IaC conversion.
- Datasource/provisioning redesign.
- Grafana version upgrade.

## Locked Decisions
1. Mode: direct cutover (no shadow phase).
2. Grafonnet dependency: pinned versioned path + lock file.
3. Pin target: `github.com/grafana/grafonnet/gen/grafonnet-v10.4.0@main` (aligned with Grafana `10.4.5` image).
4. Generated JSON committed: yes (required by current deploy model).
5. Deployment paths unchanged: yes (no k8s/docker path churn).
6. Vendor strategy: do not commit `vendor/**`; keep `jsonnetfile.lock.json`, ignore `vendor/`, and bootstrap via `jb install` in generator/check scripts.

## Target Layout
Create:
- `configs/grafana/jsonnet/jsonnetfile.json`
- `configs/grafana/jsonnet/jsonnetfile.lock.json`
- `configs/grafana/jsonnet/.gitignore` (ignores `vendor/`)
- `configs/grafana/jsonnet/g.libsonnet`
- `configs/grafana/jsonnet/lib/dashboard.libsonnet`
- `configs/grafana/jsonnet/lib/panels.libsonnet`
- `configs/grafana/jsonnet/lib/queries/common.libsonnet`
- `configs/grafana/jsonnet/lib/queries/api.libsonnet`
- `configs/grafana/jsonnet/lib/queries/logs.libsonnet`
- `configs/grafana/jsonnet/lib/queries/traces.libsonnet`
- `configs/grafana/jsonnet/dashboards/api-overview.jsonnet`
- `configs/grafana/jsonnet/dashboards/logs-overview.jsonnet`
- `configs/grafana/jsonnet/dashboards/trace-overview.jsonnet`
- `configs/grafana/jsonnet/render.jsonnet`
- `scripts/grafana/generate_dashboards.sh`
- `scripts/ci/run_grafana_dashboards_generate_check.sh`
- `scripts/ci/run_grafana_dashboards_runtime_check.sh`
- `docs/grafana-jsonnet.md`

Keep existing outputs (generated):
- `configs/grafana/dashboards/*.json`
- `k8s/overlays/observability-base/configmaps/dashboards/*.json`

## Implementation Sequence
1. Bootstrap Jsonnet toolchain and pinned grafonnet dependencies via `jsonnetfile.lock.json` + on-demand `jb install`.
2. Build reusable query/panel/dashboard helper modules.
3. Author three dashboard Jsonnet definitions.
4. Add deterministic generator writing both output directories.
5. Add CI enforcement (generate + diff check).
6. Add runtime Grafana API check in kind smoke workflow.
7. Add Task aliases for developer workflow.
8. Update docs for authored-vs-generated contract.

## Validation Matrix
- Jsonnet render compiles for all dashboards.
- Generator idempotent (second run => no diff).
- Generated JSON parseable with `jq`.
- UIDs unchanged: `api-overview`, `logs-overview`, `trace-overview`.
- k8s kind smoke confirms dashboards are discoverable via Grafana API.
- CI fails on stale generated artifacts.

## Rollback
Single-commit rollback by reverting migration commit(s). Output paths remain unchanged, so deployment rollback is non-disruptive.

## Success Criteria
- Jsonnet is sole authored dashboard format.
- 3 dashboards generated and deployed through existing paths.
- CI enforces regeneration.
- k8s runtime smoke confirms dashboards are present in Grafana.
- Contributor docs are updated end-to-end.
