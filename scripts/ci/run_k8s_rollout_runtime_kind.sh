#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"
ROLLOUT_NAME="${ROLLOUT_NAME:-secure-observable-api}"
ROLLOUT_ENV="${ROLLOUT_ENV:-staging}"
EVIDENCE_DIR="${EVIDENCE_DIR:-.artifacts/k8s-rollout-evidence}"
API_PORT="${K8S_RUNTIME_API_PORT:-18080}"
MIMIR_PORT="${K8S_RUNTIME_MIMIR_PORT:-19009}"

mkdir -p "${EVIDENCE_DIR}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "runtime-kind: missing required tool: $1" >&2
    exit 1
  fi
}

for tool in kubectl go curl jq task; do
  require_cmd "${tool}"
done

install_rollouts_controller() {
  if kubectl get crd rollouts.argoproj.io >/dev/null 2>&1; then
    echo "runtime-kind: rollouts CRD already installed"
  else
    echo "runtime-kind: installing Argo Rollouts controller"
    kubectl create namespace argo-rollouts >/dev/null 2>&1 || true
    kubectl apply -n argo-rollouts -f "https://github.com/argoproj/argo-rollouts/releases/download/v1.7.2/install.yaml"
  fi

  kubectl -n argo-rollouts rollout status deployment/argo-rollouts --timeout=240s
}

start_port_forward() {
  local resource="$1"
  local ports="$2"
  local logfile="$3"

  kubectl -n "${NAMESPACE}" port-forward "${resource}" "${ports}" >"${logfile}" 2>&1 &
  echo $!
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-20}"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "runtime-kind: timed out waiting for ${url}" >&2
  return 1
}

capture_rollout_state() {
  kubectl -n "${NAMESPACE}" get rollout "${ROLLOUT_NAME}" -o yaml >"${EVIDENCE_DIR}/rollout.yaml"
  kubectl -n "${NAMESPACE}" get pods -o wide >"${EVIDENCE_DIR}/pods.txt"
  kubectl -n "${NAMESPACE}" get svc >"${EVIDENCE_DIR}/services.txt"
  kubectl -n "${NAMESPACE}" get events --sort-by=.lastTimestamp | tail -n 200 >"${EVIDENCE_DIR}/events.txt" || true
}

capture_slo_queries() {
  local prom_base="http://127.0.0.1:${MIMIR_PORT}/prometheus"

  curl -fsS --get --data-urlencode 'query=sum(rate(http_server_request_duration_seconds_count{http_response_status_code=~"5.."}[5m])) / clamp_min(sum(rate(http_server_request_duration_seconds_count[5m])),1)' "${prom_base}/api/v1/query" >"${EVIDENCE_DIR}/query_api_5xx_ratio.json" || true
  curl -fsS --get --data-urlencode 'query=max(redis_command_error_rate_ratio)' "${prom_base}/api/v1/query" >"${EVIDENCE_DIR}/query_redis_error_ratio.json" || true
  curl -fsS --get --data-urlencode 'query=max(redis_pool_saturation_ratio)' "${prom_base}/api/v1/query" >"${EVIDENCE_DIR}/query_redis_pool_saturation_ratio.json" || true
}

main() {
  install_rollouts_controller

  echo "runtime-kind: deploying observability-ci"
  task k8s:deploy-observability-ci

  echo "runtime-kind: deploying rollout-bluegreen"
  task k8s:deploy-rollout-bluegreen

  if ! kubectl argo rollouts version >/dev/null 2>&1; then
    echo "runtime-kind: kubectl argo rollouts plugin is required" >&2
    exit 1
  fi

  echo "runtime-kind: creating preview revision via rollout restart"
  kubectl argo rollouts restart "${ROLLOUT_NAME}" -n "${NAMESPACE}"

  echo "runtime-kind: waiting for rollout to progress"
  kubectl argo rollouts get rollout "${ROLLOUT_NAME}" -n "${NAMESPACE}" >"${EVIDENCE_DIR}/rollout-get.txt"

  local api_pf_pid="" mimir_pf_pid=""
  cleanup_port_forwards() {
    local pid
    for pid in "${api_pf_pid:-}" "${mimir_pf_pid:-}"; do
      if [[ -n "${pid}" ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
    done
  }
  trap cleanup_port_forwards EXIT

  api_pf_pid="$(start_port_forward svc/secure-observable-api "${API_PORT}:8080" "${EVIDENCE_DIR}/portforward-api.log")"
  mimir_pf_pid="$(start_port_forward svc/mimir "${MIMIR_PORT}:9009" "${EVIDENCE_DIR}/portforward-mimir.log")"

  wait_for_http "http://127.0.0.1:${API_PORT}/health/live" 30
  wait_for_http "http://127.0.0.1:${MIMIR_PORT}/ready" 40 || true

  echo "runtime-kind: generating representative traffic"
  go run ./cmd/loadgen run --ci --base-url "http://127.0.0.1:${API_PORT}" --duration 35s --rps 18 --concurrency 8 >"${EVIDENCE_DIR}/loadgen.txt"

  echo "runtime-kind: running rollout precheck with observability gate enabled"
  K8S_NAMESPACE="${NAMESPACE}" \
  ROLLOUT_NAME="${ROLLOUT_NAME}" \
  ROLLOUT_ENV="${ROLLOUT_ENV}" \
  ROLLOUT_REQUIRE_OBS_STAGING=true \
  MIMIR_PROM_URL="http://127.0.0.1:${MIMIR_PORT}/prometheus" \
  bash k8s/scripts/rollout-precheck.sh | tee "${EVIDENCE_DIR}/rollout-precheck.txt"

  capture_rollout_state
  capture_slo_queries

  echo "runtime-kind: PASSED"
}

main "$@"
