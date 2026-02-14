#!/usr/bin/env bash
set -euo pipefail

MIMIR_PROM_URL="${MIMIR_PROM_URL:-http://localhost:9009/prometheus}"
API_JOB="${API_JOB:-secure-observable-go-backend-starter-kit}"
K8S_NAMESPACE="${K8S_NAMESPACE:-secure-observable}"

API_5XX_MAX="${ALERT_API_5XX_MAX:-0.05}"
REDIS_ERR_MAX="${ALERT_REDIS_ERR_MAX:-0.05}"
REDIS_SAT_MAX="${ALERT_REDIS_SAT_MAX:-0.90}"
PVC_USAGE_MAX="${ALERT_PVC_USAGE_MAX:-0.85}"
OTEL_QUEUE_MAX="${ALERT_OTEL_QUEUE_MAX:-0.80}"

REQUIRE_API_5XX_METRICS="${REQUIRE_API_5XX_METRICS:-false}"
REQUIRE_PVC_METRICS="${REQUIRE_PVC_METRICS:-false}"
REQUIRE_OTEL_QUEUE_METRICS="${REQUIRE_OTEL_QUEUE_METRICS:-false}"

for tool in curl jq awk; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "obs-alert-check: missing required tool: ${tool}" >&2
    exit 1
  fi
done

query_scalar() {
  local query="$1"
  local resp
  resp="$(curl -fsS --get --data-urlencode "query=${query}" "${MIMIR_PROM_URL}/api/v1/query")"
  local status
  status="$(echo "${resp}" | jq -r '.status')"
  if [[ "${status}" != "success" ]]; then
    echo "obs-alert-check: query failed: ${query}" >&2
    return 1
  fi
  local count
  count="$(echo "${resp}" | jq '.data.result | length')"
  if [[ "${count}" == "0" ]]; then
    echo ""
    return 0
  fi
  echo "${resp}" | jq -r '.data.result[0].value[1]'
}

check_threshold() {
  local label="$1"
  local value="$2"
  local threshold="$3"

  if [[ -z "${value}" ]]; then
    echo "WARN: ${label}: no data"
    return 2
  fi

  if awk -v v="${value}" -v t="${threshold}" 'BEGIN { exit !(v <= t) }'; then
    echo "OK: ${label}: ${value} <= ${threshold}"
    return 0
  fi

  echo "ERROR: ${label}: ${value} > ${threshold}"
  return 1
}

status=0

api_5xx_query="sum(rate(http_server_request_duration_seconds_count{job=\"${API_JOB}\",http_response_status_code=~\"5..\"}[5m])) / clamp_min(sum(rate(http_server_request_duration_seconds_count{job=\"${API_JOB}\"}[5m])), 1)"
redis_err_query="max(redis_command_error_rate_ratio{job=\"${API_JOB}\"})"
redis_sat_query="max(redis_pool_saturation_ratio{job=\"${API_JOB}\"})"
pvc_usage_query="max(kubelet_volume_stats_used_bytes{namespace=\"${K8S_NAMESPACE}\",persistentvolumeclaim=~\"tempo-data|loki-data|mimir-data|grafana-data\"} / kubelet_volume_stats_capacity_bytes{namespace=\"${K8S_NAMESPACE}\",persistentvolumeclaim=~\"tempo-data|loki-data|mimir-data|grafana-data\"})"
otel_queue_query="max(otelcol_exporter_queue_size / clamp_min(otelcol_exporter_queue_capacity, 1))"

api_5xx_val="$(query_scalar "${api_5xx_query}")"
redis_err_val="$(query_scalar "${redis_err_query}")"
redis_sat_val="$(query_scalar "${redis_sat_query}")"
pvc_usage_val="$(query_scalar "${pvc_usage_query}")"
otel_queue_val="$(query_scalar "${otel_queue_query}")"

check_threshold "api_5xx_rate_ratio" "${api_5xx_val}" "${API_5XX_MAX}" || {
  rc=$?
  if [[ "${rc}" -eq 2 && "${REQUIRE_API_5XX_METRICS}" != "true" ]]; then
    echo "WARN: api 5xx metrics missing; set REQUIRE_API_5XX_METRICS=true to enforce"
  else
    status=1
  fi
}
check_threshold "redis_command_error_rate_ratio" "${redis_err_val}" "${REDIS_ERR_MAX}" || status=$?
check_threshold "redis_pool_saturation_ratio" "${redis_sat_val}" "${REDIS_SAT_MAX}" || status=$?

check_threshold "pvc_usage_ratio" "${pvc_usage_val}" "${PVC_USAGE_MAX}" || {
  rc=$?
  if [[ "${rc}" -eq 2 && "${REQUIRE_PVC_METRICS}" != "true" ]]; then
    echo "WARN: pvc usage metrics missing; set REQUIRE_PVC_METRICS=true to enforce"
  else
    status=1
  fi
}

check_threshold "otel_exporter_queue_ratio" "${otel_queue_val}" "${OTEL_QUEUE_MAX}" || {
  rc=$?
  if [[ "${rc}" -eq 2 && "${REQUIRE_OTEL_QUEUE_METRICS}" != "true" ]]; then
    echo "WARN: otel queue metrics missing; set REQUIRE_OTEL_QUEUE_METRICS=true to enforce"
  else
    status=1
  fi
}

if [[ "${status}" -ne 0 ]]; then
  echo "obs-alert-check: FAILED"
  exit 1
fi

echo "obs-alert-check: PASSED"
