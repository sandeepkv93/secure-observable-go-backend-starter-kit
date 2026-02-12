#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"
LOCAL_PORT="${K8S_HEALTH_PORT:-18080}"

kubectl -n "${NAMESPACE}" port-forward svc/secure-observable-api "${LOCAL_PORT}:8080" >/tmp/k8s-port-forward.log 2>&1 &
PF_PID=$!
trap 'kill ${PF_PID} >/dev/null 2>&1 || true' EXIT

sleep 3
curl -fsS "http://127.0.0.1:${LOCAL_PORT}/health/live" >/dev/null
curl -fsS "http://127.0.0.1:${LOCAL_PORT}/health/ready" >/dev/null

echo "Health checks passed"
