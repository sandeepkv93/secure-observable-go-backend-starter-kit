#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"
DELETE_CLUSTER="${DELETE_CLUSTER:-false}"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-secure-observable}"

kubectl delete ns "${NAMESPACE}" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true

if [[ "${DELETE_CLUSTER}" == "true" ]]; then
  if command -v kind >/dev/null 2>&1; then
    kind delete cluster --name "${CLUSTER_NAME}" || true
  fi
fi

echo "Cleanup complete (namespace deleted, cluster deleted=${DELETE_CLUSTER})"
