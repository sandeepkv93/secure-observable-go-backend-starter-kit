#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"

kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || {
  echo "Namespace '${NAMESPACE}' not found"
  exit 0
}

kubectl -n "${NAMESPACE}" get pods,svc,ingress,pvc
