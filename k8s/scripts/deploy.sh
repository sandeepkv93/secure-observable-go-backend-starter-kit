#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"
PROFILE="${1:-base}"

resolve_target() {
  case "${PROFILE}" in
    base)
      echo "k8s/base"
      ;;
    development|dev)
      if [[ -d "k8s/overlays/development" ]]; then
        echo "k8s/overlays/development"
      else
        echo "k8s/base"
      fi
      ;;
    observability)
      if [[ -d "k8s/overlays/observability" ]]; then
        echo "k8s/overlays/observability"
      else
        echo ""
      fi
      ;;
    *)
      echo ""
      ;;
  esac
}

TARGET="$(resolve_target)"
if [[ -z "${TARGET}" ]]; then
  echo "Unknown or unavailable profile '${PROFILE}'" >&2
  echo "Usage: $0 [base|development|observability]" >&2
  exit 1
fi

kubectl apply -k "${TARGET}"

if [[ "${PROFILE}" == "base" || "${PROFILE}" == "development" || "${PROFILE}" == "dev" ]]; then
  kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status statefulset/redis --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/secure-observable-api --timeout=240s
fi

echo "Deployed profile '${PROFILE}' from ${TARGET}"
