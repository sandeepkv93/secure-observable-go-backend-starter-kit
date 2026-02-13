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
    prod-like)
      if [[ -d "k8s/overlays/prod-like" ]]; then
        echo "k8s/overlays/prod-like"
      else
        echo ""
      fi
      ;;
    staging)
      if [[ -d "k8s/overlays/staging" ]]; then
        echo "k8s/overlays/staging"
      else
        echo ""
      fi
      ;;
    production)
      if [[ -d "k8s/overlays/production" ]]; then
        echo "k8s/overlays/production"
      else
        echo ""
      fi
      ;;
    observability)
      if [[ -d "k8s/overlays/observability" ]]; then
        echo "k8s/overlays/observability"
      else
        echo ""
      fi
      ;;
    observability-dev)
      if [[ -d "k8s/overlays/observability/dev" ]]; then
        echo "k8s/overlays/observability/dev"
      else
        echo ""
      fi
      ;;
    observability-ci)
      if [[ -d "k8s/overlays/observability/ci" ]]; then
        echo "k8s/overlays/observability/ci"
      else
        echo ""
      fi
      ;;
    observability-prod-like)
      if [[ -d "k8s/overlays/observability/prod-like" ]]; then
        echo "k8s/overlays/observability/prod-like"
      else
        echo ""
      fi
      ;;
    observability-prod-like-ha)
      if [[ -d "k8s/overlays/observability/prod-like-ha" ]]; then
        echo "k8s/overlays/observability/prod-like-ha"
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
  echo "Usage: $0 [base|development|prod-like|staging|production|observability|observability-dev|observability-ci|observability-prod-like|observability-prod-like-ha]" >&2
  exit 1
fi

kubectl apply -k "${TARGET}"

if [[ "${PROFILE}" == "base" || "${PROFILE}" == "development" || "${PROFILE}" == "dev" || "${PROFILE}" == "prod-like" || "${PROFILE}" == "staging" || "${PROFILE}" == "production" ]]; then
  kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status statefulset/redis --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/secure-observable-api --timeout=240s
fi

if [[ "${PROFILE}" == observability* ]]; then
  kubectl -n "${NAMESPACE}" rollout restart deployment/secure-observable-api
  kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status statefulset/redis --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/secure-observable-api --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/otel-collector --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/tempo --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/loki --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/mimir --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status deployment/grafana --timeout=240s
fi

echo "Deployed profile '${PROFILE}' from ${TARGET}"
