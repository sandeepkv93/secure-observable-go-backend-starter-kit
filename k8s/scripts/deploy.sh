#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-secure-observable}"
PROFILE="${1:-base}"
API_IMAGE="${API_IMAGE:-}"
ALLOW_DEV_IMAGE_IN_NON_DEV="${ALLOW_DEV_IMAGE_IN_NON_DEV:-false}"
DEFAULT_DEV_IMAGE="secure-observable-api:dev"

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
    rollout-bluegreen)
      if [[ -d "k8s/overlays/rollouts/blue-green" ]]; then
        echo "k8s/overlays/rollouts/blue-green"
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

is_non_dev_profile() {
  case "${PROFILE}" in
    prod-like|staging|production|rollout-bluegreen|observability-prod-like|observability-prod-like-ha)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

effective_api_image() {
  if [[ -n "${API_IMAGE}" ]]; then
    echo "${API_IMAGE}"
  else
    echo "${DEFAULT_DEV_IMAGE}"
  fi
}

validate_image_strategy() {
  local image
  image="$(effective_api_image)"

  if is_non_dev_profile && [[ "${image}" == "${DEFAULT_DEV_IMAGE}" ]] && [[ "${ALLOW_DEV_IMAGE_IN_NON_DEV}" != "true" ]]; then
    echo "Refusing deploy for profile '${PROFILE}' with dev image '${DEFAULT_DEV_IMAGE}'." >&2
    echo "Set API_IMAGE to a pinned release image (tag or digest) for non-dev deploys." >&2
    echo "Use ALLOW_DEV_IMAGE_IN_NON_DEV=true only for explicit break-glass testing." >&2
    exit 1
  fi
}

apply_api_image_override() {
  if [[ -z "${API_IMAGE}" ]]; then
    return 0
  fi

  echo "Applying API image override: ${API_IMAGE}"

  if [[ "${PROFILE}" == "rollout-bluegreen" ]]; then
    kubectl -n "${NAMESPACE}" patch rollout secure-observable-api \
      --type='json' \
      -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"${API_IMAGE}\"}]"
    return 0
  fi

  kubectl -n "${NAMESPACE}" set image deployment/secure-observable-api api="${API_IMAGE}"
}

TARGET="$(resolve_target)"
if [[ -z "${TARGET}" ]]; then
  echo "Unknown or unavailable profile '${PROFILE}'" >&2
  echo "Usage: $0 [base|development|prod-like|staging|production|rollout-bluegreen|observability|observability-dev|observability-ci|observability-prod-like|observability-prod-like-ha]" >&2
  exit 1
fi

validate_image_strategy

kubectl apply -k "${TARGET}"
apply_api_image_override

if [[ "${PROFILE}" == "base" || "${PROFILE}" == "development" || "${PROFILE}" == "dev" || "${PROFILE}" == "prod-like" || "${PROFILE}" == "staging" || "${PROFILE}" == "production" || "${PROFILE}" == "rollout-bluegreen" ]]; then
  kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=240s
  kubectl -n "${NAMESPACE}" rollout status statefulset/redis --timeout=240s

  if [[ "${PROFILE}" == "rollout-bluegreen" ]]; then
    kubectl -n "${NAMESPACE}" rollout status rollout/secure-observable-api --timeout=240s
  else
    kubectl -n "${NAMESPACE}" rollout status deployment/secure-observable-api --timeout=240s
  fi
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
