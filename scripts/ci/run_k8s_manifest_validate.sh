#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

for tool in kustomize kubeconform; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ci: missing required tool: ${tool}" >&2
    exit 1
  fi
done

KUBE_VERSION="${KUBE_VERSION:-1.30.0}"

KUSTOMIZATION_TARGETS=(
  "k8s/base"
  "k8s/overlays/development"
  "k8s/overlays/prod-like"
  "k8s/overlays/staging"
  "k8s/overlays/production"
  "k8s/overlays/observability-base"
  "k8s/overlays/observability"
  "k8s/overlays/observability/dev"
  "k8s/overlays/observability/ci"
  "k8s/overlays/observability/prod-like"
  "k8s/overlays/observability/prod-like-ha"
)

for target in "${KUSTOMIZATION_TARGETS[@]}"; do
  echo "ci: kustomize build ${target}"
  manifest_file="$(mktemp /tmp/kustomize-manifest.XXXXXX.yaml)"
  kustomize build "${target}" >"${manifest_file}"

  echo "ci: kubeconform ${target}"
  kubeconform \
    -strict \
    -summary \
    -kubernetes-version "${KUBE_VERSION}" \
    "${manifest_file}"

  rm -f "${manifest_file}"
done

echo "ci: k8s manifest validation passed"
