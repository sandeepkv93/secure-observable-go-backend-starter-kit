#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

for tool in kustomize conftest; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ci: missing required tool: ${tool}" >&2
    exit 1
  fi
done

validate_overlay() {
  local overlay="$1"
  local manifest

  echo "ci: kustomize build ${overlay}"
  manifest="$(mktemp /tmp/kustomize-availability.XXXXXX.yaml)"
  kustomize build "${overlay}" >"${manifest}"

  echo "ci: conftest availability policy ${overlay}"
  conftest test --policy policy/k8s --namespace k8s.availability "${manifest}"

  rm -f "${manifest}"
}

validate_overlay "k8s/overlays/staging"
validate_overlay "k8s/overlays/production"

echo "ci: availability profile validation passed"
