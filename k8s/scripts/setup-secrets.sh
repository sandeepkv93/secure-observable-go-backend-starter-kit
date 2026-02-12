#!/usr/bin/env bash
set -euo pipefail

LOCAL_ENV_FILE="${K8S_APP_SECRETS_FILE:-.secrets.k8s.app.env}"
TEMPLATE_FILE="k8s/base/secrets/app-secrets.env.template"

generate() {
  if [[ -f "${LOCAL_ENV_FILE}" ]]; then
    echo "${LOCAL_ENV_FILE} already exists"
    return 0
  fi
  cp "${TEMPLATE_FILE}" "${LOCAL_ENV_FILE}"
  echo "Generated ${LOCAL_ENV_FILE} from template"
  echo "Update secret values before applying"
}

apply() {
  bash k8s/scripts/secrets.sh apply
}

cmd="${1:-}"
case "${cmd}" in
  generate)
    generate
    ;;
  apply)
    apply
    ;;
  *)
    echo "Usage: $0 [generate|apply]" >&2
    exit 1
    ;;
esac
