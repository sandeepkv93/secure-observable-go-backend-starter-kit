#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER_NAME:-secure-observable}"
KIND_CONFIG="${KIND_CONFIG:-k8s/kind-config.yaml}"
INSTALL_METRICS_SERVER="${INSTALL_METRICS_SERVER:-false}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} not found" >&2
    exit 1
  fi
}

cluster_exists() {
  kind get clusters | grep -q "^${CLUSTER_NAME}$"
}

install_ingress_nginx() {
  echo "Installing ingress-nginx..."
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
  kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=240s
}

install_metrics_server() {
  echo "Installing metrics-server..."
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
  kubectl -n kube-system rollout status deployment/metrics-server --timeout=240s
}

create_cluster() {
  require_cmd docker
  require_cmd kind
  require_cmd kubectl

  if cluster_exists; then
    echo "kind cluster '${CLUSTER_NAME}' already exists"
  else
    kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
  fi

  kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
  install_ingress_nginx

  if [[ "${INSTALL_METRICS_SERVER}" == "true" ]]; then
    install_metrics_server
  fi
}

delete_cluster() {
  require_cmd kind
  if cluster_exists; then
    kind delete cluster --name "${CLUSTER_NAME}"
  else
    echo "kind cluster '${CLUSTER_NAME}' does not exist"
  fi
}

status() {
  require_cmd kubectl
  kubectl cluster-info --context "kind-${CLUSTER_NAME}" || true
  kubectl get nodes -o wide || true
  kubectl -n ingress-nginx get pods,svc || true
}

cmd="${1:-create}"
case "${cmd}" in
  create)
    create_cluster
    ;;
  reset)
    delete_cluster
    create_cluster
    ;;
  delete)
    delete_cluster
    ;;
  status)
    status
    ;;
  *)
    echo "Usage: $0 [create|reset|delete|status]" >&2
    exit 1
    ;;
esac
