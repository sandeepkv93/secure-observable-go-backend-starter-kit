#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MOCKGEN_BIN="${MOCKGEN_BIN:-$ROOT_DIR/bin/mockgen}"

bash scripts/build/generate_mocks_auto.sh

git diff --exit-code -- \
  internal/repository/gomock \
  internal/service/gomock \
  internal/health/gomock \
  internal/http/middleware/gomock
