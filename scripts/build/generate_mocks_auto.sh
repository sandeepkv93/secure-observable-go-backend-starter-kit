#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MOCKGEN_BIN="${MOCKGEN_BIN:-}"
if [[ -z "$MOCKGEN_BIN" ]]; then
  if [[ -x "$ROOT_DIR/bin/mockgen" ]]; then
    MOCKGEN_BIN="$ROOT_DIR/bin/mockgen"
  elif command -v mockgen >/dev/null 2>&1; then
    MOCKGEN_BIN="$(command -v mockgen)"
  else
    echo "mockgen not found. Run: task mockgen:install"
    exit 1
  fi
fi

TARGET_DIRS=(
  "internal/repository"
  "internal/service"
  "internal/health"
  "internal/http/middleware"
)

discover_interface_source_files() {
  local dir="$1"
  find "$dir" -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' | sort | while read -r file; do
    if awk '/^type [A-Z][A-Za-z0-9_]* interface[[:space:]]*\{/ { found=1 } END { exit !found }' "$file"; then
      echo "$file"
    fi
  done
}

echo "mockgen: generating mocks"
for dir in "${TARGET_DIRS[@]}"; do
  if [[ ! -d "$dir" ]]; then
    continue
  fi

  mapfile -t src_files < <(discover_interface_source_files "$dir")
  if [[ "${#src_files[@]}" -eq 0 ]]; then
    continue
  fi

  out_dir="${dir}/gomock"
  mkdir -p "$out_dir"
  find "$out_dir" -maxdepth 1 -type f -name 'mock_*.go' -delete

  for src_file in "${src_files[@]}"; do
    src_base="$(basename "$src_file" .go)"
    out_file="${out_dir}/mock_${src_base}.go"
    "$MOCKGEN_BIN" -source "$src_file" -destination "$out_file" -package gomock
    echo "  generated: ${out_file}"
  done
done

echo "mockgen: done"
