#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "ci: bazel build"
bazelisk build //...

echo "ci: bazel test"
tests="$(bazelisk query 'tests(//...)')"
if [[ -n "$tests" ]]; then
  printf "%s\n" "$tests" | xargs -r bazelisk test
else
  echo "ci: no bazel test targets"
fi

echo "ci: install tools"
mkdir -p ./bin
GOBIN="$(pwd)/bin" GOTOOLCHAIN=go1.26.0 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0
GOBIN="$(pwd)/bin" go install github.com/securego/gosec/v2/cmd/gosec@v2.22.9
GOBIN="$(pwd)/bin" GOTOOLCHAIN=go1.26.0 go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
GOBIN="$(pwd)/bin" go install github.com/zricethezav/gitleaks/v8@v8.24.2
GOBIN="$(pwd)/bin" GOTOOLCHAIN=go1.26.0 go install go.uber.org/mock/mockgen@v0.6.0

echo "ci: lint"
GOTOOLCHAIN=go1.26.0 ./bin/golangci-lint run --config .golangci.yml

echo "ci: gazelle check"
bazelisk run //:gazelle
build_files="$(find . -name BUILD.bazel -type f | tr '\n' ' ')"
if [[ -n "$build_files" ]]; then
  # shellcheck disable=SC2086
  git diff --exit-code -- $build_files
fi

echo "ci: tidy check"
GOTOOLCHAIN=go1.26.0 go mod tidy
git diff --exit-code go.mod go.sum

echo "ci: wire check"
go run -mod=mod github.com/google/wire/cmd/wire ./internal/di
GOTOOLCHAIN=go1.26.0 go mod tidy
git diff --exit-code internal/di/wire_gen.go go.mod go.sum

echo "ci: mockgen check"
MOCKGEN_BIN="$(pwd)/bin/mockgen" bash scripts/ci/run_mockgen_check.sh

echo "ci: security checks"
./bin/gosec -quiet -exclude-generated -exclude-dir=bin -exclude-dir=.git -tests ./...
GOTOOLCHAIN=go1.26.0 ./bin/govulncheck ./...
./bin/gitleaks git --config .gitleaks.toml --redact --exit-code 1

echo "ci: cli smoke"
go run ./cmd/migrate --help >/dev/null
go run ./cmd/seed --help >/dev/null
go run ./cmd/loadgen --help >/dev/null
go run ./cmd/obscheck --help >/dev/null

echo "ci: all checks passed"
