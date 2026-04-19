#!/usr/bin/env bash
set -euo pipefail

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

if ! command -v go >/dev/null 2>&1; then
  if [ -x "${HOME}/sdk/go/bin/go" ]; then
    export PATH="${HOME}/sdk/go/bin:${PATH}"
  fi
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found on PATH. Install Go 1.25+ or add it to PATH." >&2
  exit 127
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

build_uwgsocks() {
  go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
}

build_uwgwrapper_linux() {
  mkdir -p ./cmd/uwgwrapper/assets
  gcc -shared -fPIC -O2 -Wall -Wextra -o ./cmd/uwgwrapper/assets/uwgpreload.so preload/uwgpreload.c -ldl -pthread
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgwrapper ./cmd/uwgwrapper
}

case "${OS}" in
  linux)
    build_uwgsocks
    if command -v gcc >/dev/null 2>&1; then
      build_uwgwrapper_linux
      echo "COMPILE SUCCEEDED. Built uwgsocks and uwgwrapper."
    else
      echo "COMPILE PARTIAL. Built uwgsocks, but skipped uwgwrapper because gcc is unavailable." >&2
    fi
    ;;
  darwin)
    build_uwgsocks
    echo "COMPILE SUCCEEDED. Built uwgsocks. uwgwrapper is Linux/Android-only and was skipped on macOS."
    ;;
  *)
    build_uwgsocks
    echo "COMPILE SUCCEEDED. Built uwgsocks. uwgwrapper is only built on Linux."
    ;;
esac
