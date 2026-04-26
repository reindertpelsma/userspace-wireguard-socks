#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# run-libc-chromium.sh: build wrapper + run the headless-Chromium
# smoke through it inside a Docker container against the container's
# native libc. Heavier sibling of run-libc-smoke / run-libc-full —
# adds node + chromium and runs the wrapper end-to-end with a real
# browser, under both bare ptrace and preload+ptrace transports.
#
# Usage:
#   run-libc-chromium.sh <image>
#
# Per-image steps:
#   1. install gcc + libc-dev + git + Go (if missing)
#   2. install node + chromium (apt or apk)
#   3. UWGS_RUN_HEADLESS_CHROME_SMOKE=1 \
#      UWGS_CHROME_BIN=/path/to/chromium \
#      UWGS_BROWSER_SMOKE_TRANSPORT=$transport \
#      go test -run TestUWGWrapperNodeHeadlessChromeSmoke
#   4. repeat for transport in {ptrace, preload-and-ptrace}
#
# Output: PASS/FAIL line per image with libc fingerprint.
# Exit code: 0 PASS (both transports), non-zero FAIL.

set -u
image="${1:?usage: $0 <image>}"
src_dir="${SRC_DIR:-/root/uwgsocks}"
deadline="${DEADLINE:-1800}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  if ! docker pull -q "$image" >/dev/null 2>&1; then
    echo "FAIL $image  image-pull-failed"
    exit 1
  fi
fi

case "$image" in
  alpine:*|*alpine*)
    install_cmd='apk add --no-cache --quiet gcc musl-dev linux-headers git wget ca-certificates chromium nodejs && \
      (command -v go >/dev/null || apk add --no-cache --quiet go)'
    chrome_bin='/usr/bin/chromium-browser'
    libc_probe='apk info musl 2>/dev/null | head -1 | awk "{print \"musl \" \$1}" | sed "s/^musl musl-/musl /"'
    ;;
  debian:*|ubuntu:*|*bullseye|*bookworm|*trixie|*jammy|*noble)
    install_cmd='DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev git wget ca-certificates chromium nodejs >/dev/null && \
      if ! command -v go >/dev/null; then \
        ARCH=$(uname -m); GOARCH=amd64; case "$ARCH" in aarch64) GOARCH=arm64 ;; esac; \
        wget -q "https://go.dev/dl/go1.24.0.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz && \
        tar -C /usr/local -xzf /tmp/go.tgz; \
      fi'
    chrome_bin='/usr/bin/chromium'
    libc_probe='ldd --version 2>&1 | head -1'
    ;;
  *)
    echo "SKIP $image  unsupported-distro"
    exit 0
    ;;
esac

results=""
for transport in ptrace preload-and-ptrace; do
  docker_script=$(cat <<EOF
set -e
$install_cmd >/dev/null 2>&1
export PATH=/usr/local/go/bin:\$PATH
cd /src
LIBCVER=\$( ($libc_probe 2>/dev/null | tr -d '\n') || echo unknown )
UWGS_RUN_HEADLESS_CHROME_SMOKE=1 \
UWGS_CHROME_BIN=$chrome_bin \
UWGS_BROWSER_SMOKE_TRANSPORT=$transport \
  go test -count=1 -timeout 240s -run TestUWGWrapperNodeHeadlessChromeSmoke ./tests/preload/ 2>&1 | tail -40
echo "ALL_OK \$LIBCVER"
EOF
)
  result=$(timeout "$deadline" docker run --rm \
    --cap-add SYS_PTRACE \
    --security-opt seccomp=unconfined \
    --shm-size=512m \
    -v "$src_dir":/src:ro \
    --network=host \
    --tmpfs /tmp:exec,size=2g \
    "$image" sh -c "$docker_script" 2>&1)
  if echo "$result" | tail -1 | grep -q '^ALL_OK '; then
    libcver=$(echo "$result" | tail -1 | sed 's/^ALL_OK //')
    results+="$transport=PASS "
  else
    last=$(echo "$result" | grep -E "FAIL|ERROR|fatal|cannot" | head -3 | tr '\n' '|')
    if [ -z "$last" ]; then
      last=$(echo "$result" | tail -3 | tr '\n' '|')
    fi
    printf "FAIL %-22s transport=%s | %s\n" "$image" "$transport" "${last:0:200}"
    exit 1
  fi
done

printf "PASS %-22s %-40s %s\n" "$image" "${libcver:-unknown}" "$results"
exit 0
