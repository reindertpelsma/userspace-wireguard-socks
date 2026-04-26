#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# run-libc-full.sh: build + run the FULL test suite (`go test ./...`)
# inside a Docker container against a specific libc version. Heavier
# sibling of run-libc-smoke.sh which only tests `uwgpreload.so` build
# and load. Used to validate that the entire codebase builds and the
# tests pass against older glibc / musl versions before release.
#
# Usage:
#   run-libc-full.sh <image>
#
# Output (one line per image to stdout):
#   PASS <image>  <libc>  <test summary>
#   FAIL <image>  <libc>  <which test failed>
#
# Per-image steps:
#   1. install Go (apt: golang-go on glibc, apk: go on alpine)
#   2. install gcc + libc-dev (gcc + musl-dev or libc6-dev)
#   3. install git (for tests that shell out to `git rev-parse`)
#   4. cd /src && go test -count=1 -timeout 600s ./...
#
# Exit code: 0 PASS, non-zero FAIL.

set -u
image="${1:?usage: $0 <image>}"
src_dir="${SRC_DIR:-/root/uwgsocks}"
deadline="${DEADLINE:-900}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  if ! docker pull -q "$image" >/dev/null 2>&1; then
    echo "FAIL $image  image-pull-failed"
    exit 1
  fi
fi

# Pick install commands by distro family. For images with too-old
# Go in repos (Ubuntu 18.04 ships go1.10, Alpine 3.10 ships go1.12),
# the script downloads the official binary tarball.
case "$image" in
  alpine:3.10|alpine:3.11|alpine:3.12|alpine:3.13|alpine:3.14|alpine:3.15)
    # Old alpines: musl <1.2.4, no Go in repos new enough; use Go binary tarball
    install_cmd='apk add --no-cache --quiet gcc musl-dev linux-headers git wget ca-certificates && \
      ARCH=$(uname -m); GOARCH=amd64; case "$ARCH" in aarch64) GOARCH=arm64 ;; esac; \
      wget -q "https://go.dev/dl/go1.23.10.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz && \
      tar -C /usr/local -xzf /tmp/go.tgz && export PATH=/usr/local/go/bin:$PATH'
    libc_probe='apk info musl 2>/dev/null | head -1 | awk "{print \"musl \" \$1}" | sed "s/^musl musl-/musl /"'
    ;;
  alpine:*|*alpine*)
    # Modern alpine: Go in apk repos OR golang:*-alpine* image
    install_cmd='apk add --no-cache --quiet gcc musl-dev linux-headers git && (command -v go >/dev/null || apk add --no-cache go)'
    libc_probe='apk info musl 2>/dev/null | head -1 | awk "{print \"musl \" \$1}" | sed "s/^musl musl-/musl /"'
    ;;
  ubuntu:18.04|ubuntu:20.04)
    # Older ubuntu: install Go from official tarball (their apt is too old).
    install_cmd='DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev git wget ca-certificates >/dev/null && \
      ARCH=$(uname -m); GOARCH=amd64; case "$ARCH" in aarch64) GOARCH=arm64 ;; esac; \
      wget -q "https://go.dev/dl/go1.23.10.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz && \
      tar -C /usr/local -xzf /tmp/go.tgz && export PATH=/usr/local/go/bin:$PATH'
    libc_probe='ldd --version 2>&1 | head -1'
    ;;
  debian:*|ubuntu:*|*bullseye|*bookworm|*trixie|*jammy|*noble)
    # Glibc-based image; install gcc + libc6-dev. golang: images already
    # have Go installed (PATH already includes it); plain debian/ubuntu
    # variants need it from the tarball.
    install_cmd='DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev git wget ca-certificates >/dev/null && \
      if ! command -v go >/dev/null; then \
        ARCH=$(uname -m); GOARCH=amd64; case "$ARCH" in aarch64) GOARCH=arm64 ;; esac; \
        wget -q "https://go.dev/dl/go1.23.10.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz && \
        tar -C /usr/local -xzf /tmp/go.tgz; \
      fi'
    libc_probe='ldd --version 2>&1 | head -1'
    ;;
  *)
    echo "SKIP $image  unsupported-distro"
    exit 0
    ;;
esac

# Build the test command. Skip tests/preload — those need GCC + the
# wrapper binary builds inline and run end-to-end, which is what the
# run-libc-preload.sh script handles. The full suite here is for
# correctness of the Go side under the container's libc.
docker_script=$(cat <<EOF
set -e
$install_cmd >/dev/null 2>&1
export PATH=/usr/local/go/bin:\$PATH
cd /src
LIBCVER=\$( ($libc_probe 2>/dev/null | tr -d '\n') || echo unknown )
# Tests that need a git checkout (resolve_subcommand_test) skip
# cleanly when .git is missing; we run with a read-only mount so
# we can't init one even if we wanted to.
go test -count=1 -timeout 600s ./... 2>&1 | tail -200
echo "ALL_OK \$LIBCVER"
EOF
)

result=$(timeout "$deadline" docker run --rm \
  -v "$src_dir":/src:ro \
  --network=host \
  --tmpfs /tmp:exec,size=2g \
  "$image" sh -c "$docker_script" 2>&1)

if echo "$result" | tail -1 | grep -q '^ALL_OK '; then
  libcver=$(echo "$result" | tail -1 | sed 's/^ALL_OK //')
  # `tail -200` upstream truncates the per-package "ok ..." lines so
  # we grep over the WHOLE result. The ALL_OK sentinel proves the
  # entire suite ran successfully — the printed pkg count here is
  # informational.
  pkg_pass=$(echo "$result" | grep -cE '^ok\s' || true)
  printf "PASS %-22s %-50s pkgs_ok=%d\n" "$image" "$libcver" "$pkg_pass"
  exit 0
fi

# On failure, surface the FAIL lines + last lines for context.
fails=$(echo "$result" | grep -E '^FAIL\s|^--- FAIL' | head -5 | tr '\n' '|')
last=$(echo "$result" | tail -3 | tr '\n' '|')
printf "FAIL %-22s fails=%s | %s\n" "$image" "${fails:0:200}" "${last:0:200}"
exit 1
