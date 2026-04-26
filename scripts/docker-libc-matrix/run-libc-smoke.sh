#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# run-libc-smoke.sh: build uwgpreload.so inside a container against
# the container's native libc and verify it loads + intercepts a
# simple socket() call. Designed for the Docker libc compatibility
# matrix (ubuntu N.NN, alpine N.NN, debian *).
#
# Usage:
#   run-libc-smoke.sh <image>
#
# Output:
#   PASS <image>  <glibc/musl version>     <one-line note>
#   FAIL <image>  <reason>
#
# Per-image steps inside the container:
#   1. install gcc + libc dev headers
#   2. compile preload/uwgpreload.c → uwgpreload.so
#   3. run /bin/true with LD_PRELOAD=uwgpreload.so (catches dlopen
#      crashes, ABI mismatches, missing dlsym targets)
#   4. run a tiny C probe that calls socket()+close(), verify
#      preload's interposition path runs without crashing
#
# Exit code is per-image: 0 PASS, 1 FAIL. Stdout has a one-line
# summary so the wrapper script can build a matrix table.

set -u
image="${1:?usage: $0 <image>}"
src_dir="${SRC_DIR:-/root/uwgsocks}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "FAIL $image  image-not-pulled"
  exit 1
fi

# Distro-specific install commands. We support apt (debian/ubuntu)
# and apk (alpine). Anything else is intentionally skipped.
case "$image" in
  alpine:*)
    install_cmd='apk add --no-cache --quiet gcc musl-dev linux-headers'
    # one-line libc fingerprint — apk info returns "musl-1.2.5-r12 description:" so trim
    libc_probe='apk info musl 2>/dev/null | head -1 | awk "{print \"musl \" \$1}" | sed "s/^musl musl-/musl /"'
    ;;
  debian:*|ubuntu:*)
    install_cmd='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev > /dev/null'
    libc_probe='ldd --version 2>&1 | head -1'
    ;;
  *)
    echo "SKIP $image  unsupported-distro"
    exit 0
    ;;
esac

# Probe runs: 1) build the .so, 2) LD_PRELOAD a no-op, 3) run a tiny
# C probe that makes one socket()+close() call so preload's
# interposition path is exercised, not just dlopen.
docker_script=$(cat <<EOF
set -e
$install_cmd >/dev/null 2>&1
cd /src
LIBCVER=\$( ($libc_probe 2>/dev/null | tr -d '\n') || echo unknown )
gcc -shared -fPIC -O2 -Wall -o /tmp/uwgpreload.so preload/uwgpreload.c -ldl -pthread -lpthread >/dev/null 2>&1
LD_PRELOAD=/tmp/uwgpreload.so /bin/true >/dev/null 2>&1
cat > /tmp/probe.c <<'PROBE'
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    close(fd);
    fputs("ok", stdout);
    return 0;
}
PROBE
gcc -O2 -o /tmp/probe /tmp/probe.c >/dev/null 2>&1
out=\$(LD_PRELOAD=/tmp/uwgpreload.so /tmp/probe 2>&1)
test "\$out" = "ok" || { echo "probe-failed:\$out"; exit 1; }
# Final line is the success sentinel; nothing else writes to stdout.
echo "ALL_OK \$LIBCVER"
EOF
)

# 90s deadline per image — slow Alpine 3.10 apk takes ~30s.
result=$(timeout 90 docker run --rm \
  -v "$src_dir":/src:ro \
  --network=host \
  "$image" sh -c "$docker_script" 2>&1 | tail -20)

if echo "$result" | tail -1 | grep -q '^ALL_OK '; then
  libcver=$(echo "$result" | tail -1 | sed 's/^ALL_OK //')
  printf "PASS %-22s %s\n" "$image" "$libcver"
  exit 0
fi

# On failure, surface the last line as the cause.
last=$(echo "$result" | tail -3 | tr '\n' ' ')
printf "FAIL %-22s %s\n" "$image" "${last:0:200}"
exit 1
