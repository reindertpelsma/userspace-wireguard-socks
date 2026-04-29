#!/bin/bash
# Phase 1 preload .so build script. This is the canonical build for the
# wrapper's embedded uwgpreload.so: compile.sh and the CI workflows all
# call this script. The legacy single-file preload/uwgpreload.c was
# retired once Phase 1 reached drop-in equivalence (verified by the
# tests/preload/ suite passing with this output substituted as the
# wrapper's embedded asset). The output path is the first positional
# argument; if omitted it defaults to preload/uwgpreload-phase1.so for
# ad-hoc local testing.
set -euo pipefail
cd "$(dirname "$0")/.."

CFLAGS_BASE="-O2 -fPIC -shared -D_GNU_SOURCE -I preload/core -I preload"
CFLAGS_WARN="-Wall -Wextra -Wno-unused-parameter -Wno-stringop-overflow"

CORE_SRCS=(
    preload/core/sigsys.c
    preload/core/seccomp.c
    preload/core/dispatch.c
    preload/core/init.c
    preload/core/shared_state.c
    preload/core/fdproxy_sock.c
    preload/core/socket_ops.c
    preload/core/addr_utils.c
    preload/core/connect_ops.c
    preload/core/bind_ops.c
    preload/core/listener_ops.c
    preload/core/stream_ops.c
    preload/core/msg_ops.c
    preload/core/fd_ops.c
    preload/core/udp_frame.c
    preload/core/dns_force.c
    preload/core/trace.c
    preload/core/freestanding_runtime.c
    preload/core/sigreturn_trampoline.c
)

SHIM_SRCS=(
    preload/shim_libc/shim_init.c
    preload/shim_libc/shim_socket.c
)

OUT="${1:-preload/uwgpreload-phase1.so}"
# Make sure the output directory exists. The CI workflows used to do
# `mkdir -p cmd/uwgwrapper/assets` before invoking gcc directly; now
# that they call this script we own that responsibility here.
out_dir="$(dirname "$OUT")"
if [ -n "$out_dir" ] && [ "$out_dir" != "." ]; then
    mkdir -p "$out_dir"
fi
# Honour CC for cross-compilation (e.g. CC="zig cc -target aarch64-linux-musl"
# from the release.yml exotic-arch matrix). Default to gcc on the host.
CC="${CC:-gcc}"
$CC $CFLAGS_BASE $CFLAGS_WARN \
    "${CORE_SRCS[@]}" "${SHIM_SRCS[@]}" \
    -o "$OUT"

echo "built $OUT ($(stat -c '%s' "$OUT") bytes)"
