#!/bin/bash
# Phase 1 preload .so build script. Produces preload/uwgpreload-phase1.so
# alongside the legacy preload/uwgpreload.c → cmd/uwgwrapper/assets/
# uwgpreload.so. The Phase 1 .so is a drop-in test artifact that
# can be loaded via UWGS_PRELOAD=/path/to/uwgpreload-phase1.so
# instead of the legacy .so.
#
# Once Phase 1 is feature-complete (UDP datagram framing, DNS-on-:53
# forcing, getsockname synthesis, full shim_libc layer) this script
# can replace the legacy preload build entirely. Until then, both
# coexist on this branch.
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
)

SHIM_SRCS=(
    preload/shim_libc/shim_init.c
    preload/shim_libc/shim_socket.c
)

OUT="${1:-preload/uwgpreload-phase1.so}"
gcc $CFLAGS_BASE $CFLAGS_WARN \
    "${CORE_SRCS[@]}" "${SHIM_SRCS[@]}" \
    -o "$OUT"

echo "built $OUT ($(stat -c '%s' "$OUT") bytes)"
