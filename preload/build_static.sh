#!/bin/bash
# Build the Phase 2 static-binary preload blob.
#
# Produces preload/uwgpreload-static.{amd64,arm64}.bin: a position-
# independent freestanding code blob containing every preload/core/*
# dispatcher with NO libc dependency (memcpy/memset/strncmp from
# preload/core/freestanding.h, custom uwg_parse_ipv6 in addr_utils.c).
#
# The blob is injected by the Phase 2 supervisor (cmd/uwgwrapper) into
# a static-linked tracee's address space at exec time, via PTRACE +
# remote mmap + POKEDATA. The tracee then jumps to the blob's entry
# point uwg_static_init, which:
#   1. Sets up sigaltstack
#   2. Installs the SIGSYS handler
#   3. Installs the seccomp filter
#   4. Returns to the tracee's saved _start
#
# The supervisor knows the entry-point offset from `nm` output of the
# build artifact.
#
# Currently this script just compiles core/ as a freestanding .so to
# verify the freestanding build works. The actual blob format (raw
# binary, single segment, with embedded jump table) is the next ladder
# step.

set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

CFLAGS_BASE="-O2 -fPIC -shared -D_GNU_SOURCE -DUWG_FREESTANDING -I preload/core -I preload"
CFLAGS_FREESTANDING="-ffreestanding -nostdlib -fno-stack-protector"
# -Wl,-Bsymbolic: bind global symbol references to the blob's own
#   definitions at link time, eliminating R_X86_64_GLOB_DAT relocations
#   we'd otherwise have to resolve at injection time.
# -Wl,-z,nodynamic-undefined-weak: same idea for weak refs.
# -fvisibility=hidden via linker script would be cleaner but Bsymbolic
#   handles all the cases we hit.
CFLAGS_LDFLAGS="-Wl,-Bsymbolic"
CFLAGS_WARN="-Wall -Wextra -Wno-unused-parameter -Wno-stringop-overflow"

# arm64 (aarch64) GCC defaults to outline-atomics — generates calls to
# __aarch64_ldadd4_rel etc. from libgcc.a. The freestanding link can't
# satisfy those, so disable outline atomics and let GCC inline LL/SC.
#
# -mno-outline-atomics was added in GCC 9. Older GCC (e.g. GCC 7 on
# Ubuntu 18.04 / glibc 2.27 hosts) doesn't recognize it; check before
# adding so the older-libc build doesn't fail with "unrecognized
# option". Older GCC also didn't default to outline-atomics, so
# omitting the flag there is correct behavior.
CC="${CC:-gcc}"
if [ "$ARCH" = "arm64" ]; then
    if echo 'int main(void){return 0;}' | "$CC" -x c -mno-outline-atomics - -o /dev/null 2>/dev/null; then
        CFLAGS_BASE="$CFLAGS_BASE -mno-outline-atomics"
    fi
fi

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
    preload/core/freestanding_impl.c
    preload/core/sigreturn_trampoline.c
    preload/core/freestanding_runtime.c
    preload/core/static_entry.c
)

OUT_DIR="${1:-cmd/uwgwrapper/assets}"
mkdir -p "$OUT_DIR"
OUT_SO="$OUT_DIR/uwgpreload-static-${ARCH}.so"

# First sanity check: does core/ compile freestanding (no libc)?
gcc $CFLAGS_BASE $CFLAGS_FREESTANDING $CFLAGS_WARN $CFLAGS_LDFLAGS \
    "${CORE_SRCS[@]}" \
    -o "$OUT_SO" 2>&1 | tail -20

ls -la "$OUT_SO"
echo "freestanding .so build OK ($(stat -c '%s' "$OUT_SO") bytes)"

# Verify no libc symbols are referenced.
echo "=== external symbols (should be only kernel-syscall-equivalents):"
nm -u --no-demangle "$OUT_SO" 2>/dev/null | head -20

echo
echo "Next ladder step: convert this .so into a single-segment"
echo "position-independent binary blob suitable for ptrace injection."
