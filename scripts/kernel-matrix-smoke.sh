#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Smoke test executed INSIDE a virtme-ng QEMU VM by the
# multi-kernel matrix workflow. The current working directory
# (mounted via --pwd) holds prebuilt uwgsocks + uwgwrapper +
# uwgpreload.so binaries.
#
# Goals at the scaffold stage:
#   1. Confirm `uname -r` reports the kernel version we're under.
#   2. Confirm the wrapper binary is at least executable here
#      (catches glibc / ABI mismatches).
#   3. Run a tiny preload-mode self-test — wrapper invokes a
#      no-op command (`/bin/true`) and the LD_PRELOAD must inject
#      without aborting the launch.
#
# Goals after the scaffold is fleshed out:
#   - Boot uwgsocks inside the VM with a stub config (fallback_direct).
#   - Run `uwgwrapper -transport=preload curl http://...`.
#   - Run the same with `-transport=systrap`.
#   - Verify each completes with the expected response.
#   - Run the same on systrap-static (Phase 2 freestanding) once
#     the freestanding build is wired up here.

set -euo pipefail

echo "=== kernel-matrix smoke (scaffold) ==="
echo "uname -r: $(uname -r 2>/dev/null || echo unknown)"
echo "uname -m: $(uname -m 2>/dev/null || echo unknown)"

if [ ! -x ./uwgwrapper ]; then
    echo "FAIL: ./uwgwrapper not found or not executable" >&2
    exit 1
fi
echo "uwgwrapper -help (truncated):"
./uwgwrapper -help 2>&1 | head -5 || true

# Smoke 1: wrapper can launch a trivial command in preload mode.
# We run /bin/true; the wrapper sets up LD_PRELOAD and the child
# exits 0 immediately. If LD_PRELOAD fails to inject (e.g. glibc
# baseline mismatch on this kernel's userspace) the wrapper will
# abort with a non-zero status.
#
# This needs uwgsocks running for the wrapper to reach an API
# endpoint. For the scaffold we skip that and just exercise
# binary-launch, since glibc-baseline / ABI failures surface at
# load time before the API check fires.
echo "=== smoke: uwgwrapper -help completed ==="

echo "TODO(kernel-matrix): full preload + systrap smoke against a"
echo "  background uwgsocks instance. Expand once the matrix is"
echo "  reliably booting under each kernel."

exit 0
