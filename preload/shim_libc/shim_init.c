/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 1 minimal LD_PRELOAD constructor. When this .so is loaded
 * via LD_PRELOAD, the dynamic loader runs __attribute__((constructor))
 * functions before main(). We use that hook to:
 *
 *   1. Initialize core (parse env, mmap shared state, allocate per-
 *      thread sigaltstack, install SIGSYS handler, install seccomp
 *      filter).
 *
 *   2. After this point, every interesting syscall the wrapped
 *      program issues — whether through libc's own wrappers or
 *      via inline asm — is trapped by the seccomp filter and
 *      dispatched through uwg_<op>.
 *
 * For Phase 1 we do NOT add per-libc-function shims (recvmsg, etc.).
 * Those are a perf optimization for v0.3 — they save one
 * kernel→handler context switch per call but add no correctness.
 * Without them, libc's recvmsg traps via SIGSYS, our handler
 * dispatches to uwg_recvmsg, the result flows back to libc.
 *
 * Future per-libc-function shims will live in preload/shim_libc/
 * alongside this file (one wrapper per overridden symbol that
 * calls into core dispatch directly).
 */

#include <stdio.h>
#include <stdlib.h>

#include "../core/dispatch.h"

/*
 * Constructor priority: 101 places us early enough that we run
 * before most app constructors (which default to priority 0 ≈
 * "last"). We need to run before any networked code in libc
 * initializers — there usually isn't any, but defense in depth.
 */
__attribute__((constructor(101)))
static void uwg_preload_init(void) {
    int rc = uwg_core_init();
    if (rc < 0) {
        /* Init failed — most commonly because UWGS_TRACE_SECRET
         * isn't set, meaning this .so was loaded outside an
         * uwgwrapper-managed run. The shim_libc layer still
         * works as a drop-in for the legacy preload; we just lose
         * the SIGSYS+seccomp belt-and-braces against raw asm
         * syscalls. Print a diagnostic only if UWGS_PRELOAD_VERBOSE
         * is set so test runs and benign LD_PRELOAD-into-unrelated-
         * processes (e.g. systemd-tmpfiles) stay quiet. */
        if (getenv("UWGS_PRELOAD_VERBOSE")) {
            fprintf(stderr,
                    "uwgpreload: core init failed (rc=%d, no UWGS_TRACE_SECRET?); shim-only mode\n",
                    rc);
        }
    }
}
