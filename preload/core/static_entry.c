/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 2 static-blob entry point. The supervisor in cmd/uwgwrapper
 * (the ptrace-injection logic) sets up the tracee's state to enter
 * uwg_static_init at the post-execve stop, having parsed the
 * tracee's auxv to find argc/argv/envp and the original AT_ENTRY
 * (saved_start).
 *
 * uwg_static_init's job:
 *   1. Save the env pointer (uwg_environ)
 *   2. Run uwg_core_init() — sets up sigaltstack, SIGSYS handler,
 *      seccomp filter
 *   3. Return to saved_start (the original program's _start)
 *
 * The supervisor handles the actual jump to saved_start by setting
 * the RIP/PC after this function returns. So this function just
 * runs init and falls off the end of its prologue/epilogue.
 *
 * Calling convention: standard ABI register passing.
 *   x86_64: rdi=argc, rsi=argv, rdx=envp
 *   arm64:  x0=argc, x1=argv, x2=envp
 */

#ifdef UWG_FREESTANDING

#include <stddef.h>
#include "freestanding_runtime.h"
#include "dispatch.h"

int uwg_static_init(int argc, char **argv, char **envp) {
    (void)argc;
    (void)argv;
    /* Capture the env vector so the rest of core/ can walk it via
     * uwg_environ. Phase 1 .so build does this via libc's environ
     * in uwg_core_init(); for the static blob we receive it directly
     * from the supervisor. */
    if (envp != NULL) {
        uwg_environ = envp;
    }

    /* Run the same init as the .so build. Returns 0 on success or
     * -errno on failure; either way we return to the supervisor and
     * it jumps to saved_start. A failed init means tunnel
     * interception isn't active — the program runs unwrapped. */
    return uwg_core_init();
}

#endif /* UWG_FREESTANDING */
