/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * SA_RESTORER trampoline for the freestanding (Phase 2) static-binary
 * build. The kernel jumps to this address when a signal handler
 * returns (sa_restorer field on x86_64 / aarch64). Without it, the
 * tracee crashes on the first SIGSYS return.
 *
 * Inline asm only — no C runtime dependencies. The trampoline issues
 * SYS_rt_sigreturn which restores the pre-signal context.
 *
 * The .so build (no UWG_FREESTANDING) doesn't compile this file; libc
 * provides __restore_rt automatically via sigaction(2).
 */

#ifdef UWG_FREESTANDING

#if defined(__x86_64__)
__attribute__((naked, noreturn))
void uwg_sigreturn_trampoline(void) {
    /* SYS_rt_sigreturn = 15 on x86_64. */
    __asm__ volatile (
        "mov $15, %%rax\n\t"
        "syscall\n\t"
        ::: "rax"
    );
}
#elif defined(__aarch64__)
__attribute__((naked, noreturn))
void uwg_sigreturn_trampoline(void) {
    /* SYS_rt_sigreturn = 139 on arm64. */
    __asm__ volatile (
        "mov x8, #139\n\t"
        "svc #0\n\t"
        ::: "x8"
    );
}
#else
#  error "uwg sigreturn trampoline: unsupported arch"
#endif

#endif /* UWG_FREESTANDING */
