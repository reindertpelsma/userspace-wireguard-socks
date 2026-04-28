/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Inline-asm syscall primitives. NO LIBC. Async-signal-safe.
 *
 * Both uwgpreload.so (libc-linked) and uwgpreload-static (freestanding)
 * include this header to issue raw syscalls without going through libc's
 * `syscall(2)` wrapper. The reasons:
 *
 *  - The SIGSYS handler runs in arbitrary signal contexts where libc's
 *    errno-via-TLS may be in an inconsistent state.
 *  - The static-binary build has no libc to link against.
 *  - The `passthrough_syscall` variants below place a 64-bit secret
 *    in the 6th positional arg slot so the seccomp filter exempts the
 *    re-issued syscall from SIGSYS interception. Wrapping libc's
 *    `syscall(...)` would clobber the 6th arg (libc's signature stops
 *    at 5 user args in some implementations).
 *
 * Return convention: same as the kernel's. On error, returns -errno.
 * On success, returns >= 0. NO global errno is touched.
 *
 * All inline asm uses the volatile + memory clobber pattern so the
 * compiler can't reorder loads/stores across the syscall.
 */

#ifndef UWG_PRELOAD_CORE_SYSCALL_H
#define UWG_PRELOAD_CORE_SYSCALL_H

#include <stdint.h>

/* No <errno.h> — we deliberately don't touch the libc errno global. */

#if defined(__x86_64__)

static inline long uwg_syscall0(long nr) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall1(long nr, long a1) {
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8  __asm__("r8")  = 0;
    register long r9  __asm__("r9")  = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall2(long nr, long a1, long a2) {
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8  __asm__("r8")  = 0;
    register long r9  __asm__("r9")  = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall3(long nr, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8  __asm__("r8")  = 0;
    register long r9  __asm__("r9")  = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = 0;
    register long r9  __asm__("r9")  = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall5(long nr, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long uwg_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#elif defined(__aarch64__)

static inline long uwg_syscall0(long nr) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0");
    __asm__ volatile ("svc #0"
                      : "=r"(x0)
                      : "r"(x8)
                      : "memory");
    return x0;
}

static inline long uwg_syscall1(long nr, long a1) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8)
                      : "memory");
    return x0;
}

static inline long uwg_syscall2(long nr, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1)
                      : "memory");
    return x0;
}

static inline long uwg_syscall3(long nr, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2)
                      : "memory");
    return x0;
}

static inline long uwg_syscall4(long nr, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                      : "memory");
    return x0;
}

static inline long uwg_syscall5(long nr, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                      : "memory");
    return x0;
}

static inline long uwg_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                      : "memory");
    return x0;
}

#else
#error "uwg core: unsupported architecture"
#endif

/*
 * Bypass-secret machinery.
 *
 * uwg_passthrough_syscall* functions place the 64-bit BYPASS_SECRET
 * in arg6. The seccomp filter has a top-level rule that exempts any
 * syscall with the secret in arg6, so these calls go directly to the
 * kernel without being trapped by SIGSYS.
 *
 * Use these when:
 *   - core decided "this fd is non-tunnel, just pass to kernel"
 *   - core's TCP-stream fast path: read/write on a managed TCP fd
 *
 * The secret is set by uwg_core_set_bypass_secret() at init time
 * (read from UWGS_TRACE_SECRET env var; same as today's uwgpreload).
 */

extern uint64_t uwg_bypass_secret;

static inline long uwg_passthrough_syscall0(long nr) {
    /* arg6 is the 6th positional; for 0-arg syscalls this still works
     * because the kernel ignores trailing args it doesn't expect. */
    return uwg_syscall6(nr, 0, 0, 0, 0, 0, (long)uwg_bypass_secret);
}

static inline long uwg_passthrough_syscall1(long nr, long a1) {
    return uwg_syscall6(nr, a1, 0, 0, 0, 0, (long)uwg_bypass_secret);
}

static inline long uwg_passthrough_syscall2(long nr, long a1, long a2) {
    return uwg_syscall6(nr, a1, a2, 0, 0, 0, (long)uwg_bypass_secret);
}

static inline long uwg_passthrough_syscall3(long nr, long a1, long a2, long a3) {
    return uwg_syscall6(nr, a1, a2, a3, 0, 0, (long)uwg_bypass_secret);
}

static inline long uwg_passthrough_syscall4(long nr, long a1, long a2, long a3, long a4) {
    return uwg_syscall6(nr, a1, a2, a3, a4, 0, (long)uwg_bypass_secret);
}

static inline long uwg_passthrough_syscall5(long nr, long a1, long a2, long a3, long a4, long a5) {
    return uwg_syscall6(nr, a1, a2, a3, a4, a5, (long)uwg_bypass_secret);
}

#endif /* UWG_PRELOAD_CORE_SYSCALL_H */
