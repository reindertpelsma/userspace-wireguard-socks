/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * End-to-end smoke test for the SIGSYS path:
 *
 *   1. Install the SIGSYS handler.
 *   2. Install the seccomp filter.
 *   3. Issue a trapped syscall (socket(2)).
 *   4. Expect: kernel raises SIGSYS, handler decodes ucontext,
 *      uwg_dispatch routes to uwg_socket() stub which returns
 *      -ENOSYS, handler writes -ENOSYS to ucontext rax, kernel
 *      sigreturn restores it, our test sees socket() return -1
 *      with errno = ENOSYS.
 *   5. Confirm the stats counter for the handler bumped.
 *   6. Issue a syscall WITH the bypass-secret in arg6 (via
 *      uwg_passthrough_syscall*) and confirm it goes through
 *      the kernel directly (returns the real fd).
 *
 * Compile + run:
 *   gcc -O2 -D_GNU_SOURCE -I preload/core \
 *       preload/core/sigsys_test.c \
 *       preload/core/sigsys.c \
 *       preload/core/seccomp.c \
 *       preload/core/dispatch.c \
 *       preload/core/init.c \
 *       -lpthread -o /tmp/sigsys_test
 *   UWGS_TRACE_SECRET=1234567890 /tmp/sigsys_test
 *
 * Exit codes:
 *   0   all checks passed
 *   1+  specific check failed; stderr explains
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "freestanding.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "dispatch.h"
#include "syscall.h"

/* Set by core/init.c at uwg_core_init() time. We declare it extern
 * here so the test can pass it to seccomp_install directly without
 * going through the full init (which also installs sigaltstack etc).
 */
extern uint64_t uwg_bypass_secret;

/* Async-signal-safe-ish print: bypasses libc and the filter via the
 * bypass-secret path. Used after the filter is installed where libc
 * stdio would be blocked because write(2) is in our trap list. */
static void uwg_print(const char *s) {
    size_t n = 0; while (s[n]) n++;
    (void)uwg_passthrough_syscall3(SYS_write, 2, (long)s, (long)n);
}

/* Format an unsigned long into a fixed buffer (decimal). */
static char *uwg_fmt_u(char *buf, size_t buflen, unsigned long v) {
    char tmp[32];
    size_t i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
    size_t out = 0;
    while (i && out < buflen - 1) buf[out++] = tmp[--i];
    buf[out] = 0;
    return buf;
}

static int fail(const char *what) {
    char nbuf[32];
    uwg_print("FAIL: ");
    uwg_print(what);
    uwg_print(" (errno=");
    uwg_print(uwg_fmt_u(nbuf, sizeof(nbuf), (unsigned long)errno));
    uwg_print(")\n");
    return 1;
}

int main(void) {
    /* Pretend we're uwg_core_init: read the secret from env, set it,
     * install handler + filter. We do this manually instead of
     * calling uwg_core_init() because we want to interleave checks
     * between steps. */

    char *s = getenv("UWGS_TRACE_SECRET");
    if (!s || !*s) {
        fprintf(stderr, "FAIL: set UWGS_TRACE_SECRET=<nonzero u64> before running\n");
        return 1;
    }
    uwg_bypass_secret = strtoull(s, NULL, 10);
    if (uwg_bypass_secret == 0) {
        fprintf(stderr, "FAIL: UWGS_TRACE_SECRET must parse to a nonzero u64\n");
        return 1;
    }

    /* Step 1: pre-flight syscall before filter — should succeed. */
    int prefd = (int)uwg_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (prefd < 0) return fail("preflight socket()");
    (void)uwg_syscall1(SYS_close, prefd);

    /* Step 2: per-thread arena (sigaltstack). */
    if (uwg_core_init_thread() < 0) return fail("uwg_core_init_thread");

    /* Step 3: install handler. */
    if (uwg_install_sigsys_handler() < 0) return fail("uwg_install_sigsys_handler");

    /* Step 4: PR_SET_NO_NEW_PRIVS + filter. */
    if (uwg_install_seccomp_filter(uwg_bypass_secret) < 0) {
        return fail("uwg_install_seccomp_filter");
    }

    /* Step 5: trapped syscall via libc → goes through SIGSYS path
     * → uwg_dispatch → uwg_socket (REAL impl in socket_ops.c) →
     * passthrough_syscall to kernel → real fd back. The fd must be
     * a positive integer; libc errno must NOT be set. */
    uint64_t calls_before = 0, unh_before = 0;
    uwg_sigsys_stats(&calls_before, &unh_before);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char nbuf[32];
        uwg_print("FAIL: trapped socket() returned -1, errno=");
        uwg_print(uwg_fmt_u(nbuf, sizeof(nbuf), (unsigned long)errno));
        uwg_print(" (want a real fd; check uwg_socket impl reaches kernel)\n");
        return 1;
    }

    uint64_t calls_after = 0, unh_after = 0;
    uwg_sigsys_stats(&calls_after, &unh_after);

    if (calls_after <= calls_before) {
        uwg_print("FAIL: SIGSYS counter didn't increase\n");
        return 1;
    }
    if (unh_after != unh_before) {
        uwg_print("FAIL: dispatcher didn't reach uwg_socket impl\n");
        return 1;
    }
    /* Close should also work via dispatch. */
    uint64_t calls_pre_close = calls_after;
    int cr = close(fd);
    if (cr != 0) {
        char nbuf[32];
        uwg_print("FAIL: close returned ");
        uwg_print(uwg_fmt_u(nbuf, sizeof(nbuf), (unsigned long)cr));
        uwg_print(" errno=");
        uwg_print(uwg_fmt_u(nbuf, sizeof(nbuf), (unsigned long)errno));
        uwg_print("\n");
        return 1;
    }
    uint64_t calls_post_close = 0;
    uwg_sigsys_stats(&calls_post_close, NULL);
    if (calls_post_close <= calls_pre_close) {
        uwg_print("FAIL: close() did not go through SIGSYS handler\n");
        return 1;
    }

    /* Step 6: bypass-secret path — issue socket() with secret in arg6.
     * Filter must allow this directly to the kernel; we should get a
     * real fd back without bumping the SIGSYS counter.
     * Snapshot the counter NOW (after the close above also bumped it). */
    uint64_t calls_pre_bypass = 0;
    uwg_sigsys_stats(&calls_pre_bypass, NULL);

    long bypass_fd = uwg_passthrough_syscall3(SYS_socket,
                                              AF_INET, SOCK_DGRAM, 0);
    if (bypass_fd < 0) {
        fprintf(stderr, "FAIL: bypass-secret socket() returned %ld\n",
                bypass_fd);
        return 1;
    }
    (void)uwg_syscall6(SYS_close, bypass_fd, 0, 0, 0, 0,
                       (long)uwg_bypass_secret);

    uint64_t calls_post_bypass = 0;
    uwg_sigsys_stats(&calls_post_bypass, NULL);
    if (calls_post_bypass != calls_pre_bypass) {
        fprintf(stderr,
                "FAIL: bypass-secret socket() triggered SIGSYS "
                "(pre=%lu post=%lu)\n",
                (unsigned long)calls_pre_bypass,
                (unsigned long)calls_post_bypass);
        return 1;
    }

    /* Step 7: a non-trapped syscall (getpid) goes straight through. */
    long pid = uwg_syscall0(SYS_getpid);
    if (pid <= 0) {
        fprintf(stderr, "FAIL: getpid via raw syscall returned %ld\n", pid);
        return 1;
    }

    /* Post-filter: libc stdio is blocked because write is trapped.
     * Use the bypass-secret path. */
    uwg_print("OK: SIGSYS handler invoked, dispatch reached, "
              "bypass-secret skipped trap, non-trapped syscall passed "
              "through. Phase 1 scaffolding works.\n");
    return 0;
}
