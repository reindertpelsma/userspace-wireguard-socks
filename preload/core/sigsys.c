/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * SIGSYS handler — invoked by the kernel when the seccomp filter
 * traps a syscall. Decodes register state from the ucontext_t, calls
 * the per-syscall dispatcher in core, writes the return value back
 * to the ucontext's "syscall return" register so the kernel restores
 * it on signal return.
 *
 * ============================================================
 * SAFETY CONSTRAINTS — read before changing this file.
 * ============================================================
 *
 *  1. ASYNC-SIGNAL-SAFE.
 *     This handler runs in a signal context. POSIX permits calling
 *     only a small set of "async-signal-safe" libc functions here.
 *     We avoid libc entirely — every kernel call goes through the
 *     inline-asm wrappers in syscall.h. NO malloc/free, NO printf,
 *     NO pthread_*, NO stdio, NO errno.
 *
 *  2. NON-REENTRANT FOR SIGSYS.
 *     Installed with sigaction default-defer behavior (SA_NODEFER
 *     NOT set). The kernel adds SIGSYS to the thread's signal mask
 *     while this handler runs, so a syscall issued from inside the
 *     handler that *would* trap is queued, not delivered. But: any
 *     `uwg_passthrough_syscall*` from inside the handler MUST carry
 *     the bypass-secret in arg6 — that's what skips the filter
 *     entirely. If a passthrough_syscall ever loses the secret, the
 *     filter would queue a SIGSYS that fires when the handler
 *     returns; the kernel would deliver it as a real signal next,
 *     causing the second syscall to fail unpredictably. Always use
 *     the passthrough wrappers; never call uwg_syscallN directly
 *     for trapped syscalls.
 *
 *  3. PER-THREAD SIGNAL STACK.
 *     Installed with SA_ONSTACK. Each thread that enters this
 *     handler must have called sigaltstack() with a thread-local
 *     stack region. We allocate these via mmap MAP_ANONYMOUS|MAP_PRIVATE
 *     in uwg_core_init_thread() — never via malloc.
 *
 *  4. NEVER LONGJMP.
 *     The kernel's signal-return path expects to find its frame
 *     intact on the alternate stack. siglongjmp out of the handler
 *     would bypass that and corrupt subsequent signal handling.
 *
 *  5. RACE-RESISTANT ACCESS TO SHARED STATE.
 *     The shared_state mmap may be read by other threads (or by
 *     other processes that share the file). All accesses must use
 *     atomic loads/stores or guard with the rwlock built into
 *     uwgshared.Table. Never copy a struct tracked_fd by value;
 *     always read fields through atomic_load_explicit().
 *
 *  6. NO ALLOCATIONS ON THE HOT PATH.
 *     The dispatcher must not call mmap, brk, or any allocator. All
 *     scratch buffers (e.g. the per-thread fdproxy round-trip buffer)
 *     are pre-allocated in TLS at init time.
 *
 * ============================================================
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>

#include "syscall.h"
#include "dispatch.h"

/* SA_RESTORER and the kernel_sigaction layout aren't always exported
 * via <signal.h>. Define explicitly. */
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

/*
 * Per-arch helpers to read the syscall NR and 6 args from the
 * ucontext, and to write the return value back. The kernel
 * synthesizes these so they reflect exactly the registers the
 * tracee had at the SIGSYS-trap point.
 */

#if defined(__x86_64__)

static inline long uwg_uctx_syscall_nr(const ucontext_t *uc) {
    /* On x86_64 the syscall NR was in rax at trap entry; the kernel
     * preserves it via siginfo->si_syscall (also reflected in
     * REG_RAX of the ucontext for SIGSYS). We use REG_RAX directly
     * because it's the source of truth for the syscall the kernel
     * was about to dispatch. */
    return (long)uc->uc_mcontext.gregs[REG_RAX];
}

static inline void uwg_uctx_load_args(const ucontext_t *uc, long args[6]) {
    args[0] = (long)uc->uc_mcontext.gregs[REG_RDI];
    args[1] = (long)uc->uc_mcontext.gregs[REG_RSI];
    args[2] = (long)uc->uc_mcontext.gregs[REG_RDX];
    args[3] = (long)uc->uc_mcontext.gregs[REG_R10];
    args[4] = (long)uc->uc_mcontext.gregs[REG_R8];
    args[5] = (long)uc->uc_mcontext.gregs[REG_R9];
}

static inline void uwg_uctx_set_result(ucontext_t *uc, long result) {
    /* Kernel restores rax from this slot when the signal handler
     * returns (sigreturn). The tracee then sees `result` as the
     * syscall return value. */
    uc->uc_mcontext.gregs[REG_RAX] = result;
}

#elif defined(__aarch64__)

static inline long uwg_uctx_syscall_nr(const ucontext_t *uc) {
    /* On aarch64 the syscall NR is in x8 at SVC dispatch. The kernel
     * preserves it in the mcontext after SIGSYS. */
    return (long)uc->uc_mcontext.regs[8];
}

static inline void uwg_uctx_load_args(const ucontext_t *uc, long args[6]) {
    args[0] = (long)uc->uc_mcontext.regs[0];
    args[1] = (long)uc->uc_mcontext.regs[1];
    args[2] = (long)uc->uc_mcontext.regs[2];
    args[3] = (long)uc->uc_mcontext.regs[3];
    args[4] = (long)uc->uc_mcontext.regs[4];
    args[5] = (long)uc->uc_mcontext.regs[5];
}

static inline void uwg_uctx_set_result(ucontext_t *uc, long result) {
    uc->uc_mcontext.regs[0] = (uint64_t)result;
}

#else
#  error "uwg core sigsys: unsupported architecture"
#endif

/*
 * Defensive bookkeeping: count handler invocations and any
 * dispatcher returns that signal a real bug (-ENOSYS unexpected
 * for a trapped syscall). Atomic ops only — no locks, async-signal-
 * safe. Exposed via uwg_sigsys_stats() for tests / introspection.
 */
static _Atomic uint64_t uwg_sigsys_calls;
static _Atomic uint64_t uwg_sigsys_unhandled;

void uwg_sigsys_stats(uint64_t *calls, uint64_t *unhandled) {
    if (calls)
        *calls = atomic_load_explicit(&uwg_sigsys_calls,
                                      memory_order_relaxed);
    if (unhandled)
        *unhandled = atomic_load_explicit(&uwg_sigsys_unhandled,
                                          memory_order_relaxed);
}

/*
 * The handler. Signature dictated by sigaction(SA_SIGINFO).
 *
 * Robustness notes:
 *   - We do NOT trust si->si_syscall blindly; we cross-check against
 *     the ucontext's NR register. If they disagree (kernel bug? ABI
 *     drift?), we fail closed: set -ENOSYS as the result.
 *   - We trap a defined set of syscalls; if dispatch is asked for
 *     an NR outside that set, that means the seccomp filter is out
 *     of sync with the dispatch table. We fail closed (-ENOSYS) and
 *     bump the unhandled counter so the bug surfaces in a soak test.
 */
void uwg_sigsys_handler(int sig, siginfo_t *si, void *uctx_void) {
    /* Silence unused-arg warning while keeping the canonical signature. */
    (void)sig;

    atomic_fetch_add_explicit(&uwg_sigsys_calls, 1, memory_order_relaxed);

    ucontext_t *uc = (ucontext_t *)uctx_void;
    if (!uc) {
        /* Should never happen — kernel always provides ucontext for
         * SA_SIGINFO. If it does, we have nothing to write back to,
         * so the syscall return is undefined. Best we can do is bump
         * the counter and return — the tracee will see whatever was
         * in rax at trap. */
        atomic_fetch_add_explicit(&uwg_sigsys_unhandled, 1,
                                  memory_order_relaxed);
        return;
    }

    long nr = uwg_uctx_syscall_nr(uc);

    /* Cross-check with siginfo. SI_SYSCALL is set by the kernel for
     * SECCOMP_RET_TRAP. If they disagree we have an ABI mismatch —
     * fail closed. */
    if (si && si->si_syscall != (int)nr) {
        atomic_fetch_add_explicit(&uwg_sigsys_unhandled, 1,
                                  memory_order_relaxed);
        uwg_uctx_set_result(uc, -38L /* -ENOSYS */);
        return;
    }

    long args[6];
    uwg_uctx_load_args(uc, args);

    long result = uwg_dispatch(nr, args[0], args[1], args[2],
                               args[3], args[4], args[5]);

    /* uwg_dispatch returns -ENOSYS to mean "not handled". For now
     * (Phase 1) all dispatchers return -ENOSYS; that's why we count
     * unhandled separately to confirm the test loop reaches us. */
    if (result == -38L /* -ENOSYS */) {
        atomic_fetch_add_explicit(&uwg_sigsys_unhandled, 1,
                                  memory_order_relaxed);
    }

    uwg_uctx_set_result(uc, result);
    /* Return — kernel runs sigreturn, restores all registers
     * (including the rax we just set), tracee resumes immediately
     * after the trapped syscall instruction with our result in rax.
     * Tracee's libc / app code observes `result` as the syscall
     * return value and behaves accordingly. */
}

/*
 * Install the SIGSYS handler. Returns 0 on success or -errno.
 *
 * Init order requirements (from PHASE1_DESIGN.md):
 *   1. sigaltstack on each thread BEFORE this is installed for that
 *      thread (otherwise SA_ONSTACK has nowhere to go).
 *   2. This call BEFORE prctl(PR_SET_NO_NEW_PRIVS) and
 *      seccomp(SECCOMP_SET_MODE_FILTER). If the filter is installed
 *      first, an unlucky window between filter-install and handler-
 *      install would let SIGSYS reach the default handler, which
 *      kills the process.
 *
 * Uses raw syscall sigaction (not libc's) so it works in the static
 * build too.
 */
/*
 * Two installation paths:
 *
 *  UWG_FREESTANDING (the static-binary build, Phase 2):
 *    Use raw rt_sigaction. We must provide our own sa_restorer
 *    trampoline because the kernel WILL try to use it on signal
 *    return on x86_64, and the vDSO fallback isn't always picked
 *    up under sandbox runtimes (gVisor in particular). Phase 2
 *    will add the trampoline as a small asm function.
 *
 *  Default (the .so build):
 *    Use libc's sigaction(), which sets up sa_restorer correctly
 *    via __restore_rt. This is what every libc-linked program
 *    relies on; we just inherit that mechanism.
 */
#ifdef UWG_FREESTANDING

extern void uwg_sigreturn_trampoline(void);

int uwg_install_sigsys_handler(void) {
    struct kernel_sigaction {
        void     (*k_sa_handler)(int, siginfo_t *, void *);
        unsigned long k_sa_flags;
        void     (*k_sa_restorer)(void);
        unsigned long k_sa_mask;
    } sa = {
        .k_sa_handler = uwg_sigsys_handler,
        .k_sa_flags   = SA_SIGINFO | SA_ONSTACK | SA_RESTORER,
        .k_sa_restorer = uwg_sigreturn_trampoline, /* provided by Phase 2 */
        .k_sa_mask    = 0,
    };
    long rc = uwg_syscall4(SYS_rt_sigaction, SIGSYS, (long)&sa, 0, 8);
    return (rc < 0) ? (int)rc : 0;
}

#else  /* libc available */

#include <errno.h>

int uwg_install_sigsys_handler(void) {
    struct sigaction sa;
    sa.sa_sigaction = uwg_sigsys_handler;
    /* SA_ONSTACK is required for Go-runtime compatibility: Go's
     * runtime/signal_unix.go preserves user-installed signal
     * handlers ONLY if they're flagged with SA_ONSTACK. Without
     * the flag, Go's runtime treats the handler as "unwanted" and
     * may override it during runtime init, causing trapped
     * syscalls to crash or hang inside Go's signal machinery.
     * Per-thread sigaltstack is set up lazily in the handler
     * itself (or during early thread init in Phase 2). */
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    /* NO SA_NODEFER → kernel adds SIGSYS to mask while handler
     * runs → blocks recursive SIGSYS. */
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) {
        /* sigaction(2) failed — typically EFAULT or EINVAL.
         * libc set errno; we mirror that as -errno per our contract. */
        return -errno;
    }
    return 0;
}

#endif  /* UWG_FREESTANDING */
