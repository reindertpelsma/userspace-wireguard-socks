/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 1 seccomp filter: traps the syscall surface that uwg_*
 * dispatchers handle, allows everything else through. The filter
 * exempts any syscall whose 6th argument equals the bypass secret,
 * which is how `uwg_passthrough_syscall*` re-issues kernel syscalls
 * from inside core dispatchers without recursing into the SIGSYS
 * handler.
 *
 * Filter rule order (top to bottom; first match wins):
 *
 *   1.  Architecture check — refuse non-x86_64 / non-aarch64 frames
 *       (kernels can deliver mixed-arch syscalls via 32-bit compat;
 *       we ignore those for now).
 *   2.  Bypass-secret check — args[5] == BYPASS_SECRET → ALLOW.
 *   3.  execve / execveat → RET_TRACE (Phase 2 bootstrap supervisor).
 *   4.  Trapped syscalls → SECCOMP_RET_TRAP (delivered as SIGSYS).
 *   5.  Default → ALLOW.
 *
 * Built by hand as a cBPF program. Doing this in seccomp_with_libseccomp
 * would link us to libseccomp (which we don't want for the static-binary
 * build) and would lose the args[5] check granularity.
 *
 * The filter is INSTALL-once-and-forget: kernel inherits across fork
 * and execve. The bootstrap supervisor in Phase 2 will use the
 * RET_TRACE on execve to detect new binaries and inject preload there
 * if needed. Until then, RET_TRACE without a tracer is treated as
 * RET_ALLOW by the kernel — the execve passes through unhindered.
 */

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "syscall.h"

#define UWG_FILTER_NR_OFFSET     offsetof(struct seccomp_data, nr)
#define UWG_FILTER_ARCH_OFFSET   offsetof(struct seccomp_data, arch)
#define UWG_FILTER_ARG5_LO       offsetof(struct seccomp_data, args[5])
#define UWG_FILTER_ARG5_HI       (offsetof(struct seccomp_data, args[5]) + 4)

#if defined(__x86_64__)
#  define UWG_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define UWG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#  error "uwg core: unsupported arch for seccomp filter"
#endif

/*
 * Trap list. These are syscalls the core dispatchers handle.
 * Kept as a static const so callers can introspect for tests.
 */
/*
 * Trap list scope — Phase 1 trade-off.
 *
 * The full surface (read/write/close/dup/fcntl + network) is what
 * shim_libc covers; trapping in the kernel too is the belt-and-
 * braces safety net for raw asm. BUT: trapping read/write/close
 * makes the libc-init window after execve fatal — those are
 * heavy-use syscalls during init, and the SIGSYS handler is
 * process-local and reset on exec, so the kernel's default
 * disposition (terminate) fires before our constructor reinstalls
 * the handler. That's the chromium-fork+exec problem.
 *
 * Trim the trap list to network-only syscalls. libc-init doesn't
 * touch socket/connect/bind/listen/accept/sendmsg/recvmsg, so the
 * post-exec window is safe. Raw asm read/write/close/dup/fcntl on
 * tunnel-managed fds will bypass our interception — accepted as a
 * Phase 1 trade-off; shim_libc still catches the libc-routed
 * common case. The full trap list returns when Phase 1.5's execve
 * supervisor lands.
 */
static const int uwg_trapped_syscalls[] = {
    /* control-plane — socket creation, connection, listener setup */
    SYS_socket,
    SYS_socketpair,
    SYS_connect,
    SYS_bind,
    SYS_listen,
    SYS_accept,
    SYS_accept4,
    SYS_setsockopt,
    SYS_getsockopt,
    SYS_getsockname,
    SYS_getpeername,
    SYS_shutdown,

    /* message-style — explicit network IO */
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_recvmmsg,
    SYS_sendto,
    SYS_sendmsg,
    SYS_sendmmsg,

    /* read / write / close / dup / fcntl deliberately NOT trapped:
     * libc-init uses them heavily, post-exec window would die. The
     * shim_libc layer catches these at the libc level for tunnel
     * fds. Raw-asm uses leak — Phase 1.5 supervisor closes the
     * gap by re-arming the SIGSYS handler before libc-init runs. */

    /* rt_sigaction was previously trapped to protect our SIGSYS handler
     * from being clobbered by application runtimes (Go's runtime
     * installs its own SIGSYS handler during M startup; chromium-style
     * sandbox layers do similar). Removed because it makes the post-
     * execve window in the child fatal: glibc-init calls rt_sigaction
     * before LD_PRELOAD .so constructors run, the new process has no
     * SIGSYS handler yet (signal handlers are reset on execve), and the
     * inherited seccomp filter trapping rt_sigaction routes that call
     * to SIGSYS → kernel default action (terminate). Trading off the
     * rt_sigaction-trap defence-in-depth for the much more common
     * dynamic-binary execve case. The shim_libc layer + handler-self-
     * defense in dispatch.c (silently succeed on rt_sigaction(SIGSYS))
     * still cover libc-routed callers. Raw asm rt_sigaction(SIGSYS)
     * after init is now a known gap (mitigated by rt_sigaction-on-
     * SIGSYS being a vanishingly rare workload). */
};

/* execve / execveat → RET_TRACE for the systrap-supervised mode.
 *
 * Behaviour switches at runtime based on whether a supervisor is
 * attached:
 *
 *   - `systrap` (no supervisor): traced list is empty; execve and
 *     execveat fall through to the default RET_ALLOW. The wrapped
 *     binary's exec into a static child loses interception (the
 *     documented systrap limitation — see PHASE2_DESIGN.md and
 *     docs/features/transparent-wrapper.md).
 *
 *   - `systrap-supervised` (UWGS_SUPERVISED=1): traced list is
 *     {SYS_execve, SYS_execveat}; the wrapper attaches a ptrace
 *     supervisor that catches PTRACE_EVENT_SECCOMP for these and
 *     re-arms the appropriate injection (LD_PRELOAD propagation
 *     for dynamic targets, freestanding-blob inject for static).
 *
 * Linux's seccomp filter caveat: RET_TRACE with NO tracer
 * attached makes the kernel fail the syscall with -ENOSYS
 * (man seccomp(2)). So we MUST only enable the traced entries
 * when the wrapper has confirmed it's attached as a tracer.
 */
static const int uwg_traced_syscalls_supervised[] = {
#ifdef SYS_execve
    SYS_execve,
#endif
#ifdef SYS_execveat
    SYS_execveat,
#endif
};
#define UWG_N_TRACED_SUPERVISED \
    (sizeof(uwg_traced_syscalls_supervised) / sizeof(uwg_traced_syscalls_supervised[0]))

/* Compile-time sentinel for the unsupervised case. */
static const int uwg_traced_syscalls_unsupervised[] = {0};
#define UWG_N_TRACED_UNSUPERVISED 0

#define UWG_N_TRAPPED  (sizeof(uwg_trapped_syscalls) / sizeof(uwg_trapped_syscalls[0]))

/* Supervised flag — set by uwg_core_init() in init.c after it reads
 * UWGS_SUPERVISED from the environment. The seccomp filter builder
 * reads this to decide whether to add execve/execveat to the
 * RET_TRACE list. */
int uwg_seccomp_supervised_flag = 0;

/*
 * Filter program build buffer. Sized to comfortably hold:
 *   - 2 instr arch check
 *   - 4 instr bypass-secret check (load lo, jmp neq, load hi, jmp eq)
 *   - 2 * UWG_N_TRACED  (load nr is shared; one jeq per trace target → ret)
 *   - 2 * UWG_N_TRAPPED (one jeq per trap target → ret)
 *   - 1 final ALLOW
 *
 * 256 instructions is plenty (kernel limit is 32768).
 */
#define UWG_FILTER_MAX_INSNS 256

struct uwg_filter_prog {
    struct sock_filter insns[UWG_FILTER_MAX_INSNS];
    size_t n;
};

static void uwg_emit(struct uwg_filter_prog *p, struct sock_filter ins) {
    /* Caller is responsible for not exceeding UWG_FILTER_MAX_INSNS. */
    p->insns[p->n++] = ins;
}

/*
 * Build the filter program. Returns 0 on success, -EINVAL if the
 * insn buffer would overflow. Output is a struct sock_fprog that
 * the caller passes to seccomp(2) directly.
 */
static int uwg_build_filter(struct uwg_filter_prog *p, uint64_t bypass_secret,
                            int supervised) {
    p->n = 0;
    const int *traced = supervised
        ? uwg_traced_syscalls_supervised
        : uwg_traced_syscalls_unsupervised;
    size_t n_traced = supervised
        ? UWG_N_TRACED_SUPERVISED
        : (size_t)UWG_N_TRACED_UNSUPERVISED;

    /* (1) architecture check */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARCH_OFFSET));
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, UWG_AUDIT_ARCH, 1, 0));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    /* (2) bypass-secret check on args[5].
     * cBPF can only load 32 bits at a time, so we check lo and hi
     * halves of the 64-bit arg separately. The jumps are arranged so
     * that any mismatch falls through to the next rule; an exact match
     * returns ALLOW immediately. */
    uint32_t lo = (uint32_t)(bypass_secret & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)((bypass_secret >> 32) & 0xFFFFFFFFu);

    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_LO));
    /* if lo != expected → skip the hi check + ALLOW return (3 insns) */
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, lo, 0, 3));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_HI));
    /* if hi != expected → skip the ALLOW return (1 insn) */
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hi, 0, 1));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    /* From here on we test the syscall nr. Load it once. */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_NR_OFFSET));

    /* (3) execve / execveat → RET_TRACE (only when supervised)
     * We emit one JEQ per syscall; a match returns RET_TRACE
     * immediately, otherwise falls through to the trap list. */
    for (size_t i = 0; i < n_traced; i++) {
        uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 traced[i], 0, 1));
        uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));
    }

    /* (4) trapped syscalls → SECCOMP_RET_TRAP */
    for (size_t i = 0; i < UWG_N_TRAPPED; i++) {
        uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 uwg_trapped_syscalls[i], 0, 1));
        uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
    }

    /* (5) default — let the kernel handle it */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    if (p->n > UWG_FILTER_MAX_INSNS) {
        return -22; /* -EINVAL */
    }
    return 0;
}

/*
 * Install the filter. Returns 0 on success or negative -errno.
 * Must be called AFTER PR_SET_NO_NEW_PRIVS and AFTER the SIGSYS
 * handler is installed.
 *
 * Uses raw syscalls — no libc — so it works in both .so and static
 * builds and is safe to call from the freestanding `core` layer.
 *
 * SECCOMP_FILTER_FLAG_TSYNC propagates the filter to all current
 * threads atomically. Any future thread (clone after this point)
 * inherits the filter automatically per kernel semantics.
 */
int uwg_install_seccomp_filter(uint64_t bypass_secret) {
    /* A zero secret would match any syscall whose unused arg6 happens
     * to be zero (the common case for syscalls with <6 args), making
     * the filter a no-op. Refuse rather than ship a broken filter.
     * Caller must generate a cryptographically-random nonzero secret
     * (uwgwrapper does this via /dev/urandom). */
    if (bypass_secret == 0) {
        return -22; /* -EINVAL */
    }

    int supervised = uwg_seccomp_supervised_flag;
    struct uwg_filter_prog prog;
    int rc = uwg_build_filter(&prog, bypass_secret, supervised);
    if (rc < 0) {
        return rc;
    }

    /* PR_SET_NO_NEW_PRIVS is required for non-cap_sys_admin processes
     * to install seccomp filters. Idempotent — safe to call again
     * even if the wrapper-launcher already set it. */
    long pr_rc = uwg_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (pr_rc < 0) {
        return (int)pr_rc;
    }

    struct sock_fprog fprog = {
        .len = (unsigned short)prog.n,
        .filter = prog.insns,
    };

    long sc_rc = uwg_syscall3(SYS_seccomp,
                              SECCOMP_SET_MODE_FILTER,
                              SECCOMP_FILTER_FLAG_TSYNC,
                              (long)&fprog);
    if (sc_rc < 0) {
        return (int)sc_rc;
    }
    return 0;
}

/* Test helper: returns the trapped-syscall list for unit testing. */
const int *uwg_seccomp_trapped_list(size_t *n) {
    if (n) *n = UWG_N_TRAPPED;
    return uwg_trapped_syscalls;
}

const int *uwg_seccomp_traced_list(size_t *n) {
    /* Returns the active traced list based on the supervised flag.
     * When supervised, includes execve/execveat; otherwise empty. */
    if (uwg_seccomp_supervised_flag) {
        if (n) *n = UWG_N_TRACED_SUPERVISED;
        return uwg_traced_syscalls_supervised;
    }
    if (n) *n = UWG_N_TRACED_UNSUPERVISED;
    return uwg_traced_syscalls_unsupervised;
}
