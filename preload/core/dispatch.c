/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 1 dispatch: stubs for every uwg_* handler. Each returns
 * -ENOSYS so the SIGSYS handler exercise loop can confirm the path
 * "kernel SIGSYS → handler → uwg_dispatch → uwg_<syscall> → -ENOSYS
 * → handler writes result → kernel sigreturn → tracee sees -ENOSYS"
 * works end-to-end before any real per-syscall logic lands.
 *
 * Phase 1's later commits replace each stub with the real
 * implementation (extracted from the existing uwgpreload.c). Until
 * then, a process that installs the filter will see network syscalls
 * fail with ENOSYS — that's expected, and tests use
 * uwg_sigsys_stats() to confirm the handler is being reached at all.
 *
 * Async-signal-safe: every function here is callable from inside
 * the SIGSYS handler. Stubs trivially are; concrete impls must
 * preserve this property.
 */

#include <sys/syscall.h>

#include "dispatch.h"
#include "syscall.h"

#define ENOSYS_RET (-38L)

/* The big switch. Kept dense so the compiler can lay it out as a
 * jump table on architectures that support it. Syscall NRs are
 * intentionally listed in numeric order within each group. */
long uwg_dispatch(long nr, long a1, long a2, long a3,
                  long a4, long a5, long a6) {
    switch (nr) {
    /* --- control plane --- */
    case SYS_socket:      return uwg_socket((int)a1, (int)a2, (int)a3);
    case SYS_socketpair:  return uwg_socketpair((int)a1, (int)a2, (int)a3, (int *)a4);
    case SYS_close:       return uwg_close((int)a1);
    case SYS_connect:     return uwg_connect((int)a1, (const struct sockaddr *)a2, (uint32_t)a3);
    case SYS_bind:        return uwg_bind((int)a1, (const struct sockaddr *)a2, (uint32_t)a3);
    case SYS_listen:      return uwg_listen((int)a1, (int)a2);
    case SYS_accept:      return uwg_accept((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_accept4:     return uwg_accept4((int)a1, (struct sockaddr *)a2, (uint32_t *)a3, (int)a4);
    case SYS_setsockopt:  return uwg_setsockopt((int)a1, (int)a2, (int)a3, (const void *)a4, (uint32_t)a5);
    case SYS_getsockopt:  return uwg_getsockopt((int)a1, (int)a2, (int)a3, (void *)a4, (uint32_t *)a5);
    case SYS_getsockname: return uwg_getsockname((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_getpeername: return uwg_getpeername((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_dup:         return uwg_dup((int)a1);
#ifdef SYS_dup2
    case SYS_dup2:        return uwg_dup2((int)a1, (int)a2);
#endif
    case SYS_dup3:        return uwg_dup3((int)a1, (int)a2, (int)a3);
    case SYS_fcntl:       return uwg_fcntl((int)a1, (int)a2, (long)a3);
    case SYS_shutdown:    return uwg_shutdown((int)a1, (int)a2);

    /* --- message-style --- */
    case SYS_recvfrom:    return uwg_recvfrom((int)a1, (void *)a2, (size_t)a3, (int)a4, (struct sockaddr *)a5, (uint32_t *)a6);
    case SYS_recvmsg:     return uwg_recvmsg((int)a1, (struct msghdr *)a2, (int)a3);
    case SYS_recvmmsg:    return uwg_recvmmsg((int)a1, (struct mmsghdr *)a2, (unsigned int)a3, (int)a4, (struct timespec *)a5);
    case SYS_sendto:      return uwg_sendto((int)a1, (const void *)a2, (size_t)a3, (int)a4, (const struct sockaddr *)a5, (uint32_t)a6);
    case SYS_sendmsg:     return uwg_sendmsg((int)a1, (const struct msghdr *)a2, (int)a3);
    case SYS_sendmmsg:    return uwg_sendmmsg((int)a1, (struct mmsghdr *)a2, (unsigned int)a3, (int)a4);

    /* --- stream-style --- */
    case SYS_read:        return uwg_read((int)a1, (void *)a2, (size_t)a3);
    case SYS_write:       return uwg_write((int)a1, (const void *)a2, (size_t)a3);
    case SYS_readv:       return uwg_readv((int)a1, (const struct iovec *)a2, (int)a3);
    case SYS_writev:      return uwg_writev((int)a1, (const struct iovec *)a2, (int)a3);
    case SYS_pread64:     return uwg_pread((int)a1, (void *)a2, (size_t)a3, (int64_t)a4);
    case SYS_pwrite64:    return uwg_pwrite((int)a1, (const void *)a2, (size_t)a3, (int64_t)a4);

    /* --- handler-protection --- */
    case SYS_rt_sigaction:
        /* Reject SIGSYS sigaction silently (return success). Other
         * signums passthrough to the kernel. SIGSYS = 31 on Linux. */
        if ((int)a1 == 31) {
            /* Application thinks it installed a handler; ours stays. */
            return 0;
        }
        return uwg_passthrough_syscall4(SYS_rt_sigaction, a1, a2, a3, a4);

    default:
        /* Filter and dispatch table out of sync — bug. The filter
         * trapped a syscall we didn't register. Fail closed. */
        return ENOSYS_RET;
    }
}

/* All uwg_* dispatchers are implemented across the per-op .c files:
 *   socket_ops.c   — socket, socketpair, close
 *   connect_ops.c  — connect
 *   bind_ops.c     — bind (real); listen / accept / accept4
 *                    (passthrough for non-tunnel; -ENOSYS for tunnel
 *                    until the listener migration commit)
 *   stream_ops.c   — read, write, readv, writev, pread64, pwrite64
 *   msg_ops.c      — recvfrom, sendto, recvmsg, sendmsg, recvmmsg,
 *                    sendmmsg (all with MSG_DONTWAIT propagation;
 *                    UDP-non-stream cases -ENOSYS until framing
 *                    helpers land)
 *   fd_ops.c       — dup, dup2, dup3, fcntl, setsockopt, getsockopt,
 *                    getsockname, getpeername, shutdown
 */
