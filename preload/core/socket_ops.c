/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * uwg_socket / uwg_socketpair / uwg_close — first concrete dispatcher
 * implementations. The pattern they establish is the template for
 * every other uwg_<op> in core/.
 *
 * Async-signal-safe: only inline-asm syscalls + atomic table ops.
 *
 * Lifecycle invariant: every socket fd that the table tracks must
 * have been recorded by uwg_socket() (or socketpair / accept variants
 * that produce new fds), and must be cleared by uwg_close() (or by
 * the implicit cleanup when the file's fd is reused for a different
 * file via dup2). Any path that creates a fd without recording it,
 * or releases without clearing, leaks shared-table slots.
 */

#include <stddef.h>
#include "freestanding.h"
#include <sys/socket.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

/* Implements: socket(domain, type, protocol).
 *
 * Strategy: every socket() call creates a real kernel fd directly
 * via passthrough_syscall (the fd may end up being tunnel-managed
 * later via connect()/bind() to a tunnel address; that's where the
 * tracking-table entry gets populated. At socket() time we just
 * record the {domain, type, proto} so connect() knows the family).
 *
 * The fd returned IS a real kernel socket. If the application calls
 * the bypass path on it (read/write on a local AF_INET socket that
 * never connects to a tunnel addr), we never enter the tunnel-handling
 * path and the kernel does its normal job.
 */
long uwg_socket(int domain, int type, int protocol) {
    long fd = uwg_passthrough_syscall3(SYS_socket, domain, type, protocol);
    uwg_tracef("socket domain=%d type=%d proto=%d -> %ld", domain, type, protocol, fd);
    if (fd < 0) return fd;

    /* Only track fds in families the wrapper cares about. AF_UNIX,
     * AF_PACKET etc. fall through unrecorded. */
    if (domain == AF_INET || domain == AF_INET6) {
        struct tracked_fd s;
        memset(&s, 0, sizeof(s));
        s.active   = 1;
        s.domain   = domain;
        s.type     = type;
        s.protocol = protocol;
        /* kind defaults to KIND_NONE; connect()/bind() will refine
         * to KIND_TCP_STREAM / KIND_UDP_CONNECTED / etc. */
        (void)uwg_state_store((int)fd, &s);
    }
    return fd;
}

/* Implements: socketpair(domain, type, protocol, sv[2]).
 *
 * Always pure passthrough — socketpair only makes sense for AF_UNIX
 * or AF_LOCAL, which are local-only and never tunnel-managed. We
 * pass through so the kernel does its job; we don't track the
 * resulting fds because they can't transition to tunnel state.
 */
long uwg_socketpair(int domain, int type, int protocol, int sv[2]) {
    return uwg_passthrough_syscall4(SYS_socketpair, domain, type, protocol,
                                    (long)sv);
}

/* Implements: close(fd).
 *
 * We unconditionally clear the table slot for `fd` (no-op if not
 * present), then pass through to the kernel. The order matters:
 * clear FIRST so a concurrent lookup never sees a freed-and-reused
 * fd as "tunnel-managed".
 *
 * Note: close() can fail (e.g. EBADF, EINTR). We propagate the
 * kernel's return value as -errno. If close fails AFTER we cleared
 * the table, the slot is unrecoverable for this pid — but that's
 * fine because a failing close means the fd shouldn't be reused.
 */
long uwg_close(int fd) {
    uwg_state_clear(fd);
    return uwg_passthrough_syscall1(SYS_close, fd);
}
