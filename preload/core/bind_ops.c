/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * uwg_bind / uwg_listen / uwg_accept / uwg_accept4 — same flow shape
 * as connect_ops but for the listener side.
 *
 *   bind:    record bind addr+port in shared state; passthrough to
 *            kernel for the underlying socket. The actual fdproxy
 *            ATTACH happens lazily at listen() (TCP) or first
 *            recv*() (UDP unconnected) per legacy uwgpreload.c.
 *   listen:  for SOCK_STREAM with active state → talk to fdproxy
 *            "LISTEN tcp <ip> <port> <reuseaddr> <reuseport>" and
 *            replace the fd with the returned manager socket.
 *   accept:  if fd is a tunnel listener, the data path is already
 *            on the manager socket; accept reads connection-arrival
 *            frames from fdproxy and returns a new fd that's the
 *            attached socketpair-end.
 *
 * Phase 1 status:
 *   - bind  is implemented (state-recording only).
 *   - listen / accept / accept4 are stubs returning -ENOSYS for now;
 *     they need the fdproxy "ATTACH" dance and per-accept frame
 *     parsing which is heavier than connect's one-shot. Lifting
 *     them mechanically from legacy uwgpreload.c is the next
 *     migration commit.
 */

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

int uwg_addr_is_loopback(const struct sockaddr *addr);
int uwg_addr_format(const struct sockaddr *addr, char *ip_buf, size_t ip_len,
                    uint16_t *port, int *family);

#define SOCK_TYPE_MASK 0xff

long uwg_bind(int fd, const struct sockaddr *addr, uint32_t alen) {
    if (!addr || alen < sizeof(struct sockaddr)) {
        return uwg_passthrough_syscall3(SYS_bind, fd, (long)addr, alen);
    }

    struct tracked_fd state = uwg_state_lookup(fd);

    if (!state.active ||
        (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
        return uwg_passthrough_syscall3(SYS_bind, fd, (long)addr, alen);
    }

    /* Loopback bind → mark inactive, passthrough. */
    if (uwg_addr_is_loopback(addr)) {
        state.active = 0;
        (void)uwg_state_store(fd, &state);
        return uwg_passthrough_syscall3(SYS_bind, fd, (long)addr, alen);
    }

    /* Tunnel-class bind: just record the address. The actual
     * tunnel-side listener is created on listen() (TCP) or first
     * recv (UDP). Returns 0 — we don't actually call the kernel's
     * bind on a tunnel address since the kernel can't bind a real
     * socket to a tunnel-private IP. The caller's perception is
     * "bind succeeded"; later operations on the fd dispatch through
     * shared state. */
    char ip[46];
    uint16_t port = 0;
    int family = 0;
    if (uwg_addr_format(addr, ip, sizeof(ip), &port, &family) < 0) {
        return -22;
    }
    state.bound = 1;
    state.bind_family = family;
    state.bind_port = port;
    {
        size_t n = 0;
        while (n < sizeof(state.bind_ip) - 1 && ip[n]) {
            state.bind_ip[n] = ip[n]; n++;
        }
        state.bind_ip[n] = 0;
    }
    (void)uwg_state_store(fd, &state);
    return 0;
}

/* Implemented in listener_ops.c. */
long uwg_start_tcp_listener(int fd);
long uwg_managed_accept(int listener_fd, struct sockaddr *addr,
                        uint32_t *addrlen);

long uwg_listen(int fd, int backlog) {
    struct tracked_fd state = uwg_state_lookup(fd);
    /* Non-tunnel fd: passthrough. */
    if (!state.active && !state.proxied) {
        return uwg_passthrough_syscall2(SYS_listen, fd, backlog);
    }
    /* If already a tunnel listener, idempotent success. */
    if (state.proxied && state.kind == KIND_TCP_LISTENER) return 0;
    /* TCP stream → set up via fdproxy. */
    if ((state.type & SOCK_TYPE_MASK) == SOCK_STREAM) {
        return uwg_start_tcp_listener(fd);
    }
    /* UDP doesn't use listen(); pass through (kernel will reject). */
    return uwg_passthrough_syscall2(SYS_listen, fd, backlog);
}

long uwg_accept(int fd, struct sockaddr *addr, uint32_t *alen) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (!state.proxied) {
        return uwg_passthrough_syscall3(SYS_accept, fd, (long)addr, (long)alen);
    }
    return uwg_managed_accept(fd, addr, alen);
}

long uwg_accept4(int fd, struct sockaddr *addr, uint32_t *alen, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (!state.proxied) {
        return uwg_passthrough_syscall4(SYS_accept4, fd, (long)addr,
                                        (long)alen, flags);
    }
    long rc = uwg_managed_accept(fd, addr, alen);
    if (rc < 0) return rc;
    /* Apply SOCK_NONBLOCK / SOCK_CLOEXEC requested via flags. */
    if (flags & 04000 /* SOCK_NONBLOCK */) {
        long fl = uwg_passthrough_syscall3(SYS_fcntl, (int)rc, 3 /* F_GETFL */, 0);
        if (fl >= 0) {
            (void)uwg_passthrough_syscall3(SYS_fcntl, (int)rc, 4 /* F_SETFL */,
                                            fl | 04000);
        }
    }
    if (flags & 02000000 /* SOCK_CLOEXEC */) {
        (void)uwg_passthrough_syscall3(SYS_fcntl, (int)rc, 2 /* F_SETFD */, 1);
    }
    return rc;
}
