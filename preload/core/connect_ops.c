/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * uwg_connect — establishes the per-fd tunnel attachment via fdproxy.
 *
 * Flow on a tunnel-relevant connect():
 *   1. look up state for fd
 *   2. if fd is not active / not INET / addr is loopback → passthrough
 *   3. format dest IP+port from sockaddr; format bind IP+port from
 *      saved state (may be 0/wildcard if no prior bind)
 *   4. open a fresh manager unix socket to fdproxy
 *   5. send "CONNECT <proto> <dest_ip> <dest_port> <bind_ip> <bind_port>\n"
 *   6. read "OK <bind_ip> <bind_port>\n" reply
 *   7. dup3 the manager fd over the original fd → app's view of `fd`
 *      is now the unix-socket data channel to fdproxy
 *   8. close the (now-redundant) manager fd
 *   9. update shared state: kind = TCP_STREAM / UDP_CONNECTED, proxied=1
 *  10. return 0
 *
 * Phase 1 limitations (TODO):
 *   - DNS-on-:53 forcing not implemented (legacy preload routes :53
 *     through a special handler; carry over later).
 *   - ICMP is detected via state.protocol but we don't yet special-
 *     case the proto string — uses "tcp"/"udp" generically.
 *   - O_NONBLOCK semantics on connect (returning EINPROGRESS for
 *     non-blocking TCP connects on tunnel fds) are not yet
 *     implemented.
 */

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

/* From addr_utils.c */
int uwg_addr_is_loopback(const struct sockaddr *addr);
int uwg_addr_format(const struct sockaddr *addr, char *ip_buf, size_t ip_len,
                    uint16_t *port, int *family);
int uwg_fmt_connect_line(char *out, size_t out_len, const char *cmd,
                         const char *proto,
                         const char *dest_ip, uint16_t dest_port,
                         const char *bind_ip, uint16_t bind_port);
int uwg_parse_ok_reply(const char *reply, char *ip_buf, size_t ip_len,
                       uint16_t *port);

#define SOCK_TYPE_MASK 0xff /* mask SOCK_NONBLOCK / SOCK_CLOEXEC bits */

long uwg_connect(int fd, const struct sockaddr *addr, uint32_t alen) {
    /* Always respect a NULL or oddly-sized addr by passthrough. */
    if (!addr || alen < sizeof(struct sockaddr)) {
        long rc = uwg_passthrough_syscall3(SYS_connect, fd, (long)addr, alen);
        uwg_tracef("connect fd=%d addr=null -> %ld", fd, rc);
        return rc;
    }

    char dest_dbg[64];
    uint16_t port_dbg = 0; int fam_dbg = 0;
    if (uwg_addr_format(addr, dest_dbg, sizeof(dest_dbg), &port_dbg, &fam_dbg) != 0) {
        dest_dbg[0] = '?'; dest_dbg[1] = 0;
    }

    struct tracked_fd state = uwg_state_lookup(fd);
    uwg_tracef("connect fd=%d to=%s:%d active=%d type=%d proto=%d",
               fd, dest_dbg, (int)port_dbg, state.active, state.type, state.protocol);

    /* Not tracked, not interesting → passthrough. */
    if (!state.active ||
        (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
        return uwg_passthrough_syscall3(SYS_connect, fd, (long)addr, alen);
    }

    /* DNS-on-:53 forcing — checked BEFORE the loopback shortcut so a
     * connect to 127.0.0.1:53 (resolv.conf style) gets diverted to
     * fdproxy's DNS endpoint rather than passing through to the
     * kernel's loopback resolver. */
    if (uwg_should_force_dns53(addr)) {
        int sock_type = state.type & SOCK_TYPE_MASK;
        long rc = uwg_force_dns_fd(fd, sock_type);
        if (rc < 0) return rc;
        /* Update remote state so getpeername returns the original
         * intended dest, not fdproxy's manager-side address. */
        struct tracked_fd post = uwg_state_lookup(fd);
        char ip[46]; uint16_t port = 0; int fam = 0;
        if (uwg_addr_format(addr, ip, sizeof(ip), &port, &fam) == 0) {
            post.remote_family = fam;
            post.remote_port = port;
            size_t i = 0;
            while (i < sizeof(post.remote_ip) - 1 && ip[i]) {
                post.remote_ip[i] = ip[i]; i++;
            }
            post.remote_ip[i] = 0;
            (void)uwg_state_store(fd, &post);
        }
        return 0;
    }

    /* Loopback → mark inactive, passthrough. */
    if (uwg_addr_is_loopback(addr)) {
        state.active = 0;
        (void)uwg_state_store(fd, &state);
        return uwg_passthrough_syscall3(SYS_connect, fd, (long)addr, alen);
    }

    /* Parse dest. */
    char dest_ip[46];
    uint16_t dest_port = 0;
    int family = 0;
    if (uwg_addr_format(addr, dest_ip, sizeof(dest_ip), &dest_port, &family) < 0) {
        return uwg_passthrough_syscall3(SYS_connect, fd, (long)addr, alen);
    }

    /* Determine bind IP + port from saved state (may be 0/wildcard). */
    char bind_ip[46];
    if (state.bound && state.bind_ip[0]) {
        size_t n = 0;
        while (n < sizeof(bind_ip) - 1 &&
               n < sizeof(state.bind_ip) && state.bind_ip[n]) {
            bind_ip[n] = state.bind_ip[n]; n++;
        }
        bind_ip[n] = 0;
    } else {
        if (family == AF_INET6) { bind_ip[0] = ':'; bind_ip[1] = ':'; bind_ip[2] = 0; }
        else                    { memcpy(bind_ip, "0.0.0.0", 8); }
    }
    uint16_t bind_port = state.bound ? (uint16_t)state.bind_port : 0;

    int sock_type = state.type & SOCK_TYPE_MASK;
    const char *proto = (sock_type == SOCK_DGRAM) ? "udp" : "tcp";

    /* Build CONNECT line. */
    char line[256];
    int line_len = uwg_fmt_connect_line(line, sizeof(line), "CONNECT", proto,
                                        dest_ip, dest_port, bind_ip, bind_port);
    if (line_len < 0) return line_len;

    /* Talk to fdproxy. */
    int mgr = uwg_fdproxy_connect();
    if (mgr < 0) return mgr;

    if (uwg_fdproxy_write_request(mgr, line) < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111; /* -ECONNREFUSED */
    }

    char reply[128];
    long rd = uwg_fdproxy_read_reply(mgr, reply, sizeof(reply));
    if (rd <= 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    char actual_bind_ip[46];
    uint16_t actual_bind_port = 0;
    if (uwg_parse_ok_reply(reply, actual_bind_ip, sizeof(actual_bind_ip),
                           &actual_bind_port) != 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    /* Update shared state with the actual bind we got. */
    state.bound = 1;
    state.remote_family = family;
    state.remote_port = dest_port;
    {
        size_t n = 0;
        while (n < sizeof(state.remote_ip) - 1 && dest_ip[n]) {
            state.remote_ip[n] = dest_ip[n]; n++;
        }
        state.remote_ip[n] = 0;
    }
    if (actual_bind_ip[0]) {
        size_t n = 0;
        while (n < sizeof(state.bind_ip) - 1 && actual_bind_ip[n]) {
            state.bind_ip[n] = actual_bind_ip[n]; n++;
        }
        state.bind_ip[n] = 0;
        state.bind_port = actual_bind_port;
    }
    state.proxied = 1;
    state.kind = (sock_type == SOCK_DGRAM) ? KIND_UDP_CONNECTED
                                            : KIND_TCP_STREAM;
    (void)uwg_state_store(fd, &state);

    /* Replace the original fd with the manager-side socket. dup3
     * with target=fd closes any prior content of fd atomically. */
    long rc = uwg_passthrough_syscall3(SYS_dup3, mgr, fd, 0);
    if (rc < 0) {
        /* dup3 failed; the fd's content is unchanged. Best we can
         * do is close the manager fd and return the error. */
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return rc;
    }
    /* dup3 made `fd` a copy of `mgr` — both refer to the same kernel
     * socket. We close `mgr` so only `fd` keeps the reference. */
    (void)uwg_passthrough_syscall1(SYS_close, mgr);
    return 0;
}
