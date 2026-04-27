/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * TCP and UDP listener flow: bridge between the tracee's listen()/
 * accept()/recv()-on-unconnected-UDP and the fdproxy LISTEN/ATTACH
 * protocol.
 *
 * Lifted from legacy uwgpreload.c::start_tcp_listener,
 * ensure_udp_listener, managed_accept. Adapted for the freestanding
 * core: no libc, no malloc, no errno globals, only inline-asm
 * syscalls + atomic shared-state ops.
 *
 * High-level flow:
 *
 *   uwg_listen on TCP:
 *     1. send "LISTEN tcp <bind-ip> <bind-port> <reuse-addr> <reuse-port>\n"
 *        to fdproxy
 *     2. parse "OKLISTEN <token> <ip> <port>\n" reply
 *     3. update shared state: kind=KIND_TCP_LISTENER, proxied=1
 *     4. dup3 the manager fd over the tracee's listen-fd —
 *        subsequent accept() reads ACCEPT-frames from this fd
 *
 *   ensure_udp_listener (called lazily from sendto/recvmsg on an
 *   unconnected UDP fd):
 *     1. send "LISTEN udp <bind-ip> <bind-port> <reuse-addr> <reuse-port>\n"
 *     2. parse "OKUDP <ip> <port>\n" reply
 *     3. update shared state: kind=KIND_UDP_LISTENER, proxied=1
 *     4. dup3 manager fd over tracee's UDP fd — subsequent
 *        recvmsg/sendmsg use the data-plane framing protocol
 *
 *   uwg_accept on a TCP listener:
 *     1. read "ACCEPT <token> <connection-id> <ip> <port>\n" line
 *        from the listener fd
 *     2. send "ATTACH <token> <connection-id>\n" to a NEW fdproxy
 *        connection
 *     3. parse "OK\n" reply (just two characters)
 *     4. the new fdproxy-side fd IS the accepted connection
 *     5. register it in shared state as KIND_TCP_STREAM
 *     6. return the fd to the caller
 */

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

/* From addr_utils.c */
int uwg_addr_format(const struct sockaddr *addr, char *ip_buf, size_t ip_len,
                    uint16_t *port, int *family);

#define SOCK_TYPE_MASK 0xff

/*
 * Build a "LISTEN <proto> <ip> <port> <reuseaddr> <reuseport>\n"
 * line. Returns bytes written or -ENOBUFS.
 */
static int build_listen_line(char *out, size_t out_len, const char *proto,
                             const char *ip, uint16_t port,
                             int reuse_addr, int reuse_port) {
    if (!out || out_len < 32) return -75;
    /* Hand-built — one fewer dependency. */
    size_t off = 0;
    const char *parts[] = { "LISTEN ", proto, " ", ip, " " };
    for (size_t pi = 0; pi < 5; pi++) {
        const char *p = parts[pi];
        while (*p) {
            if (off + 1 >= out_len) return -75;
            out[off++] = *p++;
        }
    }
    /* port digits */
    char tmp[12]; int ti = 0;
    if (port == 0) { tmp[ti++] = '0'; }
    else {
        unsigned int v = port;
        while (v) { tmp[ti++] = (char)('0' + v % 10); v /= 10; }
    }
    while (ti) {
        if (off + 1 >= out_len) return -75;
        out[off++] = tmp[--ti];
    }
    if (off + 5 >= out_len) return -75;
    out[off++] = ' ';
    out[off++] = (char)(reuse_addr ? '1' : '0');
    out[off++] = ' ';
    out[off++] = (char)(reuse_port ? '1' : '0');
    out[off++] = '\n';
    out[off] = 0;
    return (int)off;
}

/* Parse "OKLISTEN <token> <ip> <port>" or "OKUDP <ip> <port>".
 * Returns 0 on success, -1 on parse failure. token_buf may be NULL
 * (UDP case). */
static int parse_listen_reply(const char *reply, const char *prefix,
                              char *token_buf, size_t token_len,
                              char *ip_buf, size_t ip_len,
                              uint16_t *port_out) {
    /* Match prefix. */
    size_t plen = 0;
    while (prefix[plen]) plen++;
    for (size_t i = 0; i < plen; i++) {
        if (reply[i] != prefix[i]) return -1;
    }
    const char *p = reply + plen;
    while (*p == ' ' || *p == '\t') p++;

    /* Optional token field for OKLISTEN. */
    if (token_buf && token_len > 0) {
        size_t i = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            if (i + 1 >= token_len) return -1;
            token_buf[i++] = *p++;
        }
        token_buf[i] = 0;
        while (*p == ' ' || *p == '\t') p++;
    }

    /* IP field. */
    {
        size_t i = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            if (i + 1 >= ip_len) return -1;
            ip_buf[i++] = *p++;
        }
        ip_buf[i] = 0;
        while (*p == ' ' || *p == '\t') p++;
    }

    /* Port field — decimal uint16. */
    unsigned int v = 0;
    int saw_digit = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (unsigned int)(*p - '0');
        if (v > 0xFFFFu) return -1;
        p++;
        saw_digit = 1;
    }
    if (!saw_digit) return -1;
    *port_out = (uint16_t)v;
    return 0;
}

/* Determine the bind IP text from saved state. Falls back to
 * 0.0.0.0 / :: if not bound. */
static void resolve_bind_text(const struct tracked_fd *state,
                              char *out, size_t out_len) {
    if (state->bound && state->bind_ip[0]) {
        size_t i = 0;
        while (i < out_len - 1 && i < sizeof(state->bind_ip) && state->bind_ip[i]) {
            out[i] = state->bind_ip[i]; i++;
        }
        out[i] = 0;
        return;
    }
    if (state->domain == AF_INET6) {
        out[0] = ':'; out[1] = ':'; out[2] = 0;
    } else {
        const char *z = "0.0.0.0";
        size_t i = 0;
        while (i < out_len - 1 && z[i]) { out[i] = z[i]; i++; }
        out[i] = 0;
    }
}

/* dup3 the manager fd over the tracee's fd, then close the source
 * (original manager fd). On success, the tracee's fd now points
 * at the unix socketpair end fdproxy reads/writes. */
static long replace_fd_with_manager(int fd, int manager_fd, int kind,
                                    struct tracked_fd state,
                                    const char *actual_bind_ip,
                                    uint16_t actual_bind_port) {
    state.proxied = 1;
    state.kind = kind;
    state.bound = 1;
    if (actual_bind_ip && actual_bind_ip[0]) {
        size_t n = 0;
        while (n < sizeof(state.bind_ip) - 1 && actual_bind_ip[n]) {
            state.bind_ip[n] = actual_bind_ip[n]; n++;
        }
        state.bind_ip[n] = 0;
    }
    if (actual_bind_port) state.bind_port = actual_bind_port;
    (void)uwg_state_store(fd, &state);

    long rc = uwg_passthrough_syscall3(SYS_dup3, manager_fd, fd, 0);
    if (rc < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, manager_fd);
        return rc;
    }
    (void)uwg_passthrough_syscall1(SYS_close, manager_fd);
    return 0;
}

/*
 * Public entry: TCP listener setup. Called from uwg_listen when
 * the fd is tunnel-managed.
 */
long uwg_start_tcp_listener(int fd) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (!state.active) return -9; /* -EBADF */

    char bind_ip[46];
    resolve_bind_text(&state, bind_ip, sizeof(bind_ip));
    uint16_t bind_port = state.bound ? (uint16_t)state.bind_port : 0;

    char line[256];
    int line_len = build_listen_line(line, sizeof(line), "tcp",
                                     bind_ip, bind_port,
                                     state.reuse_addr, state.reuse_port);
    if (line_len < 0) return line_len;

    int mgr = uwg_fdproxy_connect();
    if (mgr < 0) return mgr;

    if (uwg_fdproxy_write_request(mgr, line) < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }
    char reply[160];
    long rd = uwg_fdproxy_read_reply(mgr, reply, sizeof(reply));
    if (rd <= 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    char token[80];
    char actual_ip[46];
    uint16_t actual_port = 0;
    if (parse_listen_reply(reply, "OKLISTEN", token, sizeof(token),
                           actual_ip, sizeof(actual_ip), &actual_port) != 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    return replace_fd_with_manager(fd, mgr, KIND_TCP_LISTENER, state,
                                   actual_ip, actual_port);
}

/*
 * Public entry: UDP listener setup. Called lazily from msg_ops/
 * stream_ops when an unconnected UDP fd hits its first send/recv.
 */
long uwg_ensure_udp_listener(int fd) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (!state.active && !state.proxied) return -9; /* -EBADF */
    if (state.proxied && state.kind == KIND_UDP_LISTENER) return 0;

    char bind_ip[46];
    resolve_bind_text(&state, bind_ip, sizeof(bind_ip));
    uint16_t bind_port = state.bound ? (uint16_t)state.bind_port : 0;

    char line[256];
    int line_len = build_listen_line(line, sizeof(line), "udp",
                                     bind_ip, bind_port,
                                     state.reuse_addr, state.reuse_port);
    if (line_len < 0) return line_len;

    int mgr = uwg_fdproxy_connect();
    if (mgr < 0) return mgr;

    if (uwg_fdproxy_write_request(mgr, line) < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }
    char reply[160];
    long rd = uwg_fdproxy_read_reply(mgr, reply, sizeof(reply));
    if (rd <= 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    char actual_ip[46];
    uint16_t actual_port = 0;
    if (parse_listen_reply(reply, "OKUDP", NULL, 0,
                           actual_ip, sizeof(actual_ip), &actual_port) != 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    return replace_fd_with_manager(fd, mgr, KIND_UDP_LISTENER, state,
                                   actual_ip, actual_port);
}

/*
 * Public entry: managed accept. Reads an ACCEPT frame from the
 * listener fd, sends ATTACH on a new fdproxy connection, registers
 * the new fd in shared state.
 */
long uwg_managed_accept(int listener_fd, struct sockaddr *addr,
                        uint32_t *addrlen) {
    /* Read ACCEPT line from the listener (already a manager fd). */
    char line[256];
    long rd = uwg_fdproxy_read_reply(listener_fd, line, sizeof(line));
    if (rd <= 0) return -111;

    /* Format: "ACCEPT <token> <id> <ip> <port>" — parse with hand-
     * rolled tokenizer (no sscanf). */
    if (line[0] != 'A' || line[1] != 'C' || line[2] != 'C' ||
        line[3] != 'E' || line[4] != 'P' || line[5] != 'T') return -111;
    const char *p = line + 6;
    while (*p == ' ') p++;

    /* token */
    char token[80]; size_t ti = 0;
    while (*p && *p != ' ' && *p != '\n') {
        if (ti + 1 >= sizeof(token)) return -111;
        token[ti++] = *p++;
    }
    token[ti] = 0;
    while (*p == ' ') p++;

    /* id (uint64 decimal) — store as printable string for the
     * ATTACH line, no need to parse to integer. */
    char id_str[24]; size_t ii = 0;
    while (*p >= '0' && *p <= '9') {
        if (ii + 1 >= sizeof(id_str)) return -111;
        id_str[ii++] = *p++;
    }
    id_str[ii] = 0;
    while (*p == ' ') p++;

    /* ip */
    char ip[46]; size_t ipi = 0;
    while (*p && *p != ' ' && *p != '\n') {
        if (ipi + 1 >= sizeof(ip)) return -111;
        ip[ipi++] = *p++;
    }
    ip[ipi] = 0;
    while (*p == ' ') p++;

    /* port */
    unsigned int port_u = 0;
    while (*p >= '0' && *p <= '9') {
        port_u = port_u * 10 + (unsigned int)(*p - '0');
        if (port_u > 0xFFFFu) return -111;
        p++;
    }

    /* Build ATTACH line. */
    char attach[160];
    {
        size_t off = 0;
        const char *pre = "ATTACH ";
        while (*pre) attach[off++] = *pre++;
        for (size_t i = 0; i < ti; i++) attach[off++] = token[i];
        attach[off++] = ' ';
        for (size_t i = 0; i < ii; i++) attach[off++] = id_str[i];
        attach[off++] = '\n';
        attach[off] = 0;
    }

    /* Open a fresh fdproxy connection for the ATTACH. */
    int mgr = uwg_fdproxy_connect();
    if (mgr < 0) return mgr;
    if (uwg_fdproxy_write_request(mgr, attach) < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }
    char ok[64];
    long ok_rd = uwg_fdproxy_read_reply(mgr, ok, sizeof(ok));
    if (ok_rd < 2 || ok[0] != 'O' || ok[1] != 'K') {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -103; /* -ECONNABORTED */
    }

    /* Register the new fd in shared state. */
    struct tracked_fd s;
    memset(&s, 0, sizeof(s));
    s.active = 1;
    s.domain = AF_INET; /* TODO: support IPv6 ACCEPT lines */
    s.type = SOCK_STREAM;
    s.proxied = 1;
    s.kind = KIND_TCP_STREAM;
    s.remote_family = AF_INET;
    s.remote_port = (uint16_t)port_u;
    {
        size_t i = 0;
        while (i < sizeof(s.remote_ip) - 1 && ip[i]) {
            s.remote_ip[i] = ip[i]; i++;
        }
        s.remote_ip[i] = 0;
    }
    (void)uwg_state_store(mgr, &s);

    /* Fill caller-provided sockaddr. (Hand-rolled inet_pton-ish
     * for the IPv4 case; IPv6 left for Phase 1 followup. ) */
    if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_port = (uint16_t)((port_u >> 8) | ((port_u & 0xff) << 8));
        /* Parse dotted-quad IPv4. */
        unsigned int oct[4] = {0};
        int oi = 0; const char *q = ip;
        while (*q && oi < 4) {
            unsigned int v = 0;
            while (*q >= '0' && *q <= '9') { v = v * 10 + (*q - '0'); q++; }
            oct[oi++] = v;
            if (*q == '.') q++;
        }
        if (oi == 4) {
            sin->sin_addr.s_addr = (uint32_t)((oct[0]) | (oct[1] << 8) |
                                              (oct[2] << 16) | (oct[3] << 24));
        }
        *addrlen = sizeof(*sin);
    }

    return mgr;
}
