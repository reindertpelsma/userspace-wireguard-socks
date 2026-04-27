/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * DNS-on-:53 forcing.
 *
 * Apps like chromium use 8.8.8.8:53 / 1.1.1.1:53 directly (no
 * loopback) for DNS, often bypassing nss/resolv.conf. Without
 * intercepting these connects, those queries leak directly to the
 * host network instead of going through the WireGuard tunnel.
 *
 * Triggered from uwg_connect when:
 *   - dest port == 53
 *   - DNS mode allows redirection (full | loopback)
 *   - either the dest is loopback (loopback mode) or any :53 (full)
 *
 * The redirection: replace the user's fd with a manager-stream fd
 * that talks to fdproxy's DNS endpoint ("DNS 16\n" for TCP, "DNS 32\n"
 * for UDP — matching legacy uwgpreload.c). fdproxy bridges the
 * dispatch to the engine's resolver.
 *
 * Env vars (matching legacy semantics):
 *   UWGS_DNS_MODE=full       (default if unset/empty) — force any :53
 *   UWGS_DNS_MODE=loopback   — force only loopback :53
 *   UWGS_DNS_MODE=none       — disable DNS forcing entirely
 *   UWGS_DNS_MODE=libc       — passthrough (let libc do its thing)
 *   UWGS_DISABLE_LOOPBACK_DNS53=1 — even in loopback/full mode,
 *                                   skip loopback :53 forcing
 *
 * Async-signal-safe — no libc, only env walk + inline-asm syscalls.
 */

#include <stddef.h>
#include <stdint.h>
#include "freestanding.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

/* Walk environ for the named var. Returns NULL if not set. */
static const char *uwg_dns_getenv(const char *name) {
    extern char **environ;
    if (!environ) return NULL;
    size_t nlen = 0;
    while (name[nlen]) nlen++;
    for (char **e = environ; *e; e++) {
        const char *p = *e;
        size_t i = 0;
        while (i < nlen && p[i] && p[i] == name[i]) i++;
        if (i == nlen && p[i] == '=') return p + i + 1;
    }
    return NULL;
}

static int str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a++ != *b++) return 0;
    }
    return *a == 0 && *b == 0;
}

static int dns_mode_full(void) {
    const char *v = uwg_dns_getenv("UWGS_DNS_MODE");
    return !v || !*v || str_eq(v, "full");
}

static int dns_mode_none(void) {
    const char *v = uwg_dns_getenv("UWGS_DNS_MODE");
    return v && str_eq(v, "none");
}

static int dns_mode_libc(void) {
    const char *v = uwg_dns_getenv("UWGS_DNS_MODE");
    return v && str_eq(v, "libc");
}

static int loopback_dns_force_enabled(void) {
    const char *v = uwg_dns_getenv("UWGS_DISABLE_LOOPBACK_DNS53");
    return !v || !*v || !str_eq(v, "1");
}

static int sockaddr_is_dns53(const struct sockaddr *addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        /* sin_port is in network byte order; 53 BE = 0x3500. */
        return sin->sin_port == ((53 << 8) & 0xFFFF);
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        return sin6->sin6_port == ((53 << 8) & 0xFFFF);
    }
    return 0;
}

/*
 * Public entry: returns 1 if connect() to `addr` should be diverted
 * to the fdproxy DNS endpoint. Returns 0 otherwise.
 */
int uwg_should_force_dns53(const struct sockaddr *addr) {
    if (dns_mode_none() || dns_mode_libc()) return 0;
    if (!sockaddr_is_dns53(addr)) return 0;
    if (uwg_addr_is_loopback(addr)) return loopback_dns_force_enabled();
    return dns_mode_full();
}

/*
 * Open a fdproxy-managed DNS fd and dup3 it over `fd`. Updates shared
 * state to KIND_TCP_STREAM (sock_type=SOCK_STREAM) or KIND_UDP_CONNECTED
 * (sock_type=SOCK_DGRAM). Returns 0 on success or -errno.
 *
 * Wire format negotiated with fdproxy: "DNS 16\n" for TCP (16-bit
 * length-prefix per DNS-over-TCP RFC 1035), "DNS 32\n" for UDP
 * (32-bit length-prefix matching fdproxy's local framing for raw
 * datagrams).
 */
long uwg_force_dns_fd(int fd, int sock_type) {
    int mgr = uwg_fdproxy_connect();
    if (mgr < 0) return mgr;

    /* SOCK_STREAM = 1, SOCK_DGRAM = 2. The legacy convention is that
     * TCP DNS uses 16-bit prefix (RFC 1035) and UDP DNS uses 32-bit
     * prefix (fdproxy raw datagram framing). */
    const char *line = (sock_type == 1) ? "DNS 16\n" : "DNS 32\n";
    if (uwg_fdproxy_write_request(mgr, line) < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111; /* -ECONNREFUSED */
    }
    char reply[64];
    long rd = uwg_fdproxy_read_reply(mgr, reply, sizeof(reply));
    if (rd <= 0 || reply[0] != 'O' || reply[1] != 'K') {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return -111;
    }

    /* Replace the original fd with the manager fd (atomic close-and-
     * replace via dup3). */
    long rc = uwg_passthrough_syscall3(SYS_dup3, mgr, fd, 0);
    if (rc < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, mgr);
        return rc;
    }
    (void)uwg_passthrough_syscall1(SYS_close, mgr);

    /* Update shared state. */
    struct tracked_fd state = uwg_state_lookup(fd);
    state.active = 1;
    state.proxied = 1;
    state.kind = (sock_type == 2) ? KIND_UDP_CONNECTED : KIND_TCP_STREAM;
    state.hot_ready = 1;
    (void)uwg_state_store(fd, &state);
    return 0;
}
