/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * UDP datagram framing over the manager-stream socket.
 *
 * Wire format must match `internal/fdproxy/fdproxy.go`'s
 * readLocalPacket / writeLocalPacket and `internal/socketproto`'s
 * Encode/DecodeUDPDatagram. Any divergence here breaks fdproxy IPC.
 *
 * Per-datagram local frame (fdproxy ↔ preload over the unix socket):
 *     [4 bytes big-endian length] [payload bytes]
 *
 * For UNCONNECTED UDP (KIND_UDP_LISTENER), the payload itself is a
 * socketproto.UDPDatagram encoding:
 *     [1 byte family code (4 or 6)]
 *     [1 byte zero padding]
 *     [2 bytes big-endian port]
 *     [4 or 16 bytes IP]
 *     [actual datagram payload]
 *
 * For CONNECTED UDP (KIND_UDP_CONNECTED), the framed payload is the
 * raw UDP payload bytes — no sockaddr prefix; the connection peer is
 * implicit.
 *
 * Async-signal-safe — uses pure inline-asm syscalls, no malloc, and
 * a stack-allocated bounce buffer sized to UWG_PACKET_MAX. The 16K
 * default is plenty for typical UDP traffic and well below the
 * sigaltstack size (64K) we allocate per thread.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#include "syscall.h"
#include "dispatch.h"

#define UWG_PACKET_MAX 16384

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) {
        long w = uwg_passthrough_syscall3(SYS_write, fd, (long)p, (long)n);
        if (w < 0) {
            if (w == -4 /* EINTR */) continue;
            return (int)w;
        }
        if (w == 0) return -32; /* -EPIPE */
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t n) {
    char *p = (char *)buf;
    while (n) {
        long r = uwg_passthrough_syscall3(SYS_read, fd, (long)p, (long)n);
        if (r < 0) {
            if (r == -4) continue;
            return (int)r;
        }
        if (r == 0) return -104; /* -ECONNRESET */
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* Write a length-prefixed packet to the manager fd. Returns 0 on
 * success or -errno. */
int uwg_write_packet(int fd, const void *buf, size_t len) {
    if (len > UWG_PACKET_MAX) return -90; /* -EMSGSIZE */
    uint32_t n_be = (uint32_t)((len & 0xff) << 24 | ((len >> 8) & 0xff) << 16 |
                                ((len >> 16) & 0xff) << 8 | ((len >> 24) & 0xff));
    /* The above is htonl; do it inline to avoid pulling htonl
     * (which on some libc is a function call — we want freestanding). */
    int rc = write_all(fd, &n_be, sizeof(n_be));
    if (rc < 0) return rc;
    if (len == 0) return 0;
    return write_all(fd, buf, len);
}

/* Read one length-prefixed packet into `out` (caller-provided buffer).
 * Returns the number of payload bytes read on success, or -errno.
 * If the payload exceeds out_max, returns -ENOBUFS. */
long uwg_read_packet(int fd, void *out, size_t out_max) {
    uint32_t n_be;
    int rc = read_all(fd, &n_be, sizeof(n_be));
    if (rc < 0) return rc;
    uint32_t n = ((n_be & 0xff) << 24 | ((n_be >> 8) & 0xff) << 16 |
                  ((n_be >> 16) & 0xff) << 8 | ((n_be >> 24) & 0xff));
    if (n > UWG_PACKET_MAX) return -90;
    if ((size_t)n > out_max) {
        /* Drain — we don't have space. Return -ENOBUFS so caller
         * knows the packet was lost. */
        char drain[1024];
        size_t left = n;
        while (left) {
            size_t want = left > sizeof(drain) ? sizeof(drain) : left;
            int dr = read_all(fd, drain, want);
            if (dr < 0) return dr;
            left -= want;
        }
        return -105; /* -ENOBUFS */
    }
    if (n == 0) return 0;
    rc = read_all(fd, out, n);
    if (rc < 0) return rc;
    return (long)n;
}

/* Non-blocking variant for MSG_DONTWAIT semantics: poll first,
 * return -EAGAIN if nothing is queued.
 *
 * arm64 dropped SYS_poll from its syscall table in favor of
 * SYS_ppoll; route through ppoll there with a zero timespec to get
 * the same "non-blocking probe" semantics. x86_64 keeps SYS_poll. */
long uwg_read_packet_nonblock(int fd, void *out, size_t out_max) {
    struct {
        int fd;
        short events;
        short revents;
    } pfd = { fd, 1 /* POLLIN */, 0 };
#ifdef SYS_poll
    long rc = uwg_passthrough_syscall3(SYS_poll, (long)&pfd, 1, 0);
#else
    /* ppoll(&pfd, 1, &zero, NULL) — zero timespec means "no wait". */
    struct { long tv_sec; long tv_nsec; } ts = { 0, 0 };
    long rc = uwg_passthrough_syscall5(SYS_ppoll, (long)&pfd, 1,
                                       (long)&ts, 0, 0);
#endif
    if (rc < 0) return rc;
    if (rc == 0) return -11; /* -EAGAIN */
    if (!(pfd.revents & 1 /* POLLIN */)) return -11;
    return uwg_read_packet(fd, out, out_max);
}

/*
 * encode_udp_datagram for unconnected UDP: prepends a tagged
 * sockaddr to the payload.
 *   [1 byte family-code (4 or 6)]
 *   [1 byte zero padding]
 *   [2 bytes big-endian port]
 *   [4 bytes IPv4 OR 16 bytes IPv6]
 *   [payload bytes]
 *
 * Header layout matches socketproto.EncodeUDPDatagram so the bytes
 * round-trip cleanly through fdproxy. Writes to `out` (caller-
 * allocated, must have at least 4 + (4 or 16) + payload_len bytes).
 * Returns total encoded length on success, -errno on failure.
 */
long uwg_encode_udp_datagram(const struct sockaddr *dest,
                             const void *payload, size_t payload_len,
                             void *out, size_t out_max) {
    if (!dest || !out) return -22;
    uint8_t *p = (uint8_t *)out;

    if (dest->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)dest;
        size_t total = 4 + 4 + payload_len;
        if (total > out_max) return -75; /* -EOVERFLOW */
        p[0] = 4;
        p[1] = 0;
        /* sin_port is in network byte order already. Copy big-endian
         * straight through. */
        uint16_t pn = sin->sin_port;
        p[2] = (uint8_t)(pn & 0xff);
        p[3] = (uint8_t)((pn >> 8) & 0xff);
        memcpy(p + 4, &sin->sin_addr.s_addr, 4);
        if (payload_len) memcpy(p + 8, payload, payload_len);
        return (long)total;
    }
    if (dest->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)dest;
        size_t total = 4 + 16 + payload_len;
        if (total > out_max) return -75;
        p[0] = 6;
        p[1] = 0;
        uint16_t pn = sin6->sin6_port;
        p[2] = (uint8_t)(pn & 0xff);
        p[3] = (uint8_t)((pn >> 8) & 0xff);
        memcpy(p + 4, sin6->sin6_addr.s6_addr, 16);
        if (payload_len) memcpy(p + 20, payload, payload_len);
        return (long)total;
    }
    return -22;
}

/* decode_udp_datagram: complement of encode. Parses the tagged
 * sockaddr prefix from a frame and returns a pointer to the payload
 * within `frame` (no copy). */
long uwg_decode_udp_datagram(const void *frame, size_t frame_len,
                             struct sockaddr *src, size_t src_len,
                             const void **payload, size_t *payload_len) {
    const uint8_t *p = (const uint8_t *)frame;
    if (frame_len < 4) return -22;

    uint8_t family = p[0];
    /* port_net is in network byte order on the wire. */
    uint16_t port_net = (uint16_t)((uint16_t)p[3] << 8 | (uint16_t)p[2]);

    if (family == 4) {
        if (frame_len < 8) return -22;
        if (src && src_len >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src;
            memset(sin, 0, sizeof(*sin));
            sin->sin_family = AF_INET;
            sin->sin_port = port_net;
            memcpy(&sin->sin_addr.s_addr, p + 4, 4);
        }
        if (payload) *payload = p + 8;
        if (payload_len) *payload_len = frame_len - 8;
        return 0;
    }
    if (family == 6) {
        if (frame_len < 20) return -22;
        if (src && src_len >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src;
            memset(sin6, 0, sizeof(*sin6));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = port_net;
            memcpy(sin6->sin6_addr.s6_addr, p + 4, 16);
        }
        if (payload) *payload = p + 20;
        if (payload_len) *payload_len = frame_len - 20;
        return 0;
    }
    return -22;
}
