/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Stream-style I/O dispatchers: read / write / readv / writev /
 * pread64 / pwrite64.
 *
 * The TCP-stream fast path:
 *   For a fd whose state.kind == KIND_TCP_STREAM, we do NOT translate
 *   anything — the fd is already a unix-stream socketpair end whose
 *   peer is fdproxy. Reads and writes flow as raw bytes through the
 *   socketpair and out the WireGuard tunnel without any per-syscall
 *   wrapper involvement. We just bypass-syscall to the kernel and
 *   the kernel does the right thing.
 *
 * The UDP slow path:
 *   For state.kind == KIND_UDP_CONNECTED, read/write translate to
 *   one length-prefixed datagram on the manager socket per call
 *   (uwg_read_packet / uwg_write_packet from udp_frame.c). Truncates
 *   per UDP semantics if the user buffer is smaller than the datagram.
 *   For state.kind == KIND_UDP_LISTENER, read returns the inner
 *   payload only (source address discarded — recvfrom is the right
 *   syscall to learn that). write returns -EDESTADDRREQ — sending
 *   on an unconnected UDP socket without a destination is meaningless.
 *
 * Non-tunnel fds: pure passthrough.
 */

#include <stddef.h>
#include "freestanding.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

#define UWG_FRAME_MAX 16384

static int udp_is_nonblock(const struct tracked_fd *state) {
    return (state->saved_fl & 04000 /* O_NONBLOCK */) ? 1 : 0;
}

static long udp_read_into(int fd, const struct tracked_fd *state,
                          int kind, void *buf, size_t n) {
    char tmp[UWG_FRAME_MAX];
    int nb = udp_is_nonblock(state);
    long rc = nb ? uwg_read_packet_nonblock(fd, tmp, sizeof(tmp))
                 : uwg_read_packet(fd, tmp, sizeof(tmp));
    if (rc < 0) return rc;
    const void *payload = tmp;
    size_t payload_len = (size_t)rc;
    if (kind == KIND_UDP_LISTENER) {
        long dec = uwg_decode_udp_datagram(tmp, (size_t)rc, NULL, 0,
                                           &payload, &payload_len);
        if (dec < 0) return dec;
    }
    size_t copy = payload_len < n ? payload_len : n;
    if (copy && buf) memcpy(buf, payload, copy);
    return (long)copy;
}

static long udp_write_from(int fd, int kind, const void *buf, size_t n) {
    if (kind == KIND_UDP_LISTENER) return -89; /* -EDESTADDRREQ */
    /* KIND_UDP_CONNECTED: framed write of raw payload. */
    if (n > UWG_FRAME_MAX) return -90; /* -EMSGSIZE */
    int rc = uwg_write_packet(fd, buf, n);
    if (rc < 0) return rc;
    return (long)n;
}

static size_t iov_total_local(const struct iovec *iov, int iovcnt) {
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
    return total;
}

static size_t iov_gather_local(const struct iovec *iov, int iovcnt,
                               void *out, size_t out_max) {
    char *dst = (char *)out;
    size_t off = 0;
    for (int i = 0; i < iovcnt && off < out_max; i++) {
        size_t copy = iov[i].iov_len;
        if (copy > out_max - off) copy = out_max - off;
        if (copy) memcpy(dst + off, iov[i].iov_base, copy);
        off += copy;
    }
    return off;
}

static size_t iov_scatter_local(const struct iovec *iov, int iovcnt,
                                const void *in, size_t in_len) {
    const char *src = (const char *)in;
    size_t off = 0;
    for (int i = 0; i < iovcnt && off < in_len; i++) {
        size_t copy = iov[i].iov_len;
        if (copy > in_len - off) copy = in_len - off;
        if (copy) memcpy(iov[i].iov_base, src + off, copy);
        off += copy;
    }
    return off;
}

long uwg_read(int fd, void *buf, size_t n) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        long rc = udp_read_into(fd, &state, state.kind, buf, n);
        uwg_tracef("read fd=%d kind=%d n=%ld -> %ld", fd, state.kind, (long)n, rc);
        return rc;
    }
    long rc = uwg_passthrough_syscall3(SYS_read, fd, (long)buf, (long)n);
    if (state.proxied || state.active) {
        uwg_tracef("read.passthrough fd=%d kind=%d n=%ld -> %ld",
                   fd, state.kind, (long)n, rc);
    }
    return rc;
}

long uwg_write(int fd, const void *buf, size_t n) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        long rc = udp_write_from(fd, state.kind, buf, n);
        uwg_tracef("write fd=%d kind=%d n=%ld -> %ld", fd, state.kind, (long)n, rc);
        return rc;
    }
    long rc = uwg_passthrough_syscall3(SYS_write, fd, (long)buf, (long)n);
    if (state.proxied || state.active) {
        uwg_tracef("write.passthrough fd=%d kind=%d n=%ld -> %ld",
                   fd, state.kind, (long)n, rc);
    }
    return rc;
}

long uwg_readv(int fd, const struct iovec *iov, int iovcnt) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        char tmp[UWG_FRAME_MAX];
        int nb = udp_is_nonblock(&state);
        long rc = nb ? uwg_read_packet_nonblock(fd, tmp, sizeof(tmp))
                     : uwg_read_packet(fd, tmp, sizeof(tmp));
        if (rc < 0) return rc;
        const void *payload = tmp;
        size_t payload_len = (size_t)rc;
        if (state.kind == KIND_UDP_LISTENER) {
            long dec = uwg_decode_udp_datagram(tmp, (size_t)rc, NULL, 0,
                                               &payload, &payload_len);
            if (dec < 0) return dec;
        }
        size_t cap = iov_total_local(iov, iovcnt);
        size_t copy = payload_len < cap ? payload_len : cap;
        return (long)iov_scatter_local(iov, iovcnt, payload, copy);
    }
    return uwg_passthrough_syscall3(SYS_readv, fd, (long)iov, (long)iovcnt);
}

long uwg_writev(int fd, const struct iovec *iov, int iovcnt) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind == KIND_UDP_LISTENER) {
        return -89; /* -EDESTADDRREQ */
    }
    if (state.proxied && state.kind == KIND_UDP_CONNECTED) {
        char tmp[UWG_FRAME_MAX];
        size_t cap = iov_total_local(iov, iovcnt);
        if (cap > sizeof(tmp)) return -90;
        size_t got = iov_gather_local(iov, iovcnt, tmp, sizeof(tmp));
        int rc = uwg_write_packet(fd, tmp, got);
        if (rc < 0) return rc;
        return (long)got;
    }
    return uwg_passthrough_syscall3(SYS_writev, fd, (long)iov, (long)iovcnt);
}

long uwg_pread(int fd, void *buf, size_t n, int64_t off) {
    /* pread doesn't make sense on a socket; kernel will reject with
     * -ESPIPE. Pass through. */
    return uwg_passthrough_syscall4(SYS_pread64, fd, (long)buf, (long)n,
                                    (long)off);
}

long uwg_pwrite(int fd, const void *buf, size_t n, int64_t off) {
    return uwg_passthrough_syscall4(SYS_pwrite64, fd, (long)buf, (long)n,
                                    (long)off);
}
