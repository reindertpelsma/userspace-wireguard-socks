/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Message-style I/O dispatchers: recvfrom / sendto / recvmsg / sendmsg /
 * recvmmsg / sendmmsg.
 *
 * For tunnel TCP-stream fds (the chromium hot path), these collapse
 * to a kernel passthrough — fdproxy treats the manager-side socket
 * as a raw byte stream so any libc message-style call works directly.
 *
 * For UDP-connected and UDP-listener fds, these speak the framed
 * datagram protocol (see preload/core/udp_frame.c):
 *   - sendmsg/sendto KIND_UDP_CONNECTED: gather iovecs into a stack
 *     buffer and uwg_write_packet (4-byte BE length prefix + raw bytes).
 *   - sendmsg/sendto KIND_UDP_LISTENER: must include a destination;
 *     uwg_encode_udp_datagram tags the payload with sockaddr, then
 *     uwg_write_packet.
 *   - recvmsg/recvfrom KIND_UDP_CONNECTED: uwg_read_packet returns the
 *     raw bytes; we copy out (truncating to user buffer), and synthesize
 *     the source sockaddr from the saved remote_ip/remote_port.
 *   - recvmsg/recvfrom KIND_UDP_LISTENER: uwg_read_packet returns the
 *     tagged frame; uwg_decode_udp_datagram unpacks src + payload.
 *
 * MSG_DONTWAIT propagation is load-bearing here. The legacy ptrace
 * path's recvmsg failed to propagate this flag, causing chromium /
 * libuv / Go-netpoller apps to deadlock. v0.1.0-beta.46 fixed it on
 * the ptrace side; this layer re-applies the same logic at the
 * SIGSYS layer — for both the TCP-stream passthrough AND the framed
 * UDP recv, where a non-blocking read on the manager socket avoids
 * blocking our dispatcher when the tracee already gave up.
 */

#include <stddef.h>
#include "freestanding.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

#define UWG_MSG_DONTWAIT 0x40 /* matches kernel ABI */
#define UWG_MSG_CMSG_CLOEXEC 0x40000000
#define UWG_SOCK_TYPE_MASK 0xff

/* Bounce-buffer size for UDP framed I/O. Must match udp_frame.c.
 * Stack-allocated per call; the sigaltstack is 64K so this is fine. */
#define UWG_FRAME_MAX 16384

/* Forward decl from listener_ops.c */
long uwg_ensure_udp_listener(int fd);
/* Forward decl from addr_utils.c */
int uwg_addr_is_loopback(const struct sockaddr *addr);

static int is_icmp_state(const struct tracked_fd *state) {
    /* IPPROTO_ICMP = 1, IPPROTO_ICMPV6 = 58. */
    return state->protocol == 1 || state->protocol == 58;
}

static int is_dgram(const struct tracked_fd *state) {
    return (state->type & UWG_SOCK_TYPE_MASK) == 2 /* SOCK_DGRAM */;
}

/*
 * Lazy listener bootstrap for unconnected-UDP send/recv. Mirrors
 * legacy uwgpreload.c::ensure_udp_listener call sites:
 *   - sendto/sendmsg: when active && DGRAM && !proxied && !icmp,
 *     and the destination is non-loopback (loopback gets kernel
 *     passthrough so localhost services keep working).
 *   - recvfrom/recvmsg: when active && DGRAM && !proxied && bound &&
 *     !icmp (only bound sockets can sensibly recv).
 *
 * Returns 0 on success (state may have been mutated to KIND_UDP_LISTENER),
 * a negative -errno on failure, or 0 with state unchanged when no
 * bootstrap was needed.
 */
static long maybe_lazy_udp_listener_send(int fd, struct tracked_fd *state,
                                         const struct sockaddr *dest) {
    if (!state->active || state->proxied) return 0;
    if (!is_dgram(state) || is_icmp_state(state)) return 0;
    if (dest && uwg_addr_is_loopback(dest)) return 0;
    long rc = uwg_ensure_udp_listener(fd);
    if (rc < 0) return rc;
    *state = uwg_state_lookup(fd);
    return 0;
}

static long maybe_lazy_udp_listener_recv(int fd, struct tracked_fd *state) {
    if (!state->active || state->proxied) return 0;
    if (!is_dgram(state) || is_icmp_state(state)) return 0;
    if (!state->bound) return 0;
    long rc = uwg_ensure_udp_listener(fd);
    if (rc < 0) return rc;
    *state = uwg_state_lookup(fd);
    return 0;
}

static int recv_is_nonblock(const struct tracked_fd *state, int caller_flags) {
    if (caller_flags & UWG_MSG_DONTWAIT) return 1;
    if (state->saved_fl & 04000 /* O_NONBLOCK */) return 1;
    return 0;
}

/*
 * Helper: when the fd has O_NONBLOCK set on the tracee side, OR
 * MSG_DONTWAIT into the syscall flags so the kernel-side recv on
 * the manager socket also returns EAGAIN. Without this, the manager
 * socket (always blocking) would block our handler thread waiting
 * for data the tracee already gave up on. This is the v0.1.0-beta.46
 * recvmsg-MSG_DONTWAIT-propagation fix, re-applied here for the
 * SIGSYS path.
 */
static int effective_recv_flags(const struct tracked_fd *state, int caller_flags) {
    if (state->saved_fl & 04000 /* O_NONBLOCK */) {
        return caller_flags | UWG_MSG_DONTWAIT;
    }
    return caller_flags;
}

static size_t iov_total(const struct iovec *iov, int iovcnt) {
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
    return total;
}

static size_t iov_gather(const struct iovec *iov, int iovcnt,
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

static size_t iov_scatter(const struct iovec *iov, int iovcnt,
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

/*
 * Receive one datagram from `fd` into `iov`/`iovcnt`. Honors
 * O_NONBLOCK / MSG_DONTWAIT via `eff_nonblock`. Sets src/slen if
 * requested. Returns bytes copied to iov on success, or -errno.
 *
 * Flow:
 *   1. Stack-alloc UWG_FRAME_MAX bounce.
 *   2. uwg_read_packet[_nonblock] into bounce.
 *   3. KIND_UDP_CONNECTED: bounce IS the payload — synthesize src
 *      from saved remote_ip/remote_port.
 *      KIND_UDP_LISTENER: decode bounce → src + inner-payload-ptr.
 *   4. Scatter into iov (truncating to total iov capacity).
 */
static long udp_recv_fd(int fd, const struct tracked_fd *state, int kind,
                        int eff_nonblock,
                        const struct iovec *iov, int iovcnt,
                        struct sockaddr *src, uint32_t *slen) {
    char tmp[UWG_FRAME_MAX];
    long n = eff_nonblock
                 ? uwg_read_packet_nonblock(fd, tmp, sizeof(tmp))
                 : uwg_read_packet(fd, tmp, sizeof(tmp));
    if (n < 0) return n;

    size_t cap = iov_total(iov, iovcnt);
    if (kind == KIND_UDP_CONNECTED) {
        /* tmp[0..n] is the payload. Fill src from saved peer. */
        if (src && slen) {
            int fam = state->remote_family ? state->remote_family : state->domain;
            uwg_addr_from_text(fam, state->remote_ip, state->remote_port, src, slen);
        }
        size_t copy = (size_t)n < cap ? (size_t)n : cap;
        return (long)iov_scatter(iov, iovcnt, tmp, copy);
    }
    /* KIND_UDP_LISTENER */
    const void *payload = NULL;
    size_t payload_len = 0;
    /* Decode source straight into user-provided sockaddr if it has
     * room; otherwise into a stack bounce, then truncate-copy. */
    struct sockaddr_in6 sa_full;
    uint32_t full_len = (uint32_t)sizeof(sa_full);
    long rc = uwg_decode_udp_datagram(tmp, (size_t)n,
                                      (struct sockaddr *)&sa_full, full_len,
                                      &payload, &payload_len);
    if (rc < 0) return rc;
    if (src && slen) {
        uint32_t actual = (sa_full.sin6_family == AF_INET)
                              ? (uint32_t)sizeof(struct sockaddr_in)
                              : (uint32_t)sizeof(struct sockaddr_in6);
        uint32_t copy = *slen < actual ? *slen : actual;
        memcpy(src, &sa_full, copy);
        *slen = actual;
    }
    size_t copy = payload_len < cap ? payload_len : cap;
    return (long)iov_scatter(iov, iovcnt, payload, copy);
}

/*
 * Send one datagram from `iov`/`iovcnt` to `dest` (KIND_UDP_LISTENER)
 * or to the connected peer (KIND_UDP_CONNECTED). Returns bytes sent
 * (== gathered iov total) on success or -errno.
 */
static long udp_send_fd(int fd, int kind,
                        const struct iovec *iov, int iovcnt,
                        const struct sockaddr *dest) {
    /* Refuse oversized: gather will hit UWG_FRAME_MAX. */
    char tmp[UWG_FRAME_MAX];

    if (kind == KIND_UDP_CONNECTED) {
        /* Sending with a non-NULL dest on a connected UDP socket is
         * EISCONN per Linux. */
        if (dest) return -106; /* -EISCONN */
        size_t cap = iov_total(iov, iovcnt);
        if (cap > sizeof(tmp)) return -90; /* -EMSGSIZE */
        size_t got = iov_gather(iov, iovcnt, tmp, sizeof(tmp));
        int rc = uwg_write_packet(fd, tmp, got);
        if (rc < 0) return rc;
        return (long)got;
    }
    /* KIND_UDP_LISTENER */
    if (!dest) return -89; /* -EDESTADDRREQ */
    /* Encode dest+payload into tmp via two-phase build:
     * 1. Gather iovec to a small buffer (raw payload).
     * 2. uwg_encode_udp_datagram into tmp.
     * Two stack buffers fit comfortably in 64K sigaltstack. */
    char raw[UWG_FRAME_MAX];
    size_t cap = iov_total(iov, iovcnt);
    if (cap > sizeof(raw)) return -90;
    size_t got = iov_gather(iov, iovcnt, raw, sizeof(raw));
    long enc = uwg_encode_udp_datagram(dest, raw, got, tmp, sizeof(tmp));
    if (enc < 0) return enc;
    int rc = uwg_write_packet(fd, tmp, (size_t)enc);
    if (rc < 0) return rc;
    return (long)got;
}

long uwg_recvfrom(int fd, void *buf, size_t len, int flags,
                  struct sockaddr *src, uint32_t *slen) {
    struct tracked_fd state = uwg_state_lookup(fd);

    /* MSG_CMSG_CLOEXEC and src-without-slen are awkward — punt for
     * Phase 1 (very rare in real apps). */
    if (flags & UWG_MSG_CMSG_CLOEXEC) return -38L;
    if (src && !slen) return -22; /* -EINVAL */

    long lz = maybe_lazy_udp_listener_recv(fd, &state);
    if (lz < 0) return lz;

    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        return udp_recv_fd(fd, &state, state.kind,
                           recv_is_nonblock(&state, flags),
                           &iov, 1, src, slen);
    }

    /* TCP-stream / non-tunnel: build msghdr and use recvmsg.
     * Zero the whole struct first — see uwg_sendto comment for the
     * musl-vs-kernel msghdr layout hazard (32-bit msg_iovlen + pad). */
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = src;
    msg.msg_namelen = src ? (slen ? *slen : 0) : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    int eff_flags = (state.proxied && state.kind == KIND_TCP_STREAM)
                        ? effective_recv_flags(&state, flags)
                        : flags;
    long rc = uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)&msg, eff_flags);
    if (rc >= 0 && src && slen) *slen = msg.msg_namelen;
    return rc;
}

long uwg_sendto(int fd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest, uint32_t dlen) {
    struct tracked_fd state = uwg_state_lookup(fd);

    long lz = maybe_lazy_udp_listener_send(fd, &state, dest);
    if (lz < 0) return lz;

    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        if (dest == NULL && dlen != 0) return -22;
        struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
        return udp_send_fd(fd, state.kind, &iov, 1, dest);
    }

    /* dest=NULL with nonzero dlen is the awkward case — punt. */
    if (dest == NULL && dlen != 0) return -22;

    /* IMPORTANT: zero the entire msghdr. musl declares msg_iovlen as
     * int (32-bit) with __pad1 after it on 64-bit little-endian; the
     * kernel reads msg_iovlen as __kernel_size_t (64-bit). If we
     * leave __pad1 uninitialized, the kernel sees garbage in the
     * high 32 bits of iovlen and rejects with -ENOBUFS (or similar).
     * Same hazard for msg_controllen / __pad2. Glibc's struct has
     * size_t fields directly so the bug is musl-only. */
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)dest;
    msg.msg_namelen = dest ? dlen : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    /* msg_control / msg_controllen / msg_flags / any libc padding
     * are already zeroed by the memset above. */

    return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)&msg, flags);
}

long uwg_recvmsg(int fd, struct msghdr *msg, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    long lz = maybe_lazy_udp_listener_recv(fd, &state);
    if (lz < 0) return lz;

    uwg_tracef("recvmsg fd=%d kind=%d proxied=%d flags=%x", fd, state.kind, state.proxied, flags);
    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        if (!msg) return -22;
        struct sockaddr *src = (struct sockaddr *)msg->msg_name;
        uint32_t slen = msg->msg_namelen;
        long rc = udp_recv_fd(fd, &state, state.kind,
                              recv_is_nonblock(&state, flags),
                              msg->msg_iov, (int)msg->msg_iovlen,
                              src, src ? &slen : 0);
        if (rc >= 0) {
            if (src) msg->msg_namelen = slen;
            msg->msg_controllen = 0;
            msg->msg_flags = 0;
        }
        return rc;
    }

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        int eff_flags = effective_recv_flags(&state, flags);
        return uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)msg, eff_flags);
    }
    return uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)msg, flags);
}

long uwg_sendmsg(int fd, const struct msghdr *msg, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (msg) {
        long lz = maybe_lazy_udp_listener_send(
            fd, &state, (const struct sockaddr *)msg->msg_name);
        if (lz < 0) return lz;
    }

    uwg_tracef("sendmsg fd=%d kind=%d proxied=%d flags=%x", fd, state.kind, state.proxied, flags);
    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        if (!msg) return -22;
        const struct sockaddr *dest = (const struct sockaddr *)msg->msg_name;
        return udp_send_fd(fd, state.kind,
                           msg->msg_iov, (int)msg->msg_iovlen, dest);
    }

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)msg, flags);
    }
    return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)msg, flags);
}

/* From recvmmsg(2): MSG_WAITFORONE = 0x10000 — return after first
 * datagram received, regardless of vlen. */
#define UWG_MSG_WAITFORONE 0x10000

/* Cap on the recv/sendmmsg vlen we'll actually process per call. The
 * Linux kernel itself caps recvmmsg/sendmmsg at UIO_MAXIOV (1024) but
 * our shim runs in userspace and a malicious or buggy caller passing
 * vlen=UINT_MAX would otherwise spin our loop UINT_MAX times against
 * proxied UDP fds. Match the kernel's cap so we never amplify what
 * the kernel would have done anyway, and short-circuit the rest of
 * the buffer. Real-world callers use vlen ≤ a few dozen. */
#define UWG_MMSG_VLEN_CAP 1024

long uwg_recvmmsg(int fd, struct mmsghdr *vec, unsigned int vlen,
                  int flags, struct timespec *to) {
    struct tracked_fd state = uwg_state_lookup(fd);

    long lz = maybe_lazy_udp_listener_recv(fd, &state);
    if (lz < 0) return lz;

    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        /* Drain up to vlen datagrams. Per recvmmsg(2): without
         * MSG_WAITFORONE, every recv inherits the fd's blocking mode
         * — the kernel waits for vlen datagrams (or `to` to expire,
         * which we don't track precisely; best-effort is fine for
         * Phase 1). With MSG_WAITFORONE, return as soon as one is
         * received. Stop on the first error and return either the
         * partial count or the -errno from the first recv. */
        if (!vec || vlen == 0) return -22;
        if (vlen > UWG_MMSG_VLEN_CAP) vlen = UWG_MMSG_VLEN_CAP;
        int caller_nonblock = recv_is_nonblock(&state, flags);
        int wait_for_one = (flags & UWG_MSG_WAITFORONE) != 0;
        unsigned int got = 0;
        for (unsigned int i = 0; i < vlen; i++) {
            int nb = caller_nonblock || (wait_for_one && i > 0);
            long rc = udp_recv_fd(fd, &state, state.kind, nb,
                                  vec[i].msg_hdr.msg_iov,
                                  (int)vec[i].msg_hdr.msg_iovlen,
                                  (struct sockaddr *)vec[i].msg_hdr.msg_name,
                                  vec[i].msg_hdr.msg_name
                                      ? &vec[i].msg_hdr.msg_namelen : 0);
            if (rc < 0) {
                if (got > 0) return (long)got;
                return rc;
            }
            vec[i].msg_len = (unsigned int)rc;
            vec[i].msg_hdr.msg_controllen = 0;
            vec[i].msg_hdr.msg_flags = 0;
            got++;
        }
        (void)to;
        return (long)got;
    }

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        int eff_flags = effective_recv_flags(&state, flags);
        return uwg_passthrough_syscall5(SYS_recvmmsg, fd, (long)vec,
                                        (long)vlen, eff_flags, (long)to);
    }
    return uwg_passthrough_syscall5(SYS_recvmmsg, fd, (long)vec,
                                    (long)vlen, flags, (long)to);
}

long uwg_sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (vec && vlen > 0) {
        const struct sockaddr *first_dest =
            (const struct sockaddr *)vec[0].msg_hdr.msg_name;
        long lz = maybe_lazy_udp_listener_send(fd, &state, first_dest);
        if (lz < 0) return lz;
    }

    if (state.proxied && (state.kind == KIND_UDP_CONNECTED ||
                          state.kind == KIND_UDP_LISTENER)) {
        if (!vec || vlen == 0) return -22;
        if (vlen > UWG_MMSG_VLEN_CAP) vlen = UWG_MMSG_VLEN_CAP;
        unsigned int sent = 0;
        for (unsigned int i = 0; i < vlen; i++) {
            const struct sockaddr *dest =
                (const struct sockaddr *)vec[i].msg_hdr.msg_name;
            long rc = udp_send_fd(fd, state.kind,
                                  vec[i].msg_hdr.msg_iov,
                                  (int)vec[i].msg_hdr.msg_iovlen,
                                  dest);
            if (rc < 0) {
                if (sent > 0) return (long)sent;
                return rc;
            }
            vec[i].msg_len = (unsigned int)rc;
            sent++;
        }
        return (long)sent;
    }

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        return uwg_passthrough_syscall4(SYS_sendmmsg, fd, (long)vec,
                                        (long)vlen, flags);
    }
    return uwg_passthrough_syscall4(SYS_sendmmsg, fd, (long)vec,
                                    (long)vlen, flags);
}
