/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Raw protocol to fdproxy via /tmp/uwgfdproxy.sock (or whatever
 * UWGS_FDPROXY points at). Pure inline-asm syscalls, async-signal-
 * safe. NO libc.
 *
 * The protocol is a simple newline-delimited text line per request:
 *   "CONNECT tcp 100.64.94.1 18090 0.0.0.0 0\n"
 * fdproxy replies with one of:
 *   "OK <bind-ip> <bind-port>\n"        (CONNECT)
 *   "OKLISTEN <token> <bind-ip> <port>\n" (LISTEN tcp)
 *   "OKUDP <bind-ip> <port>\n"          (LISTEN udp)
 *   "ERR <code> <message>\n"            (any failure — Phase 3 wrapper
 *                                        change; today fdproxy just
 *                                        closes the socket on failure)
 *   <empty / EOF>                       (today's failure mode)
 *
 * Each successful CONNECT/LISTEN keeps the socket open afterward —
 * the wrapper-side fd is the same fd, used as the data path (TCP
 * stream bytes flow through directly; UDP datagrams use the framed
 * protocol from preload's writeLocalPacket / readLocalPacket).
 *
 * For Phase 1 this file provides the connection + line-level send/
 * recv primitives. The data-plane framing for UDP is in
 * preload/core/msg_ops.c when those impls land.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>      /* struct timespec — pulled transitively via <sys/socket.h>
                          on glibc, but musl requires the explicit include. */
#include "freestanding.h"
#include "freestanding_runtime.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include "syscall.h"
#include "dispatch.h"

#define UWG_FDPROXY_DEFAULT_PATH "/tmp/uwgfdproxy.sock"

/* The manager-socket path is read once at init from UWGS_FDPROXY env.
 * After that it's read-only — no atomics needed for accesses. The
 * static buffer is sized to fit a maximum-length sun_path. */
static char uwg_fdproxy_path[108]; /* sizeof(sockaddr_un.sun_path) on Linux */
static int  uwg_fdproxy_path_set;

static size_t uwg_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

/* Initialize from environment. Idempotent. Called from init.c. */
void uwg_fdproxy_init(void) {
    if (uwg_fdproxy_path_set) return;

    const char *path = NULL;
    for (char **e = uwg_environ; e && *e; e++) {
        const char *s = *e;
        if (strncmp(s, "UWGS_FDPROXY=", 13) == 0) {
            path = s + 13;
            break;
        }
    }
    if (!path || !*path) path = UWG_FDPROXY_DEFAULT_PATH;

    size_t n = uwg_strlen(path);
    if (n >= sizeof(uwg_fdproxy_path)) n = sizeof(uwg_fdproxy_path) - 1;
    for (size_t i = 0; i < n; i++) uwg_fdproxy_path[i] = path[i];
    uwg_fdproxy_path[n] = 0;
    uwg_fdproxy_path_set = 1;
}

/*
 * Open a connected unix-stream socket to fdproxy. Returns fd on
 * success or -errno. Uses passthrough_syscall so the operations
 * skip the seccomp trap (these are core's own kernel calls, not
 * tracee-originated).
 *
 * Retries up to 50 times with a 10ms sleep between attempts on
 * ECONNREFUSED / ENOENT / ECONNRESET — fdproxy may still be
 * starting up the first time the wrapped process touches it.
 * (Same retry policy the existing uwgpreload.c uses.)
 */
int uwg_fdproxy_connect(void) {
    if (!uwg_fdproxy_path_set) uwg_fdproxy_init();

    /* Retry loop. struct timespec for nanosleep. */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 }; /* 10ms */

    for (int attempt = 0; attempt < 50; attempt++) {
        long fd = uwg_passthrough_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return (int)fd;

        struct sockaddr_un un;
        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        size_t n = uwg_strlen(uwg_fdproxy_path);
        if (n >= sizeof(un.sun_path)) n = sizeof(un.sun_path) - 1;
        for (size_t i = 0; i < n; i++) un.sun_path[i] = uwg_fdproxy_path[i];
        un.sun_path[n] = 0;

        long rc = uwg_passthrough_syscall3(SYS_connect, fd, (long)&un,
                                           (long)sizeof(un));
        if (rc == 0) return (int)fd;

        int err = (int)(-rc);
        (void)uwg_passthrough_syscall1(SYS_close, fd);

        if (err != 111 /* ECONNREFUSED */ &&
            err != 2   /* ENOENT */ &&
            err != 104 /* ECONNRESET */) {
            return -err;
        }
        if (attempt == 49) return -err;
        (void)uwg_passthrough_syscall2(SYS_nanosleep, (long)&ts, 0);
    }
    return -111; /* -ECONNREFUSED */
}

/*
 * Write all bytes to the fd. Loops on partial writes and EINTR.
 * Returns 0 on success or -errno.
 */
static int uwg_write_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) {
        long w = uwg_passthrough_syscall3(SYS_write, fd, (long)p, (long)n);
        if (w < 0) {
            if (w == -4 /* -EINTR */) continue;
            return (int)w;
        }
        if (w == 0) return -32; /* -EPIPE */
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/*
 * Read a line up to a newline OR until reply_len-1 bytes have been
 * read (then NUL-terminated). Returns the number of bytes read
 * (excluding the final NUL) on success or -errno.
 *
 * One byte at a time — slow but simple, and the wrapper protocol's
 * lines are short (< 256 bytes typically).
 */
static long uwg_read_line(int fd, char *out, size_t out_len) {
    if (out_len == 0) return -22; /* -EINVAL */
    size_t pos = 0;
    while (pos < out_len - 1) {
        char c;
        long r = uwg_passthrough_syscall3(SYS_read, fd, (long)&c, 1);
        if (r < 0) {
            if (r == -4) continue;
            return r;
        }
        if (r == 0) {
            /* EOF before newline — caller-defined. Some replies
             * (e.g. failure) close without a newline. Return what
             * we have so far. */
            break;
        }
        if (c == '\n') break;
        out[pos++] = c;
    }
    out[pos] = 0;
    return (long)pos;
}

/*
 * One-shot request/reply: connect, send `line`, read one reply line,
 * then close. Returns the bytes read on success (excluding terminator)
 * or -errno.
 *
 * Caller MUST size `reply` to at least 256 bytes for typical replies.
 *
 * NOTE: this is the simple closure pattern for control-plane requests
 * (CONNECT/LISTEN/ATTACH). For data-plane operations (sendmsg/recvmsg
 * etc.) the caller wants to KEEP the fd open after the request and
 * use it for subsequent data transfer. Use uwg_fdproxy_connect() +
 * uwg_fdproxy_write_request() + uwg_fdproxy_read_reply() directly
 * for that.
 */
int uwg_fdproxy_request(const char *line, char *reply, size_t reply_len) {
    int fd = uwg_fdproxy_connect();
    if (fd < 0) return fd;

    int wr = uwg_write_all(fd, line, uwg_strlen(line));
    if (wr < 0) {
        (void)uwg_passthrough_syscall1(SYS_close, fd);
        return wr;
    }

    long rd = uwg_read_line(fd, reply, reply_len);
    (void)uwg_passthrough_syscall1(SYS_close, fd);
    if (rd < 0) return (int)rd;
    if (rd == 0) return -71; /* -EPROTO — empty reply */
    return (int)rd;
}

/* Lower-level helpers exposed for data-plane callers that need to
 * keep the fdproxy socket open. */
int uwg_fdproxy_write_request(int fd, const char *line) {
    return uwg_write_all(fd, line, uwg_strlen(line));
}

long uwg_fdproxy_read_reply(int fd, char *reply, size_t reply_len) {
    return uwg_read_line(fd, reply, reply_len);
}
