/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * libc socket-syscall interposition layer. Each public libc symbol
 * gets a wrapper that calls the corresponding uwg_<op> dispatcher and
 * translates the freestanding (-errno on error, value on success)
 * convention into libc's (-1 + errno on error, value on success).
 *
 * Why the shim layer matters: without it, phase1.so requires
 * UWGS_TRACE_SECRET in the environment so the SIGSYS+seccomp filter
 * can install. With it, the .so works as a drop-in replacement for
 * the legacy preload/uwgpreload.c — apps using libc-routed syscalls
 * (almost everything but raw asm) hit the shim directly without
 * needing the kernel-level filter at all. The filter still installs
 * when UWGS_TRACE_SECRET is set, catching raw asm syscalls that
 * bypass the shim. So we get both layers of coverage.
 *
 * The shims are intentionally thin: argument forwarding, return-value
 * translation, errno set. No state lookup or fdproxy IPC happens
 * here — that all lives behind uwg_<op> in core/.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "../core/dispatch.h"

/* Translate a freestanding return (-errno on error, >=0 on success)
 * into the libc convention. Sets errno if rc < 0. */
static int errno_from(long rc) {
    if (rc < 0) {
        errno = (int)(-rc);
        return -1;
    }
    return (int)rc;
}

static ssize_t errno_from_ssize(long rc) {
    if (rc < 0) {
        errno = (int)(-rc);
        return -1;
    }
    return (ssize_t)rc;
}

int socket(int domain, int type, int protocol) {
    return errno_from(uwg_socket(domain, type, protocol));
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    return errno_from(uwg_socketpair(domain, type, protocol, sv));
}

int close(int fd) {
    return errno_from(uwg_close(fd));
}

int connect(int fd, const struct sockaddr *addr, socklen_t alen) {
    return errno_from(uwg_connect(fd, addr, (uint32_t)alen));
}

int bind(int fd, const struct sockaddr *addr, socklen_t alen) {
    return errno_from(uwg_bind(fd, addr, (uint32_t)alen));
}

int listen(int fd, int backlog) {
    return errno_from(uwg_listen(fd, backlog));
}

int accept(int fd, struct sockaddr *addr, socklen_t *alen) {
    uint32_t a = alen ? *alen : 0;
    long rc = uwg_accept(fd, addr, alen ? &a : NULL);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (alen) *alen = (socklen_t)a;
    return (int)rc;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *alen, int flags) {
    uint32_t a = alen ? *alen : 0;
    long rc = uwg_accept4(fd, addr, alen ? &a : NULL, flags);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (alen) *alen = (socklen_t)a;
    return (int)rc;
}

int setsockopt(int fd, int level, int optname, const void *val, socklen_t vlen) {
    return errno_from(uwg_setsockopt(fd, level, optname, val, (uint32_t)vlen));
}

int getsockopt(int fd, int level, int optname, void *val, socklen_t *vlen) {
    uint32_t v = vlen ? *vlen : 0;
    long rc = uwg_getsockopt(fd, level, optname, val, vlen ? &v : NULL);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (vlen) *vlen = (socklen_t)v;
    return (int)rc;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *alen) {
    uint32_t a = alen ? *alen : 0;
    long rc = uwg_getsockname(fd, addr, alen ? &a : NULL);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (alen) *alen = (socklen_t)a;
    return (int)rc;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *alen) {
    uint32_t a = alen ? *alen : 0;
    long rc = uwg_getpeername(fd, addr, alen ? &a : NULL);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (alen) *alen = (socklen_t)a;
    return (int)rc;
}

int dup(int fd) {
    return errno_from(uwg_dup(fd));
}

int dup2(int oldfd, int newfd) {
    return errno_from(uwg_dup2(oldfd, newfd));
}

int dup3(int oldfd, int newfd, int flags) {
    return errno_from(uwg_dup3(oldfd, newfd, flags));
}

/* fcntl is variadic in libc; we accept the third arg as long which
 * covers both int and pointer cases on the architectures we target. */
int fcntl(int fd, int cmd, ...) {
    long arg = 0;
    /* Read the optional 3rd arg via __builtin_va_*. cmd determines
     * whether the arg is meaningful; the variadic ABI guarantees
     * reading is safe even if absent (the slot may contain garbage
     * but we only forward — fcntl(2) ignores the arg for cmds that
     * don't need it). */
    __builtin_va_list ap;
    __builtin_va_start(ap, cmd);
    arg = __builtin_va_arg(ap, long);
    __builtin_va_end(ap);
    return errno_from(uwg_fcntl(fd, cmd, arg));
}

int shutdown(int fd, int how) {
    return errno_from(uwg_shutdown(fd, how));
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src, socklen_t *slen) {
    uint32_t s = slen ? *slen : 0;
    long rc = uwg_recvfrom(fd, buf, len, flags, src, slen ? &s : NULL);
    if (rc < 0) { errno = (int)(-rc); return -1; }
    if (slen) *slen = (socklen_t)s;
    return (ssize_t)rc;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    return errno_from_ssize(uwg_recvfrom(fd, buf, len, flags, NULL, NULL));
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest, socklen_t dlen) {
    return errno_from_ssize(uwg_sendto(fd, buf, len, flags, dest,
                                       (uint32_t)dlen));
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    return errno_from_ssize(uwg_sendto(fd, buf, len, flags, NULL, 0));
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    return errno_from_ssize(uwg_recvmsg(fd, msg, flags));
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    return errno_from_ssize(uwg_sendmsg(fd, msg, flags));
}

/* glibc declares the flags arg of recvmmsg/sendmmsg as `int`; musl
 * declares it as `unsigned int`. The kernel ABI accepts both — the
 * value is a bitfield. Match each libc to avoid "conflicting types"
 * errors in the shim. */
#ifdef __GLIBC__
int recvmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags,
             struct timespec *to) {
    return errno_from(uwg_recvmmsg(fd, vec, vlen, flags, to));
}

int sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags) {
    return errno_from(uwg_sendmmsg(fd, vec, vlen, flags));
}
#else
int recvmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, unsigned int flags,
             struct timespec *to) {
    return errno_from(uwg_recvmmsg(fd, vec, vlen, (int)flags, to));
}

int sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, unsigned int flags) {
    return errno_from(uwg_sendmmsg(fd, vec, vlen, (int)flags));
}
#endif

ssize_t read(int fd, void *buf, size_t n) {
    return errno_from_ssize(uwg_read(fd, buf, n));
}

ssize_t write(int fd, const void *buf, size_t n) {
    return errno_from_ssize(uwg_write(fd, buf, n));
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    return errno_from_ssize(uwg_readv(fd, iov, iovcnt));
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    return errno_from_ssize(uwg_writev(fd, iov, iovcnt));
}

ssize_t pread(int fd, void *buf, size_t n, off_t off) {
    return errno_from_ssize(uwg_pread(fd, buf, n, (int64_t)off));
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    return errno_from_ssize(uwg_pwrite(fd, buf, n, (int64_t)off));
}
