/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Core dispatch table — the boundary the SIGSYS handler and the
 * libc shim both call into. Every function:
 *
 *   - Returns >= 0 on success.
 *   - Returns -errno on failure.
 *   - Never touches global errno (TLS-unsafe in signal context).
 *   - Is async-signal-safe.
 *   - Looks up the fd in shared_state and decides:
 *       (a) tunnel fd → does the work (may IPC fdproxy via raw
 *           uwg_syscall* on the unix socket /tmp/uwgfdproxy.sock).
 *       (b) non-tunnel fd, or fast path (TCP-stream read/write on
 *           a managed-but-stream fd) → re-issue the real syscall
 *           with bypass-secret in arg6, return result.
 *
 * For Phase 1 these are STUBS returning -ENOSYS so the SIGSYS path
 * can be exercised end-to-end (handler invoked → dispatch returns
 * -ENOSYS → tracee sees -ENOSYS in rax). Phase 1's later commits
 * mechanically lift implementations from the existing
 * uwgpreload.c into the corresponding _ops.c files.
 */

#ifndef UWG_PRELOAD_CORE_DISPATCH_H
#define UWG_PRELOAD_CORE_DISPATCH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Forward declares — the .so build pulls full struct definitions in
 * via <sys/socket.h> etc.; the static build will provide its own
 * minimal versions in Phase 2. */
struct sockaddr;
struct msghdr;
struct mmsghdr;
struct iovec;
struct timespec;

/*
 * The single dispatcher entry. Called by:
 *   - uwg_sigsys_handler (after decoding ucontext)
 *   - shim_libc/syscall_shim.c (libc's `long syscall(long nr, ...)`)
 *
 * Returns:
 *   - whatever the matched uwg_* function returned, OR
 *   - -ENOSYS if no matching handler exists.
 */
long uwg_dispatch(long nr, long a1, long a2, long a3,
                  long a4, long a5, long a6);

/* Per-syscall handlers — called by both the dispatcher and (eventually)
 * directly from the libc shim. Each takes the same args its kernel
 * counterpart does. */

long uwg_socket    (int domain, int type, int protocol);
long uwg_socketpair(int domain, int type, int protocol, int sv[2]);
long uwg_close     (int fd);
long uwg_connect   (int fd, const struct sockaddr *addr, uint32_t alen);
long uwg_bind      (int fd, const struct sockaddr *addr, uint32_t alen);
long uwg_listen    (int fd, int backlog);
long uwg_accept    (int fd, struct sockaddr *addr, uint32_t *alen);
long uwg_accept4   (int fd, struct sockaddr *addr, uint32_t *alen, int flags);
long uwg_setsockopt(int fd, int level, int optname, const void *val, uint32_t vlen);
long uwg_getsockopt(int fd, int level, int optname, void *val, uint32_t *vlen);
long uwg_getsockname(int fd, struct sockaddr *addr, uint32_t *alen);
long uwg_getpeername(int fd, struct sockaddr *addr, uint32_t *alen);
long uwg_dup       (int fd);
long uwg_dup2      (int oldfd, int newfd);
long uwg_dup3      (int oldfd, int newfd, int flags);
long uwg_fcntl     (int fd, int cmd, long arg);
long uwg_shutdown  (int fd, int how);

long uwg_recvfrom  (int fd, void *buf, size_t len, int flags,
                    struct sockaddr *src, uint32_t *slen);
long uwg_sendto    (int fd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest, uint32_t dlen);
long uwg_recvmsg   (int fd, struct msghdr *msg, int flags);
long uwg_sendmsg   (int fd, const struct msghdr *msg, int flags);
long uwg_recvmmsg  (int fd, struct mmsghdr *vec, unsigned int vlen,
                    int flags, struct timespec *to);
long uwg_sendmmsg  (int fd, struct mmsghdr *vec, unsigned int vlen, int flags);

long uwg_read      (int fd, void *buf, size_t n);
long uwg_write     (int fd, const void *buf, size_t n);
long uwg_readv     (int fd, const struct iovec *iov, int iovcnt);
long uwg_writev    (int fd, const struct iovec *iov, int iovcnt);
long uwg_pread     (int fd, void *buf, size_t n, int64_t off);
long uwg_pwrite    (int fd, const void *buf, size_t n, int64_t off);

/*
 * Stats / introspection — used by tests and by the soak harness to
 * confirm the SIGSYS path is being reached. Async-signal-safe; uses
 * relaxed atomics.
 */
void uwg_sigsys_stats(uint64_t *calls, uint64_t *unhandled);

/*
 * Init entry — shared between the .so constructor and the static
 * binary's __uwg_init bootstrap.
 *
 * Order (load-bearing):
 *   1. parse env (UWGS_TRACE_SECRET, UWGS_FDPROXY)
 *   2. mmap shared state
 *   3. preallocate per-thread arenas (called per thread, see below)
 *   4. install sigaltstack (per thread)
 *   5. install SIGSYS handler (process-wide via rt_sigaction)
 *   6. PR_SET_NO_NEW_PRIVS
 *   7. install seccomp filter
 *
 * Returns 0 on success or -errno. On error, the process should
 * fail closed (the seccomp filter wasn't installed; the wrapper
 * isn't doing its job and the tracee would silently leak traffic).
 */
int uwg_core_init(void);

/* Called per thread that will issue trapped syscalls. Idempotent. */
int uwg_core_init_thread(void);

/* Helpers exposed for tests — see seccomp.c for definitions. */
int uwg_install_seccomp_filter(uint64_t bypass_secret);
int uwg_install_sigsys_handler(void);
const int *uwg_seccomp_trapped_list(size_t *n);
const int *uwg_seccomp_traced_list(size_t *n);

/* Shared state operations — see shared_state.c. */
struct tracked_fd; /* defined in preload/shared_state.h */
int uwg_state_init(void);
struct tracked_fd uwg_state_lookup(int fd);
int uwg_state_store(int fd, const struct tracked_fd *state);
void uwg_state_clear(int fd);
uint64_t uwg_state_secret(void);

/* fdproxy unix-socket protocol — see fdproxy_sock.c. */
void uwg_fdproxy_init(void);
int  uwg_fdproxy_connect(void);
int  uwg_fdproxy_request(const char *line, char *reply, size_t reply_len);
int  uwg_fdproxy_write_request(int fd, const char *line);
long uwg_fdproxy_read_reply(int fd, char *reply, size_t reply_len);

/* UDP datagram framing — see udp_frame.c.
 * uwg_write_packet returns 0 on success or -errno.
 * uwg_read_packet[_nonblock] returns the byte count read into out
 * (0..out_max) on success, -errno on failure (-EAGAIN if nonblock
 * and nothing is queued).
 * uwg_encode_udp_datagram returns total encoded length on success
 * or -errno on failure.
 * uwg_decode_udp_datagram returns 0 on success and writes a pointer
 * INTO `frame` plus the payload length to *payload / *payload_len.
 */
int  uwg_write_packet(int fd, const void *buf, size_t len);
long uwg_read_packet(int fd, void *out, size_t out_max);
long uwg_read_packet_nonblock(int fd, void *out, size_t out_max);
long uwg_encode_udp_datagram(const struct sockaddr *dest,
                             const void *payload, size_t payload_len,
                             void *out, size_t out_max);
long uwg_decode_udp_datagram(const void *frame, size_t frame_len,
                             struct sockaddr *src, size_t src_len,
                             const void **payload, size_t *payload_len);

/* Build a sockaddr from text-form IP + host-order port. See
 * addr_utils.c. *sa_len becomes the FULL constructed-sockaddr size
 * on return; the caller can detect truncation by comparing it to
 * the original buffer length. */
int uwg_addr_from_text(int family, const char *ip, uint16_t port,
                       struct sockaddr *sa, uint32_t *sa_len);

/* Optional per-call trace log. See trace.c. Active when
 * UWGS_PRELOAD_TRACE=/path/to/log is set; otherwise no-op. */
void uwg_tracef(const char *fmt, ...);

/* DNS-on-:53 forcing. See dns_force.c.
 * uwg_should_force_dns53 returns 1 if connect() to addr should be
 * diverted through fdproxy's DNS endpoint per UWGS_DNS_MODE.
 * uwg_force_dns_fd opens that endpoint and dup3s it over `fd`. */
int  uwg_addr_is_loopback(const struct sockaddr *addr);
int  uwg_should_force_dns53(const struct sockaddr *addr);
long uwg_force_dns_fd(int fd, int sock_type);

#endif /* UWG_PRELOAD_CORE_DISPATCH_H */
