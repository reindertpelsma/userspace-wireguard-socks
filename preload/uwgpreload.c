/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "dns/preload_dns.c"

/* DNS routing mode helpers */
static int dns_mode_full(void);
static int dns_mode_libc(void);
static int dns_mode_none(void);
static int loopback_dns_force_enabled(void);
static int sockaddr_is_dns53(const struct sockaddr *addr);
static int should_force_loopback_dns53(const struct sockaddr *addr);
static int should_force_any_dns53(const struct sockaddr *addr);
static int dns_udp_connect(void);
static int force_dns_stream_fd(int fd);
static int force_dns_dgram_fd(int fd);

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

#define MAX_TRACKED_FD 65536
#define MAX_PACKET (1u << 20)

enum managed_kind {
  KIND_NONE = 0,
  KIND_TCP_STREAM = 1,
  KIND_UDP_CONNECTED = 2,
  KIND_UDP_LISTENER = 3,
  KIND_TCP_LISTENER = 4,
};

struct tracked_fd {
  int active;
  int domain;
  int type;
  int protocol;
  int proxied;
  int kind;
  int bound;
  int bind_family;
  uint16_t bind_port;
  char bind_ip[INET6_ADDRSTRLEN];
  int remote_family;
  uint16_t remote_port;
  char remote_ip[INET6_ADDRSTRLEN];
  int saved_fl;
  int saved_fdfl;
};

static struct tracked_fd tracked[MAX_TRACKED_FD];
static int (*real_socket_fn)(int, int, int);
static int (*real_connect_fn)(int, const struct sockaddr *, socklen_t);
static int (*real_bind_fn)(int, const struct sockaddr *, socklen_t);
static int (*real_listen_fn)(int, int);
static int (*real_accept_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4_fn)(int, struct sockaddr *, socklen_t *, int);
static int (*real_close_fn)(int);
static ssize_t (*real_sendto_fn)(int, const void *, size_t, int,
                                 const struct sockaddr *, socklen_t);
static ssize_t (*real_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *,
                                   socklen_t *);
static ssize_t (*real_send_fn)(int, const void *, size_t, int);
static ssize_t (*real_recv_fn)(int, void *, size_t, int);
static ssize_t (*real_read_fn)(int, void *, size_t);
static ssize_t (*real_write_fn)(int, void *, size_t);
static int (*real_dup_fn)(int);
static int (*real_dup2_fn)(int, int);
static int (*real_dup3_fn)(int, int, int);
static int (*real_getsockname_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_getpeername_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_shutdown_fn)(int, int);
static int (*real_fcntl_fn)(int, int, ...);
static int (*real_getsockopt_fn)(int, int, int, void *, socklen_t *);
static int (*real_setsockopt_fn)(int, int, int, const void *, socklen_t);

static int fill_sockaddr_from_text(int family, const char *ip, uint16_t port,
                                   struct sockaddr *addr, socklen_t *addrlen);

static void init_real(void) {
  if (real_socket_fn)
    return;
  real_socket_fn = dlsym(RTLD_NEXT, "socket");
  real_connect_fn = dlsym(RTLD_NEXT, "connect");
  real_bind_fn = dlsym(RTLD_NEXT, "bind");
  real_listen_fn = dlsym(RTLD_NEXT, "listen");
  real_accept_fn = dlsym(RTLD_NEXT, "accept");
  real_accept4_fn = dlsym(RTLD_NEXT, "accept4");
  real_close_fn = dlsym(RTLD_NEXT, "close");
  real_sendto_fn = dlsym(RTLD_NEXT, "sendto");
  real_recvfrom_fn = dlsym(RTLD_NEXT, "recvfrom");
  real_send_fn = dlsym(RTLD_NEXT, "send");
  real_recv_fn = dlsym(RTLD_NEXT, "recv");
  real_write_fn = dlsym(RTLD_NEXT, "write");
  real_read_fn = dlsym(RTLD_NEXT, "read");
  real_dup_fn = dlsym(RTLD_NEXT, "dup");
  real_dup2_fn = dlsym(RTLD_NEXT, "dup2");
  real_dup3_fn = dlsym(RTLD_NEXT, "dup3");
  real_getsockname_fn = dlsym(RTLD_NEXT, "getsockname");
  real_getpeername_fn = dlsym(RTLD_NEXT, "getpeername");
  real_shutdown_fn = dlsym(RTLD_NEXT, "shutdown");
  real_fcntl_fn = dlsym(RTLD_NEXT, "fcntl");
  real_getsockopt_fn = dlsym(RTLD_NEXT, "getsockopt");
  real_setsockopt_fn = dlsym(RTLD_NEXT, "setsockopt");
}

static int debug_enabled(void) {
  const char *v = getenv("UWGS_PRELOAD_DEBUG");
  return v && *v && strcmp(v, "0") != 0;
}

static void debugf(const char *fmt, ...) {
  if (!debug_enabled())
    return;

  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n <= 0)
    return;

  size_t m = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
  if (real_write_fn) {
    (void)real_write_fn(2, buf, m);
    (void)real_write_fn(2, "\n", 1);
  } else {
    (void)syscall(SYS_write, 2, buf, m);
    (void)syscall(SYS_write, 2, "\n", 1);
  }
}
static int fd_ok(int fd) { return fd >= 0 && fd < MAX_TRACKED_FD; }

static int is_loopback_addr(const struct sockaddr *addr) {
  if (!addr)
    return 0;
  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    return (ntohl(in->sin_addr.s_addr) & 0xff000000u) == 0x7f000000u;
  }
  if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    static const unsigned char loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 1};
    return memcmp(&in6->sin6_addr, loopback, 16) == 0;
  }
  return 0;
}

static int sockaddr_to_ip_port(const struct sockaddr *addr, char *ip,
                               size_t ip_len, uint16_t *port, int *family) {
  if (!addr)
    return -1;
  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    if (!inet_ntop(AF_INET, &in->sin_addr, ip, ip_len))
      return -1;
    *port = ntohs(in->sin_port);
    *family = AF_INET;
    return 0;
  }
  if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    if (!inet_ntop(AF_INET6, &in6->sin6_addr, ip, ip_len))
      return -1;
    *port = ntohs(in6->sin6_port);
    *family = AF_INET6;
    return 0;
  }
  return -1;
}

static void copy_tracking(int dst, int src) {
  if (!fd_ok(dst))
    return;
  if (fd_ok(src)) {
    tracked[dst] = tracked[src];
  } else {
    memset(&tracked[dst], 0, sizeof(tracked[dst]));
  }
}

static const char *manager_path(void) {
  const char *path = getenv("UWGS_FDPROXY");
  if (!path || !*path)
    path = "/tmp/uwgfdproxy.sock";
  return path;
}

static int write_all(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len > 0) {
    ssize_t n = real_send_fn(fd, p, len, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = EPIPE;
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

static int read_all(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len > 0) {
    ssize_t n = real_recv_fn(fd, p, len, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

static int read_line(int fd, char *buf, size_t len) {
  if (len == 0) {
    errno = EINVAL;
    return -1;
  }
  size_t off = 0;
  while (off + 1 < len) {
    char c;
    ssize_t n = real_recv_fn(fd, &c, 1, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    buf[off++] = c;
    if (c == '\n')
      break;
  }
  buf[off] = 0;
  return 0;
}

static int manager_connect(void) {
  int fd = real_socket_fn(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  snprintf(un.sun_path, sizeof(un.sun_path), "%s", manager_path());
  if (real_connect_fn(fd, (struct sockaddr *)&un, sizeof(un)) != 0) {
    real_close_fn(fd);
    return -1;
  }
  return fd;
}

static int is_manager_fd(int fd) {
  struct sockaddr_un un;
  socklen_t len = sizeof(un);
  memset(&un, 0, sizeof(un));
  if (getpeername(fd, (struct sockaddr *)&un, &len) != 0)
    return 0;
  if (un.sun_family != AF_UNIX)
    return 0;
  return strcmp(un.sun_path, manager_path()) == 0;
}

int dns_tcp_connect(void) {
  if (dns_mode_none()) {
    debugf("dns_tcp_connect: disabled by mode none");
    errno = ENOSYS;
    return -1;
  }
  debugf("dns_tcp_connect: opening DNS16 manager socket");
  init_real();
  int fd = manager_connect();
  if (fd < 0)
    return -1;
  if (write_all(fd, "DNS 16\n", 7) != 0) {
    int e = errno;
    real_close_fn(fd);
    errno = e;
    return -1;
  }
  char ok[64];
  if (read_line(fd, ok, sizeof(ok)) != 0) {
    int e = errno;
    real_close_fn(fd);
    errno = e;
    return -1;
  }
  if (strncmp(ok, "OK", 2) != 0) {
    real_close_fn(fd);
    errno = ECONNREFUSED;
    return -1;
  }
  if (fd_ok(fd)) {
    tracked[fd].active = 1;
    tracked[fd].proxied = 1;
    tracked[fd].kind = KIND_TCP_STREAM;
    tracked[fd].domain = AF_UNIX;
    tracked[fd].type = SOCK_STREAM;
    tracked[fd].protocol = 0;
  }
  return fd;
}

static int dns_mode_full(void) {
  const char *v = getenv("UWGS_DNS_MODE");
  return !v || !*v || strcmp(v, "full") == 0;
}

static int dns_mode_libc(void) {
  const char *v = getenv("UWGS_DNS_MODE");
  return v && strcmp(v, "libc") == 0;
}

static int dns_mode_none(void) {
  const char *v = getenv("UWGS_DNS_MODE");
  return v && strcmp(v, "none") == 0;
}

static int loopback_dns_force_enabled(void) {
  const char *v = getenv("UWGS_DISABLE_LOOPBACK_DNS53");
  return !v || !*v || strcmp(v, "1") != 0;
}

static int sockaddr_is_dns53(const struct sockaddr *addr) {
  if (!addr)
    return 0;
  if (addr->sa_family == AF_INET) {
    return ntohs(((const struct sockaddr_in *)addr)->sin_port) == 53;
  }
  if (addr->sa_family == AF_INET6) {
    return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port) == 53;
  }
  return 0;
}

static int should_force_loopback_dns53(const struct sockaddr *addr) {
  return loopback_dns_force_enabled() && is_loopback_addr(addr) &&
         sockaddr_is_dns53(addr);
}

static int should_force_any_dns53(const struct sockaddr *addr) {
  if (dns_mode_none())
    return 0;
  if (should_force_loopback_dns53(addr))
    return 1;
  if (!dns_mode_full())
    return 0;
  return sockaddr_is_dns53(addr);
}

static int dns_udp_connect(void) {
  init_real();
  int fd = manager_connect();
  if (fd < 0)
    return -1;
  if (write_all(fd, "DNS 32\n", 7) != 0) {
    int e = errno;
    real_close_fn(fd);
    errno = e;
    return -1;
  }
  char ok[64];
  if (read_line(fd, ok, sizeof(ok)) != 0) {
    int e = errno;
    real_close_fn(fd);
    errno = e;
    return -1;
  }
  if (strncmp(ok, "OK", 2) != 0) {
    real_close_fn(fd);
    errno = ECONNREFUSED;
    return -1;
  }
  return fd;
}

static int force_dns_stream_fd(int fd) {
  int dfd = dns_tcp_connect();
  if (dfd < 0)
    return -1;
  if (dup2(dfd, fd) < 0) {
    int e = errno;
    real_close_fn(dfd);
    errno = e;
    return -1;
  }
  if (dfd != fd)
    real_close_fn(dfd);
  if (fd_ok(fd)) {
    tracked[fd].active = 1;
    tracked[fd].proxied = 1;
    tracked[fd].kind = KIND_TCP_STREAM;
  }
  return 0;
}

static int force_dns_dgram_fd(int fd) {
  int dfd = dns_udp_connect();
  if (dfd < 0)
    return -1;
  if (dup2(dfd, fd) < 0) {
    int e = errno;
    real_close_fn(dfd);
    errno = e;
    return -1;
  }
  if (dfd != fd)
    real_close_fn(dfd);
  if (fd_ok(fd)) {
    tracked[fd].active = 1;
    tracked[fd].proxied = 1;
    tracked[fd].kind = KIND_UDP_CONNECTED;
  }
  return 0;
}

static int manager_request(const char *line, char *reply, size_t reply_len) {
  int fd = manager_connect();
  if (fd < 0)
    return -1;
  if (write_all(fd, line, strlen(line)) != 0) {
    real_close_fn(fd);
    return -1;
  }
  if (read_line(fd, reply, reply_len) != 0) {
    real_close_fn(fd);
    return -1;
  }
  return fd;
}

static int replace_fd(int fd, int manager_fd, int kind) {
  int fl = real_fcntl_fn ? real_fcntl_fn(fd, F_GETFL) : -1;
  int fdfl = real_fcntl_fn ? real_fcntl_fn(fd, F_GETFD) : -1;

  if (real_dup2_fn(manager_fd, fd) < 0) {
    real_close_fn(manager_fd);
    return -1;
  }

  if (real_fcntl_fn) {
    if (fl >= 0)
      real_fcntl_fn(fd, F_SETFL, fl);
    if (fdfl >= 0)
      real_fcntl_fn(fd, F_SETFD, fdfl);
  }
  if (manager_fd != fd)
    real_close_fn(manager_fd);
  if (fd_ok(fd)) {
    tracked[fd].proxied = 1;
    tracked[fd].kind = kind;
    tracked[fd].saved_fl = fl;
    tracked[fd].saved_fdfl = fdfl;
  }
  return 0;
}

static int write_packet(int fd, const void *buf, size_t len) {
  if (len > MAX_PACKET) {
    errno = EMSGSIZE;
    return -1;
  }
  uint32_t n = htonl((uint32_t)len);
  if (write_all(fd, &n, sizeof(n)) != 0)
    return -1;
  if (len == 0)
    return 0;
  return write_all(fd, buf, len);
}

static ssize_t read_packet(int fd, void **out) {
  uint32_t n;
  if (read_all(fd, &n, sizeof(n)) != 0)
    return -1;
  n = ntohl(n);
  if (n > MAX_PACKET) {
    errno = EMSGSIZE;
    return -1;
  }
  void *buf = malloc(n ? n : 1);
  if (!buf) {
    errno = ENOMEM;
    return -1;
  }
  if (n && read_all(fd, buf, n) != 0) {
    free(buf);
    return -1;
  }
  *out = buf;
  return (ssize_t)n;
}

static int encode_udp_datagram(const struct sockaddr *dest, const void *buf,
                               size_t len, void **out, size_t *out_len) {
  char ip[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  int family = 0;
  if (sockaddr_to_ip_port(dest, ip, sizeof(ip), &port, &family) != 0) {
    errno = EDESTADDRREQ;
    return -1;
  }
  size_t ip_len = family == AF_INET ? 4 : 16;
  if (len > MAX_PACKET || len > MAX_PACKET - 4 - ip_len) {
    errno = EMSGSIZE;
    return -1;
  }
  unsigned char *p = malloc(4 + ip_len + len);
  if (!p) {
    errno = ENOMEM;
    return -1;
  }
  p[0] = family == AF_INET ? 4 : 6;
  p[1] = 0;
  p[2] = (unsigned char)(port >> 8);
  p[3] = (unsigned char)port;
  if (family == AF_INET) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) {
      free(p);
      errno = EINVAL;
      return -1;
    }
    memcpy(p + 4, &a, 4);
  } else {
    struct in6_addr a6;
    if (inet_pton(AF_INET6, ip, &a6) != 1) {
      free(p);
      errno = EINVAL;
      return -1;
    }
    memcpy(p + 4, &a6, 16);
  }
  memcpy(p + 4 + ip_len, buf, len);
  *out = p;
  *out_len = 4 + ip_len + len;
  return 0;
}

static ssize_t decode_udp_datagram(const void *packet, size_t packet_len,
                                   void *buf, size_t len, struct sockaddr *src,
                                   socklen_t *srclen) {
  const unsigned char *p = (const unsigned char *)packet;
  if (packet_len < 8) {
    errno = EPROTO;
    return -1;
  }
  int family = p[0] == 4 ? AF_INET : (p[0] == 6 ? AF_INET6 : 0);
  size_t ip_len = family == AF_INET ? 4 : (family == AF_INET6 ? 16 : 0);
  if (!family || packet_len < 4 + ip_len) {
    errno = EPROTO;
    return -1;
  }
  uint16_t port = ((uint16_t)p[2] << 8) | p[3];
  if (src && srclen) {

    socklen_t need = (family == AF_INET) ? sizeof(struct sockaddr_in)
                                         : sizeof(struct sockaddr_in6);

    socklen_t copy = *srclen < need ? *srclen : need;

    if (family == AF_INET) {
      struct sockaddr_in in;
      memset(&in, 0, sizeof(in));
      in.sin_family = AF_INET;
      in.sin_port = htons(port);
      memcpy(&in.sin_addr, p + 4, 4);

      memcpy(src, &in, copy);

    } else {
      struct sockaddr_in6 in6;
      memset(&in6, 0, sizeof(in6));
      in6.sin6_family = AF_INET6;
      in6.sin6_port = htons(port);
      memcpy(&in6.sin6_addr, p + 4, 16);

      memcpy(src, &in6, copy);
    }

    *srclen = need;
  }
  size_t data_len = packet_len - 4 - ip_len;
  size_t copy = data_len < len ? data_len : len;
  if (copy)
    memcpy(buf, p + 4 + ip_len, copy);
  return (ssize_t)copy;
}

static int proxy_connect(int fd, const struct sockaddr *addr,
                         socklen_t addrlen) {
  (void)addrlen;
  if (is_loopback_addr(addr)) {
    if (fd_ok(fd))
      tracked[fd].active = 0;
    return real_connect_fn(fd, addr, addrlen);
  }
  char ip[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  int family = 0;
  if (sockaddr_to_ip_port(addr, ip, sizeof(ip), &port, &family) != 0) {
    return real_connect_fn(fd, addr, addrlen);
  }
  int base = tracked[fd].type & SOCK_TYPE_MASK;
  const char *proto = base == SOCK_DGRAM ? "udp" : "tcp";
  char line[256], ok[128];
  snprintf(line, sizeof(line), "CONNECT %s %s %u\n", proto, ip, (unsigned)port);
  int manager_fd = manager_request(line, ok, sizeof(ok));
  if (manager_fd < 0)
    return -1;
  if (strncmp(ok, "OK", 2) != 0) {
    real_close_fn(manager_fd);
    errno = ECONNREFUSED;
    return -1;
  }
  if (fd_ok(fd)) {
    tracked[fd].remote_family = family;
    tracked[fd].remote_port = port;
    snprintf(tracked[fd].remote_ip, sizeof(tracked[fd].remote_ip), "%s", ip);
  }
  return replace_fd(fd, manager_fd,
                    base == SOCK_DGRAM ? KIND_UDP_CONNECTED : KIND_TCP_STREAM);
}

static int ensure_udp_listener(int fd, int family) {
  if (!fd_ok(fd)) {
    errno = EBADF;
    return -1;
  }
  if (tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER)
    return 0;
  char ip[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  if (tracked[fd].bound) {
    snprintf(ip, sizeof(ip), "%s", tracked[fd].bind_ip);
    port = tracked[fd].bind_port;
  } else if (family == AF_INET6) {
    snprintf(ip, sizeof(ip), "::");
  } else {
    snprintf(ip, sizeof(ip), "0.0.0.0");
  }
  char line[256], ok[128];
  snprintf(line, sizeof(line), "LISTEN udp %s %u\n", ip, (unsigned)port);
  int manager_fd = manager_request(line, ok, sizeof(ok));
  if (manager_fd < 0)
    return -1;
  if (strncmp(ok, "OKUDP", 5) != 0) {
    real_close_fn(manager_fd);
    errno = ECONNREFUSED;
    return -1;
  }
  return replace_fd(fd, manager_fd, KIND_UDP_LISTENER);
}

static int start_tcp_listener(int fd) {
  if (!fd_ok(fd)) {
    errno = EBADF;
    return -1;
  }
  const char *ip = tracked[fd].bound ? tracked[fd].bind_ip : "0.0.0.0";
  uint16_t port = tracked[fd].bound ? tracked[fd].bind_port : 0;
  char line[256], ok[128];
  snprintf(line, sizeof(line), "LISTEN tcp %s %u\n", ip, (unsigned)port);
  int manager_fd = manager_request(line, ok, sizeof(ok));
  if (manager_fd < 0)
    return -1;
  if (strncmp(ok, "OKLISTEN ", 9) != 0) {
    real_close_fn(manager_fd);
    errno = ECONNREFUSED;
    return -1;
  }
  return replace_fd(fd, manager_fd, KIND_TCP_LISTENER);
}

static int managed_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  char line[256];
  if (read_line(fd, line, sizeof(line)) != 0)
    return -1;
  char token[80], ip[INET6_ADDRSTRLEN];
  unsigned long long id = 0;
  unsigned int port = 0;
  if (sscanf(line, "ACCEPT %79s %llu %45s %u", token, &id, ip, &port) != 4) {
    errno = EPROTO;
    return -1;
  }
  char req[256], ok[64];
  snprintf(req, sizeof(req), "ATTACH %s %llu\n", token, id);
  int accepted = manager_request(req, ok, sizeof(ok));
  if (accepted < 0)
    return -1;
  if (strncmp(ok, "OK", 2) != 0) {
    real_close_fn(accepted);
    errno = ECONNABORTED;
    return -1;
  }
  if (addr && addrlen) {
    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &in.sin_addr) == 1) {
      if (*addrlen >= sizeof(in))
        memcpy(addr, &in, sizeof(in));
      else
        memcpy(addr, &in, *addrlen);
      *addrlen = sizeof(in);
    }
  }
  if (fd_ok(accepted)) {
    tracked[accepted].active = 1;
    tracked[accepted].domain = AF_INET;
    tracked[accepted].type = SOCK_STREAM;
    tracked[accepted].proxied = 1;
    tracked[accepted].kind = KIND_TCP_STREAM;
  }
  return accepted;
}

int socket(int domain, int type, int protocol) {
  init_real();
  int fd = real_socket_fn(domain, type, protocol);
  if (fd_ok(fd) && (domain == AF_INET || domain == AF_INET6)) {
    int base = type & SOCK_TYPE_MASK;
    if (base == SOCK_STREAM || base == SOCK_DGRAM) {
      memset(&tracked[fd], 0, sizeof(tracked[fd]));
      tracked[fd].active = 1;
      tracked[fd].domain = domain;
      tracked[fd].type = type;
      tracked[fd].protocol = protocol;
      tracked[fd].saved_fl = real_fcntl_fn ? real_fcntl_fn(fd, F_GETFL) : 0;
      tracked[fd].saved_fdfl = real_fcntl_fn ? real_fcntl_fn(fd, F_GETFD) : 0;
    }
  }
  return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
  init_real();
  if (!fd_ok(fd) || !tracked[fd].active || !addr ||
      (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
    return real_bind_fn(fd, addr, len);
  }
  if (is_loopback_addr(addr)) {
    tracked[fd].active = 0;
    return real_bind_fn(fd, addr, len);
  }
  char ip[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  int family = 0;
  if (sockaddr_to_ip_port(addr, ip, sizeof(ip), &port, &family) != 0) {
    errno = EINVAL;
    return -1;
  }
  tracked[fd].bound = 1;
  tracked[fd].bind_family = family;
  tracked[fd].bind_port = port;
  snprintf(tracked[fd].bind_ip, sizeof(tracked[fd].bind_ip), "%s", ip);
  return 0;
}

int listen(int fd, int backlog) {
  init_real();
  (void)backlog;
  if (fd_ok(fd) && tracked[fd].active &&
      (tracked[fd].type & SOCK_TYPE_MASK) == SOCK_STREAM) {
    return start_tcp_listener(fd);
  }
  return real_listen_fn(fd, backlog);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
  init_real();
  if (debug_enabled() && addr &&
      (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
    char ip[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    int family = 0;
    if (sockaddr_to_ip_port(addr, ip, sizeof(ip), &port, &family) == 0)
      debugf("connect fd=%d family=%d type=%d ip=%s port=%u", fd, family,
             fd_ok(fd) ? tracked[fd].type : 0, ip, (unsigned)port);
  }
  if (fd_ok(fd) && tracked[fd].active && addr &&
      (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
    if ((tracked[fd].type & SOCK_TYPE_MASK) == SOCK_STREAM &&
        should_force_any_dns53(addr)) {
      return force_dns_stream_fd(fd);
    }
    if ((tracked[fd].type & SOCK_TYPE_MASK) == SOCK_DGRAM &&
        should_force_any_dns53(addr)) {
      return force_dns_dgram_fd(fd);
    }
    return proxy_connect(fd, addr, len);
  }
  return real_connect_fn(fd, addr, len);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    return write_packet(fd, buf, len) == 0 ? (ssize_t)len : -1;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {
    errno = EDESTADDRREQ;
    return -1;
  }
  return real_send_fn(fd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t len) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    return write_packet(fd, buf, len) == 0 ? (ssize_t)len : -1;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {
    errno = EDESTADDRREQ;
    return -1;
  }
  return real_write_fn(fd, (void *)buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
  init_real();
  (void)flags;
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    void *packet = NULL;
    ssize_t n = read_packet(fd, &packet);
    if (n < 0)
      return -1;
    size_t copy = (size_t)n < len ? (size_t)n : len;
    if (copy)
      memcpy(buf, packet, copy);
    free(packet);
    return (ssize_t)copy;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {
    return recvfrom(fd, buf, len, flags, NULL, NULL);
  }
  return real_recv_fn(fd, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t len) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    void *packet = NULL;
    ssize_t n = read_packet(fd, &packet);
    if (n < 0)
      return -1;
    size_t copy = (size_t)n < len ? (size_t)n : len;
    if (copy)
      memcpy(buf, packet, copy);
    free(packet);
    return (ssize_t)copy;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {
    return recvfrom(fd, buf, len, 0, NULL, NULL);
  }
  return real_read_fn(fd, buf, len);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest, socklen_t destlen) {
  init_real();
  int family = dest ? dest->sa_family : 0;
  if (fd_ok(fd) && tracked[fd].active &&
      (tracked[fd].type & SOCK_TYPE_MASK) == SOCK_DGRAM &&
      !tracked[fd].proxied) {
    // if (dest && should_force_any_dns53(dest)) {
    //     if (force_dns_dgram_fd(fd) != 0) return -1;
    /*} else*/
    if (dest && is_loopback_addr(dest)) {
      tracked[fd].active = 0;
      return real_sendto_fn(fd, buf, len, flags, dest, destlen);
    } else {
      if (ensure_udp_listener(fd, family == AF_INET6 ? AF_INET6 : AF_INET) != 0)
        return -1;
    }
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    if (dest) {
      errno = EISCONN;
      return -1;
    }
    return write_packet(fd, buf, len) == 0 ? (ssize_t)len : -1;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {
    void *packet = NULL;
    size_t packet_len = 0;
    if (encode_udp_datagram(dest, buf, len, &packet, &packet_len) != 0)
      return -1;
    int err = write_packet(fd, packet, packet_len);
    free(packet);
    return err == 0 ? (ssize_t)len : -1;
  }
  return real_sendto_fn(fd, buf, len, flags, dest, destlen);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src,
                 socklen_t *srclen) {
  init_real();
  (void)flags;

  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_CONNECTED) {

    void *packet = NULL;
    ssize_t n = read_packet(fd, &packet);
    if (n < 0)
      return -1;

    size_t copy = (size_t)n < len ? (size_t)n : len;
    if (copy)
      memcpy(buf, packet, copy);

    free(packet);

    /* IMPORTANT: connected UDP sockets still must return a source address */
    if (src && srclen) {

      int fam = tracked[fd].remote_family ? tracked[fd].remote_family
                                          : tracked[fd].domain;

      fill_sockaddr_from_text(fam, tracked[fd].remote_ip,
                              tracked[fd].remote_port, src, srclen);
    }

    return (ssize_t)copy;
  }
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_UDP_LISTENER) {

    void *packet = NULL;
    ssize_t n = read_packet(fd, &packet);
    if (n < 0)
      return -1;

    ssize_t out;

    if (src && srclen) {

      socklen_t provided = *srclen;

      out = decode_udp_datagram(packet, (size_t)n, buf, len, src, srclen);

      /* POSIX semantics: srclen must contain actual size,
         but we only copy what fits in the provided buffer */

      if (out >= 0) {

        socklen_t actual = (src->sa_family == AF_INET)
                               ? sizeof(struct sockaddr_in)
                               : sizeof(struct sockaddr_in6);

        if (provided < actual) {
          /* buffer was smaller → keep provided copy size */
          *srclen = actual;
        }
      }
    } else {

      out = decode_udp_datagram(packet, (size_t)n, buf, len, NULL, NULL);
    }

    free(packet);
    return out;
  }
  return real_recvfrom_fn(fd, buf, len, flags, src, srclen);
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_TCP_LISTENER) {
    return managed_accept(fd, addr, addrlen);
  }
  int out = real_accept_fn(fd, addr, addrlen);
  if (out < 0 && errno == EINVAL && is_manager_fd(fd)) {
    return managed_accept(fd, addr, addrlen);
  }
  return out;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      tracked[fd].kind == KIND_TCP_LISTENER) {
    (void)flags;
    return managed_accept(fd, addr, addrlen);
  }
  int out = real_accept4_fn ? real_accept4_fn(fd, addr, addrlen, flags)
                            : real_accept_fn(fd, addr, addrlen);
  if (out < 0 && errno == EINVAL && is_manager_fd(fd)) {
    return managed_accept(fd, addr, addrlen);
  }
  return out;
}

int close(int fd) {
  init_real();
  if (fd_ok(fd))
    memset(&tracked[fd], 0, sizeof(tracked[fd]));
  return real_close_fn(fd);
}

int dup(int oldfd) {
  init_real();
  int fd = real_dup_fn(oldfd);
  if (fd >= 0)
    copy_tracking(fd, oldfd);
  return fd;
}

int dup2(int oldfd, int newfd) {
  init_real();
  int fd = real_dup2_fn(oldfd, newfd);
  if (fd >= 0)
    copy_tracking(newfd, oldfd);
  return fd;
}

int dup3(int oldfd, int newfd, int flags) {
  init_real();
  if (!real_dup3_fn) {
    errno = ENOSYS;
    return -1;
  }
  int fd = real_dup3_fn(oldfd, newfd, flags);
  if (fd >= 0)
    copy_tracking(newfd, oldfd);
  return fd;
}

static int fill_sockaddr_from_text(int family, const char *ip, uint16_t port,
                                   struct sockaddr *addr, socklen_t *addrlen) {
  if (!addrlen) {
    errno = EFAULT;
    return -1;
  }
  if (!addr) {
    *addrlen = family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                  : sizeof(struct sockaddr_in);
    return 0;
  }
  if (family == AF_INET6) {
    struct sockaddr_in6 in6;
    memset(&in6, 0, sizeof(in6));
    in6.sin6_family = AF_INET6;
    in6.sin6_port = htons(port);
    if (ip && *ip && inet_pton(AF_INET6, ip, &in6.sin6_addr) != 1) {
      errno = EINVAL;
      return -1;
    }
    if (*addrlen >= sizeof(struct sockaddr_in))
      memcpy(addr, &in6, sizeof(in6));
    else
      memcpy(addr, &in6, *addrlen);
    *addrlen = sizeof(in6);
    return 0;
  }
  struct sockaddr_in in;
  memset(&in, 0, sizeof(in));
  in.sin_family = AF_INET;
  in.sin_port = htons(port);
  if (ip && *ip && inet_pton(AF_INET, ip, &in.sin_addr) != 1) {
    errno = EINVAL;
    return -1;
  }
  if (*addrlen >= sizeof(struct sockaddr_in))
    memcpy(addr, &in, sizeof(in));
  else
    memcpy(addr, &in, *addrlen);
  *addrlen = sizeof(in);
  return 0;
}

static int managed_getsockname(int fd, struct sockaddr *addr,
                               socklen_t *addrlen) {
  if (!fd_ok(fd) || !tracked[fd].proxied) {
    errno = EBADF;
    return -1;
  }
  if (tracked[fd].kind == KIND_TCP_STREAM ||
      tracked[fd].kind == KIND_TCP_LISTENER ||
      tracked[fd].kind == KIND_UDP_CONNECTED ||
      tracked[fd].kind == KIND_UDP_LISTENER) {
    int family = tracked[fd].bound
                     ? tracked[fd].bind_family
                     : (tracked[fd].domain == AF_INET6 ? AF_INET6 : AF_INET);
    const char *ip = tracked[fd].bound
                         ? tracked[fd].bind_ip
                         : (family == AF_INET6 ? "::" : "0.0.0.0");
    uint16_t port = tracked[fd].bound ? tracked[fd].bind_port : 0;
    return fill_sockaddr_from_text(family, ip, port, addr, addrlen);
  }
  return real_getsockname_fn(fd, addr, addrlen);
}

static int managed_getpeername(int fd, struct sockaddr *addr,
                               socklen_t *addrlen) {
  if (!fd_ok(fd) || !tracked[fd].proxied) {
    errno = ENOTCONN;
    return -1;
  }
  if (tracked[fd].kind == KIND_TCP_STREAM ||
      tracked[fd].kind == KIND_UDP_CONNECTED) {
    if (!tracked[fd].remote_port) {
      errno = ENOTCONN;
      return -1;
    }
    return fill_sockaddr_from_text(
        tracked[fd].remote_family
            ? tracked[fd].remote_family
            : (tracked[fd].domain == AF_INET6 ? AF_INET6 : AF_INET),
        tracked[fd].remote_ip, tracked[fd].remote_port, addr, addrlen);
  }
  errno = ENOTCONN;
  return -1;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    return managed_getsockname(fd, addr, addrlen);
  }
  return real_getsockname_fn(fd, addr, addrlen);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    return managed_getpeername(fd, addr, addrlen);
  }
  return real_getpeername_fn(fd, addr, addrlen);
}

int shutdown(int fd, int how) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied &&
      (tracked[fd].kind == KIND_UDP_CONNECTED ||
       tracked[fd].kind == KIND_UDP_LISTENER)) {
    if (how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR) {
      return 0;
    }
    errno = EINVAL;
    return -1;
  }
  return real_shutdown_fn(fd, how);
}

int __getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  return getsockname(fd, addr, addrlen);
}

int __getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  return getpeername(fd, addr, addrlen);
}

int __shutdown(int fd, int how) { return shutdown(fd, how); }

int fcntl(int fd, int cmd, ...) {
  init_real();
  va_list ap;
  void *argp = NULL;
  long arg = 0;
  va_start(ap, cmd);
  arg = va_arg(ap, long);
  argp = (void *)arg;
  va_end(ap);

  if (fd_ok(fd) && tracked[fd].proxied) {
    switch (cmd) {
    case F_GETFL:
      return tracked[fd].saved_fl
                 ? tracked[fd].saved_fl
                 : (real_fcntl_fn ? real_fcntl_fn(fd, cmd) : 0);
    case F_SETFL:
      tracked[fd].saved_fl = (int)arg;
      return real_fcntl_fn ? real_fcntl_fn(fd, cmd, arg) : 0;
    case F_GETFD:
      return tracked[fd].saved_fdfl
                 ? tracked[fd].saved_fdfl
                 : (real_fcntl_fn ? real_fcntl_fn(fd, cmd) : 0);
    case F_SETFD:
      tracked[fd].saved_fdfl = (int)arg;
      return real_fcntl_fn ? real_fcntl_fn(fd, cmd, arg) : 0;
    default:
      break;
    }
  }
  return real_fcntl_fn ? real_fcntl_fn(fd, cmd, argp) : -1;
}

int getsockopt(int fd, int level, int optname, void *optval,
               socklen_t *optlen) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied && optval && optlen) {
    if (level == SOL_SOCKET) {
      if (optname == SO_ERROR && *optlen >= sizeof(int)) {
        *(int *)optval = 0;
        *optlen = sizeof(int);
        return 0;
      }
      if (optname == SO_TYPE && *optlen >= sizeof(int)) {
        *(int *)optval = tracked[fd].type & SOCK_TYPE_MASK;
        *optlen = sizeof(int);
        return 0;
      }
#ifdef SO_DOMAIN
      if (optname == SO_DOMAIN && *optlen >= sizeof(int)) {
        *(int *)optval = tracked[fd].remote_family ? tracked[fd].remote_family
                                                   : tracked[fd].domain;
        *optlen = sizeof(int);
        return 0;
      }
#endif
#ifdef SO_PROTOCOL
      if (optname == SO_PROTOCOL && *optlen >= sizeof(int)) {
        *(int *)optval = tracked[fd].protocol;
        *optlen = sizeof(int);
        return 0;
      }
#endif
#ifdef SO_ACCEPTCONN
      if (optname == SO_ACCEPTCONN && *optlen >= sizeof(int)) {
        *(int *)optval = tracked[fd].kind == KIND_TCP_LISTENER;
        *optlen = sizeof(int);
        return 0;
      }
#endif
    }
#ifdef IPPROTO_TCP
#ifdef TCP_NODELAY
    if (level == IPPROTO_TCP && optname == TCP_NODELAY &&
        *optlen >= sizeof(int)) {
      *(int *)optval = 1;
      *optlen = sizeof(int);
      return 0;
    }
#endif
#endif
  }
  return real_getsockopt_fn
             ? real_getsockopt_fn(fd, level, optname, optval, optlen)
             : -1;
}

int setsockopt(int fd, int level, int optname, const void *optval,
               socklen_t optlen) {
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    if (level == SOL_SOCKET) {
      switch (optname) {
      case SO_KEEPALIVE:
      case SO_REUSEADDR:
#ifdef SO_REUSEPORT
      case SO_REUSEPORT:
#endif
      case SO_SNDBUF:
      case SO_RCVBUF:
        return 0;
      }
    }
#ifdef IPPROTO_TCP
#ifdef TCP_NODELAY
    if (level == IPPROTO_TCP && optname == TCP_NODELAY)
      return 0;
#endif
#endif
  }
  return real_setsockopt_fn
             ? real_setsockopt_fn(fd, level, optname, optval, optlen)
             : -1;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
  static ssize_t (*real_sendmsg_fn)(int, const struct msghdr *, int) = NULL;
  if (!real_sendmsg_fn)
    real_sendmsg_fn = dlsym(RTLD_NEXT, "sendmsg");
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    size_t len = 0, off = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++)
      len += msg->msg_iov[i].iov_len;
    char *buf = malloc(len ? len : 1);
    if (!buf) {
      errno = ENOMEM;
      return -1;
    }
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
      memcpy(buf + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
      off += msg->msg_iov[i].iov_len;
    }
    ssize_t r;
    if ((tracked[fd].kind == KIND_UDP_LISTENER ||
         tracked[fd].kind == KIND_UDP_CONNECTED) &&
        msg->msg_name) {
      r = sendto(fd, buf, len, flags, (const struct sockaddr *)msg->msg_name,
                 msg->msg_namelen);
    } else {
      r = send(fd, buf, len, flags);
    }
    free(buf);
    return r;
  }
  return real_sendmsg_fn ? real_sendmsg_fn(fd, msg, flags) : -1;
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
  static ssize_t (*real_recvmsg_fn)(int, struct msghdr *, int) = NULL;
  if (!real_recvmsg_fn)
    real_recvmsg_fn = dlsym(RTLD_NEXT, "recvmsg");
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    char buf[65536];
    ssize_t r;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    r = recvfrom(fd, buf, sizeof(buf), flags, (struct sockaddr *)&ss, &sl);

    if (r > 0 && msg->msg_name) {
      socklen_t copy = msg->msg_namelen < sl ? msg->msg_namelen : sl;

      memcpy(msg->msg_name, &ss, copy);
      msg->msg_namelen = sl;
    }
    if (r <= 0)
      return r;
    size_t off = 0;
    for (size_t i = 0; i < msg->msg_iovlen && off < (size_t)r; i++) {
      size_t c = msg->msg_iov[i].iov_len;
      if (c > (size_t)r - off)
        c = (size_t)r - off;
      memcpy(msg->msg_iov[i].iov_base, buf + off, c);
      off += c;
    }
    msg->msg_flags = 0;
    return r;
  }
  return real_recvmsg_fn ? real_recvmsg_fn(fd, msg, flags) : -1;
}

int sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags) {
  static int (*real_sendmmsg_fn)(int, struct mmsghdr *, unsigned int, int) =
      NULL;
  if (!real_sendmmsg_fn)
    real_sendmmsg_fn = dlsym(RTLD_NEXT, "sendmmsg");
  init_real();
  if (fd_ok(fd) && tracked[fd].proxied) {
    unsigned int i;
    for (i = 0; i < vlen; i++) {
      ssize_t n = sendmsg(fd, &vmessages[i].msg_hdr, flags);
      if (n < 0)
        return i ? (int)i : -1;
      vmessages[i].msg_len = (unsigned int)n;
    }
    return (int)i;
  }
  return real_sendmmsg_fn ? real_sendmmsg_fn(fd, vmessages, vlen, flags) : -1;
}

int recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags,
             struct timespec *timeout) {
  static int (*real_recvmmsg_fn)(int, struct mmsghdr *, unsigned int, int,
                                 struct timespec *) = NULL;
  if (!real_recvmmsg_fn)
    real_recvmmsg_fn = dlsym(RTLD_NEXT, "recvmmsg");
  init_real();
  (void)timeout;
  if (fd_ok(fd) && tracked[fd].proxied) {
    unsigned int i;
    for (i = 0; i < vlen; i++) {
      ssize_t n = recvmsg(fd, &vmessages[i].msg_hdr, flags);
      if (n < 0)
        return i ? (int)i : -1;
      vmessages[i].msg_len = (unsigned int)n;
    }
    return (int)i;
  }
  return real_recvmmsg_fn
             ? real_recvmmsg_fn(fd, vmessages, vlen, flags, timeout)
             : -1;
}
