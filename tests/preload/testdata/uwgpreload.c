/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

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
};

static struct tracked_fd tracked[MAX_TRACKED_FD];
static int (*real_socket_fn)(int, int, int);
static int (*real_connect_fn)(int, const struct sockaddr *, socklen_t);
static int (*real_bind_fn)(int, const struct sockaddr *, socklen_t);
static int (*real_listen_fn)(int, int);
static int (*real_accept_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4_fn)(int, struct sockaddr *, socklen_t *, int);
static int (*real_close_fn)(int);
static ssize_t (*real_sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*real_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*real_send_fn)(int, const void *, size_t, int);
static ssize_t (*real_recv_fn)(int, void *, size_t, int);
static int (*real_dup_fn)(int);
static int (*real_dup2_fn)(int, int);
static int (*real_dup3_fn)(int, int, int);

static void init_real(void) {
    if (real_socket_fn) return;
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
    real_dup_fn = dlsym(RTLD_NEXT, "dup");
    real_dup2_fn = dlsym(RTLD_NEXT, "dup2");
    real_dup3_fn = dlsym(RTLD_NEXT, "dup3");
}

static int fd_ok(int fd) {
    return fd >= 0 && fd < MAX_TRACKED_FD;
}

static int is_loopback_addr(const struct sockaddr *addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        return (ntohl(in->sin_addr.s_addr) & 0xff000000u) == 0x7f000000u;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        static const unsigned char loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return memcmp(&in6->sin6_addr, loopback, 16) == 0;
    }
    return 0;
}

static int sockaddr_to_ip_port(const struct sockaddr *addr, char *ip, size_t ip_len, uint16_t *port, int *family) {
    if (!addr) return -1;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        if (!inet_ntop(AF_INET, &in->sin_addr, ip, ip_len)) return -1;
        *port = ntohs(in->sin_port);
        *family = AF_INET;
        return 0;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (!inet_ntop(AF_INET6, &in6->sin6_addr, ip, ip_len)) return -1;
        *port = ntohs(in6->sin6_port);
        *family = AF_INET6;
        return 0;
    }
    return -1;
}

static void copy_tracking(int dst, int src) {
    if (!fd_ok(dst)) return;
    if (fd_ok(src)) {
        tracked[dst] = tracked[src];
    } else {
        memset(&tracked[dst], 0, sizeof(tracked[dst]));
    }
}

static const char *manager_path(void) {
    const char *path = getenv("UWGS_FDPROXY");
    if (!path || !*path) path = "/tmp/uwgfdproxy.sock";
    return path;
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = real_send_fn(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
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
            if (errno == EINTR) continue;
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
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        buf[off++] = c;
        if (c == '\n') break;
    }
    buf[off] = 0;
    return 0;
}

static int manager_connect(void) {
    int fd = real_socket_fn(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
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
    if (getpeername(fd, (struct sockaddr *)&un, &len) != 0) return 0;
    if (un.sun_family != AF_UNIX) return 0;
    return strcmp(un.sun_path, manager_path()) == 0;
}

static int manager_request(const char *line, char *reply, size_t reply_len) {
    int fd = manager_connect();
    if (fd < 0) return -1;
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
    if (real_dup2_fn(manager_fd, fd) < 0) {
        real_close_fn(manager_fd);
        return -1;
    }
    if (manager_fd != fd) real_close_fn(manager_fd);
    if (fd_ok(fd)) {
        tracked[fd].proxied = 1;
        tracked[fd].kind = kind;
    }
    return 0;
}

static int write_packet(int fd, const void *buf, size_t len) {
    if (len > MAX_PACKET) {
        errno = EMSGSIZE;
        return -1;
    }
    uint32_t n = htonl((uint32_t)len);
    if (write_all(fd, &n, sizeof(n)) != 0) return -1;
    if (len == 0) return 0;
    return write_all(fd, buf, len);
}

static ssize_t read_packet(int fd, void **out) {
    uint32_t n;
    if (read_all(fd, &n, sizeof(n)) != 0) return -1;
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

static int encode_udp_datagram(const struct sockaddr *dest, const void *buf, size_t len, void **out, size_t *out_len) {
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

static ssize_t decode_udp_datagram(const void *packet, size_t packet_len, void *buf, size_t len, struct sockaddr *src, socklen_t *srclen) {
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
        if (family == AF_INET && *srclen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in *in = (struct sockaddr_in *)src;
            memset(in, 0, sizeof(*in));
            in->sin_family = AF_INET;
            in->sin_port = htons(port);
            memcpy(&in->sin_addr, p + 4, 4);
            *srclen = sizeof(*in);
        } else if (family == AF_INET6 && *srclen >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src;
            memset(in6, 0, sizeof(*in6));
            in6->sin6_family = AF_INET6;
            in6->sin6_port = htons(port);
            memcpy(&in6->sin6_addr, p + 4, 16);
            *srclen = sizeof(*in6);
        }
    }
    size_t data_len = packet_len - 4 - ip_len;
    size_t copy = data_len < len ? data_len : len;
    if (copy) memcpy(buf, p + 4 + ip_len, copy);
    return (ssize_t)copy;
}

static int proxy_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    if (is_loopback_addr(addr)) {
        if (fd_ok(fd)) tracked[fd].active = 0;
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
    if (manager_fd < 0) return -1;
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
    return replace_fd(fd, manager_fd, base == SOCK_DGRAM ? KIND_UDP_CONNECTED : KIND_TCP_STREAM);
}

static int ensure_udp_listener(int fd, int family) {
    if (!fd_ok(fd)) {
        errno = EBADF;
        return -1;
    }
    if (tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER) return 0;
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
    if (manager_fd < 0) return -1;
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
    if (manager_fd < 0) return -1;
    if (strncmp(ok, "OKLISTEN ", 9) != 0) {
        real_close_fn(manager_fd);
        errno = ECONNREFUSED;
        return -1;
    }
    return replace_fd(fd, manager_fd, KIND_TCP_LISTENER);
}

static int managed_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    char line[256];
    if (read_line(fd, line, sizeof(line)) != 0) return -1;
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
    if (accepted < 0) return -1;
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
        if (inet_pton(AF_INET, ip, &in.sin_addr) == 1 && *addrlen >= sizeof(in)) {
            memcpy(addr, &in, sizeof(in));
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
        }
    }
    return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    init_real();
    if (!fd_ok(fd) || !tracked[fd].active || !addr || (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
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
    if (fd_ok(fd) && tracked[fd].active && (tracked[fd].type & SOCK_TYPE_MASK) == SOCK_STREAM) {
        return start_tcp_listener(fd);
    }
    return real_listen_fn(fd, backlog);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    init_real();
    if (fd_ok(fd) && tracked[fd].active && addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        return proxy_connect(fd, addr, len);
    }
    return real_connect_fn(fd, addr, len);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    init_real();
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_CONNECTED) {
        return write_packet(fd, buf, len) == 0 ? (ssize_t)len : -1;
    }
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER) {
        errno = EDESTADDRREQ;
        return -1;
    }
    return real_send_fn(fd, buf, len, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    init_real();
    (void)flags;
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_CONNECTED) {
        void *packet = NULL;
        ssize_t n = read_packet(fd, &packet);
        if (n < 0) return -1;
        size_t copy = (size_t)n < len ? (size_t)n : len;
        if (copy) memcpy(buf, packet, copy);
        free(packet);
        return (ssize_t)copy;
    }
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER) {
        return recvfrom(fd, buf, len, flags, NULL, NULL);
    }
    return real_recv_fn(fd, buf, len, flags);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest, socklen_t destlen) {
    init_real();
    int family = dest ? dest->sa_family : 0;
    if (fd_ok(fd) && tracked[fd].active && (tracked[fd].type & SOCK_TYPE_MASK) == SOCK_DGRAM && !tracked[fd].proxied) {
        if (dest && is_loopback_addr(dest)) {
            tracked[fd].active = 0;
            return real_sendto_fn(fd, buf, len, flags, dest, destlen);
        }
        if (ensure_udp_listener(fd, family == AF_INET6 ? AF_INET6 : AF_INET) != 0) return -1;
    }
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_CONNECTED) {
        if (dest) {
            errno = EISCONN;
            return -1;
        }
        return write_packet(fd, buf, len) == 0 ? (ssize_t)len : -1;
    }
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER) {
        void *packet = NULL;
        size_t packet_len = 0;
        if (encode_udp_datagram(dest, buf, len, &packet, &packet_len) != 0) return -1;
        int err = write_packet(fd, packet, packet_len);
        free(packet);
        return err == 0 ? (ssize_t)len : -1;
    }
    return real_sendto_fn(fd, buf, len, flags, dest, destlen);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src, socklen_t *srclen) {
    init_real();
    (void)flags;
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_CONNECTED) {
        void *packet = NULL;
        ssize_t n = read_packet(fd, &packet);
        if (n < 0) return -1;
        size_t copy = (size_t)n < len ? (size_t)n : len;
        if (copy) memcpy(buf, packet, copy);
        free(packet);
        return (ssize_t)copy;
    }
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_UDP_LISTENER) {
        void *packet = NULL;
        ssize_t n = read_packet(fd, &packet);
        if (n < 0) return -1;
        ssize_t out = decode_udp_datagram(packet, (size_t)n, buf, len, src, srclen);
        free(packet);
        return out;
    }
    return real_recvfrom_fn(fd, buf, len, flags, src, srclen);
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    init_real();
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_TCP_LISTENER) {
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
    if (fd_ok(fd) && tracked[fd].proxied && tracked[fd].kind == KIND_TCP_LISTENER) {
        (void)flags;
        return managed_accept(fd, addr, addrlen);
    }
    int out = real_accept4_fn ? real_accept4_fn(fd, addr, addrlen, flags) : real_accept_fn(fd, addr, addrlen);
    if (out < 0 && errno == EINVAL && is_manager_fd(fd)) {
        return managed_accept(fd, addr, addrlen);
    }
    return out;
}

int close(int fd) {
    init_real();
    if (fd_ok(fd)) memset(&tracked[fd], 0, sizeof(tracked[fd]));
    return real_close_fn(fd);
}

int dup(int oldfd) {
    init_real();
    int fd = real_dup_fn(oldfd);
    if (fd >= 0) copy_tracking(fd, oldfd);
    return fd;
}

int dup2(int oldfd, int newfd) {
    init_real();
    int fd = real_dup2_fn(oldfd, newfd);
    if (fd >= 0) copy_tracking(newfd, oldfd);
    return fd;
}

int dup3(int oldfd, int newfd, int flags) {
    init_real();
    if (!real_dup3_fn) {
        errno = ENOSYS;
        return -1;
    }
    int fd = real_dup3_fn(oldfd, newfd, flags);
    if (fd >= 0) copy_tracking(newfd, oldfd);
    return fd;
}
