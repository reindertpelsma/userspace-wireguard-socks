//go:build ignore
// +build ignore

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../preload/uwgpreload.c"

static int stub_socket(int d, int t, int p) { (void)d; (void)t; (void)p; return -1; }
static int stub_connect(int fd, const struct sockaddr *a, socklen_t l) { (void)fd; (void)a; (void)l; errno = ENOSYS; return -1; }
static int stub_bind(int fd, const struct sockaddr *a, socklen_t l) { (void)fd; (void)a; (void)l; errno = ENOSYS; return -1; }
static int stub_listen(int fd, int b) { (void)fd; (void)b; errno = ENOSYS; return -1; }
static int stub_accept(int fd, struct sockaddr *a, socklen_t *l) { (void)fd; (void)a; (void)l; errno = ENOSYS; return -1; }
static int stub_accept4(int fd, struct sockaddr *a, socklen_t *l, int f) { (void)fd; (void)a; (void)l; (void)f; errno = ENOSYS; return -1; }
static int stub_close(int fd) { (void)fd; return 0; }
static ssize_t stub_sendto(int fd, const void *b, size_t n, int f, const struct sockaddr *a, socklen_t l) { (void)fd; (void)b; (void)n; (void)f; (void)a; (void)l; errno = ENOSYS; return -1; }
static ssize_t stub_recvfrom(int fd, void *b, size_t n, int f, struct sockaddr *a, socklen_t *l) { (void)fd; (void)b; (void)n; (void)f; (void)a; (void)l; errno = ENOSYS; return -1; }
static ssize_t stub_send(int fd, const void *b, size_t n, int f) { (void)fd; (void)b; (void)n; (void)f; errno = ENOSYS; return -1; }
static ssize_t stub_recv(int fd, void *b, size_t n, int f) { (void)fd; (void)b; (void)n; (void)f; errno = ENOSYS; return -1; }
static ssize_t stub_read(int fd, void *b, size_t n) { (void)fd; (void)b; (void)n; errno = ENOSYS; return -1; }
static ssize_t stub_write(int fd, void *b, size_t n) { (void)fd; (void)b; (void)n; errno = ENOSYS; return -1; }
static int stub_dup(int fd) { return fd; }
static int stub_dup2(int a, int b) { (void)a; return b; }
static int stub_dup3(int a, int b, int c) { (void)a; (void)c; return b; }
static int fallback_getsockname_called;
static int fallback_getpeername_called;
static int fallback_shutdown_called;
static int stub_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    fallback_getsockname_called++;
    (void)fd;
    struct sockaddr_in *in = (struct sockaddr_in *) addr;
    assert(*addrlen >= sizeof(*in));
    memset(in, 0, sizeof(*in));
    in->sin_family = AF_INET;
    in->sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.9", &in->sin_addr);
    *addrlen = sizeof(*in);
    return 0;
}
static int stub_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    fallback_getpeername_called++;
    (void)fd;
    struct sockaddr_in *in = (struct sockaddr_in *) addr;
    assert(*addrlen >= sizeof(*in));
    memset(in, 0, sizeof(*in));
    in->sin_family = AF_INET;
    in->sin_port = htons(8888);
    inet_pton(AF_INET, "127.0.0.8", &in->sin_addr);
    *addrlen = sizeof(*in);
    return 0;
}
static int stub_shutdown(int fd, int how) { fallback_shutdown_called++; assert(fd == 43); assert(how == SHUT_RDWR); return 0; }
static void install_stubs(void) {
    real_socket_fn = stub_socket; real_connect_fn = stub_connect; real_bind_fn = stub_bind; real_listen_fn = stub_listen;
    real_accept_fn = stub_accept; real_accept4_fn = stub_accept4; real_close_fn = stub_close; original_real_sendto_fn = stub_sendto;
    original_real_recvfrom_fn = stub_recvfrom; real_send_fn = stub_send; real_recv_fn = stub_recv; real_read_fn = stub_read;
    real_write_fn = stub_write; real_dup_fn = stub_dup; real_dup2_fn = stub_dup2; real_dup3_fn = stub_dup3;
    real_getsockname_fn = stub_getsockname; real_getpeername_fn = stub_getpeername; real_shutdown_fn = stub_shutdown;
}
static void reset_tracking(void) { memset(tracked, 0, sizeof(tracked)); fallback_getsockname_called = 0; fallback_getpeername_called = 0; fallback_shutdown_called = 0; }
int main(void) {
    install_stubs();
    reset_tracking(); tracked[42].proxied = 1; tracked[42].kind = KIND_UDP_LISTENER; tracked[42].domain = AF_INET; tracked[42].bound = 1; tracked[42].bind_family = AF_INET; tracked[42].bind_port = 5353; snprintf(tracked[42].bind_ip, sizeof(tracked[42].bind_ip), "%s", "10.1.2.3");
    struct sockaddr_in in; socklen_t len = sizeof(in); assert(getsockname(42, (struct sockaddr *)&in, &len) == 0); assert(fallback_getsockname_called == 0); assert(ntohs(in.sin_port) == 5353);
    reset_tracking(); tracked[42].proxied = 1; tracked[42].kind = KIND_TCP_STREAM; tracked[42].domain = AF_INET6; tracked[42].remote_family = AF_INET; tracked[42].remote_port = 443; snprintf(tracked[42].remote_ip, sizeof(tracked[42].remote_ip), "%s", "93.184.216.34"); len = sizeof(in); assert(getpeername(42, (struct sockaddr *)&in, &len) == 0); assert(fallback_getpeername_called == 0); assert(ntohs(in.sin_port) == 443);
    reset_tracking(); tracked[42].proxied = 1; tracked[42].kind = KIND_UDP_CONNECTED; assert(shutdown(42, SHUT_RDWR) == 0); assert(fallback_shutdown_called == 0);
    reset_tracking(); len = sizeof(in); assert(getsockname(43, (struct sockaddr *)&in, &len) == 0); assert(fallback_getsockname_called == 1); len = sizeof(in); assert(getpeername(43, (struct sockaddr *)&in, &len) == 0); assert(fallback_getpeername_called == 1); assert(shutdown(43, SHUT_RDWR) == 0); assert(fallback_shutdown_called == 1);
    puts("ok");
    return 0;
}
