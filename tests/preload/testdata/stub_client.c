/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int apply_reuse_from_env(int fd) {
    const char *reuse = getenv("UWGS_STUB_REUSE");
    int one = 1;
    if (!reuse || !*reuse || strcmp(reuse, "0") == 0) {
        return 0;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        return 1;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
        perror("setsockopt(SO_REUSEPORT)");
        return 1;
    }
#endif
    return 0;
}

static int env_int_or_default(const char *name, int fallback) {
    const char *value = getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || parsed <= 0 || parsed > 1000000) {
        return fallback;
    }
    return (int)parsed;
}

static int echo_connected(int fd, const char *message) {
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, 1000) <= 0 || !(pfd.revents & POLLOUT)) {
        perror("poll writable");
        return 1;
    }
    size_t want = strlen(message);
    if (send(fd, message, want, 0) != (ssize_t)want) {
        perror("send");
        return 1;
    }
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 3000) <= 0 || !(pfd.revents & POLLIN)) {
        perror("poll readable");
        return 1;
    }
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        perror("recv");
        return 1;
    }
    buf[n] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

static int echo_connected_nopoll(int fd, const char *message) {
    size_t want = strlen(message);
    if (send(fd, message, want, 0) != (ssize_t)want) {
        perror("send");
        return 1;
    }
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        perror("recv");
        return 1;
    }
    buf[n] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

static int echo_unconnected_udp(int fd, const struct sockaddr_in *addr, const char *message) {
    size_t want = strlen(message);
    if (sendto(fd, message, want, 0, (const struct sockaddr *)addr, sizeof(*addr)) != (ssize_t)want) {
        perror("sendto");
        return 1;
    }
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 3000) <= 0 || !(pfd.revents & POLLIN)) {
        perror("poll udp readable");
        return 1;
    }
    char buf[4096];
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &srclen);
    if (n < 0) {
        perror("recvfrom");
        return 1;
    }
    buf[n] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

static int echo_unconnected_udp_nopoll(int fd, const struct sockaddr_in *addr, const char *message) {
    size_t want = strlen(message);
    if (sendto(fd, message, want, 0, (const struct sockaddr *)addr, sizeof(*addr)) != (ssize_t)want) {
        perror("sendto");
        return 1;
    }
    char buf[4096];
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &srclen);
    if (n < 0) {
        perror("recvfrom");
        return 1;
    }
    buf[n] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

static int echo_connected_udp_nopoll(int fd, const char *message) {
    size_t want = strlen(message);
    if (send(fd, message, want, 0) != (ssize_t)want) {
        perror("send");
        return 1;
    }
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        perror("recv");
        return 1;
    }
    buf[n] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

static int accept_one(int fd, const char *message) {
    const char *reply = getenv("UWGS_STUB_REPLY");
    int c = accept(fd, NULL, NULL);
    if (c < 0) {
        perror("accept");
        return 1;
    }
    char buf[4096];
    ssize_t n = recv(c, buf, sizeof(buf), 0);
    if (n < 0) {
        perror("listener recv");
        return 1;
    }
    if ((!reply || !*reply) && ((size_t)n != strlen(message) || memcmp(buf, message, (size_t)n) != 0)) {
        fprintf(stderr, "listener got unexpected payload\n");
        return 1;
    }
    const void *send_buf = buf;
    size_t send_len = (size_t)n;
    if (reply && *reply) {
        send_buf = reply;
        send_len = strlen(reply);
    }
    if (send(c, send_buf, send_len, 0) != (ssize_t)send_len) {
        perror("listener send");
        return 1;
    }
    close(c);
    return 0;
}

static int run_tcp_listener(const char *self, const char *ip, const char *port, const char *message, int exec_before_accept) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    if (apply_reuse_from_env(fd) != 0) {
        close(fd);
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(port));
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        perror("inet_pton");
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(fd, 16) != 0) {
        perror("listen");
        return 1;
    }
    printf("READY\n");
    fflush(stdout);
    if (exec_before_accept) {
        char fd_s[32];
        snprintf(fd_s, sizeof(fd_s), "%d", fd);
        setenv("UWGS_STUB_FD", fd_s, 1);
        char *args[] = {(char *)self, (char *)ip, (char *)port, (char *)message, "accept-child", NULL};
        execv(self, args);
        perror("listener execv");
        return 1;
    }
    int rc = accept_one(fd, message);
    close(fd);
    return rc;
}

static int run_udp_listener(const char *ip, const char *port, const char *message) {
    const char *reply = getenv("UWGS_STUB_REPLY");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    if (apply_reuse_from_env(fd) != 0) {
        close(fd);
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(port));
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        perror("inet_pton");
        close(fd);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    printf("READY\n");
    fflush(stdout);
    int listen_count = env_int_or_default("UWGS_STUB_LISTEN_COUNT", 1);
    for (int i = 0; i < listen_count; i++) {
        char buf[4096];
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &srclen);
        if (n < 0) {
            perror("recvfrom");
            close(fd);
            return 1;
        }
        const char *send_buf = (reply && *reply) ? reply : message;
        size_t want = strlen(send_buf);
        if ((!reply || !*reply) && ((size_t)n != strlen(message) || memcmp(buf, message, (size_t)n) != 0)) {
            fprintf(stderr, "udp listener got unexpected payload\n");
            close(fd);
            return 1;
        }
        if (sendto(fd, send_buf, want, 0, (const struct sockaddr *)&src, srclen) != (ssize_t)want) {
            perror("sendto");
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

static int bind_from_env(int fd) {
    const char *spec = getenv("UWGS_STUB_BIND");
    if (!spec || !*spec) return 0;
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    char *colon = strrchr(tmp, ':');
    if (!colon) {
        fprintf(stderr, "bad UWGS_STUB_BIND\n");
        return 1;
    }
    *colon = 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(colon + 1));
    if (inet_pton(AF_INET, tmp, &addr.sin_addr) != 1) {
        perror("bind inet_pton");
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("env bind");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip> <port> <message> [tcp|udp|udp-unconnected|dup|fork|exec|exec-child|listen-tcp]\n", argv[0]);
        return 2;
    }
    int socktype = SOCK_STREAM;
    int use_dup = 0;
    int use_fork = 0;
    int use_exec = 0;
    int exec_child = 0;
    int accept_child = 0;
    int udp_unconnected = 0;
    int listen_tcp = 0;
    int listen_udp = 0;
    int tcp_no_poll = 0;
    int udp_no_poll = 0;
    int udp_unconnected_no_poll = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "udp") == 0) {
            socktype = SOCK_DGRAM;
        } else if (strcmp(argv[i], "udp-unconnected") == 0) {
            socktype = SOCK_DGRAM;
            udp_unconnected = 1;
        } else if (strcmp(argv[i], "udp-unconnected-no-poll") == 0) {
            socktype = SOCK_DGRAM;
            udp_unconnected = 1;
            udp_unconnected_no_poll = 1;
        } else if (strcmp(argv[i], "tcp") == 0) {
            socktype = SOCK_STREAM;
        } else if (strcmp(argv[i], "dup") == 0) {
            use_dup = 1;
        } else if (strcmp(argv[i], "fork") == 0) {
            use_fork = 1;
        } else if (strcmp(argv[i], "exec") == 0) {
            use_exec = 1;
        } else if (strcmp(argv[i], "exec-child") == 0) {
            exec_child = 1;
        } else if (strcmp(argv[i], "accept-child") == 0) {
            accept_child = 1;
        } else if (strcmp(argv[i], "listen-tcp") == 0) {
            listen_tcp = 1;
        } else if (strcmp(argv[i], "listen-udp") == 0) {
            listen_udp = 1;
        } else if (strcmp(argv[i], "tcp-no-poll") == 0) {
            tcp_no_poll = 1;
        } else if (strcmp(argv[i], "udp-no-poll") == 0) {
            socktype = SOCK_DGRAM;
            udp_no_poll = 1;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 2;
        }
    }
    if (listen_tcp) {
        return run_tcp_listener(argv[0], argv[1], argv[2], argv[3], use_exec);
    }
    if (listen_udp) {
        return run_udp_listener(argv[1], argv[2], argv[3]);
    }
    if (accept_child) {
        const char *fd_s = getenv("UWGS_STUB_FD");
        if (!fd_s) {
            fprintf(stderr, "UWGS_STUB_FD is not set\n");
            return 2;
        }
        return accept_one(atoi(fd_s), argv[3]);
    }
    if (exec_child) {
        const char *fd_s = getenv("UWGS_STUB_FD");
        if (!fd_s) {
            fprintf(stderr, "UWGS_STUB_FD is not set\n");
            return 2;
        }
        if (tcp_no_poll) {
            return echo_connected_nopoll(atoi(fd_s), argv[3]);
        }
        return echo_connected(atoi(fd_s), argv[3]);
    }
    int fd = socket(AF_INET, socktype, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    if (apply_reuse_from_env(fd) != 0) {
        close(fd);
        return 1;
    }
    if (bind_from_env(fd) != 0) {
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
        perror("inet_pton");
        return 1;
    }
    if (udp_unconnected) {
        int rc = udp_unconnected_no_poll ? echo_unconnected_udp_nopoll(fd, &addr, argv[3]) : echo_unconnected_udp(fd, &addr, argv[3]);
        close(fd);
        return rc;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }
    if (use_dup) {
        int next = dup(fd);
        if (next < 0) {
            perror("dup");
            return 1;
        }
        close(fd);
        fd = next;
    }
    if (use_fork) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0) {
            int rc = tcp_no_poll ? echo_connected_nopoll(fd, argv[3]) : echo_connected(fd, argv[3]);
            fflush(stdout);
            _exit(rc);
        }
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            return 1;
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    if (use_exec) {
        char fd_s[32];
        snprintf(fd_s, sizeof(fd_s), "%d", fd);
        setenv("UWGS_STUB_FD", fd_s, 1);
        char *args[] = {argv[0], argv[1], argv[2], argv[3], "exec-child", NULL};
        execv(argv[0], args);
        perror("execv");
        return 1;
    }
    int rc;
    if (udp_no_poll) {
        rc = echo_connected_udp_nopoll(fd, argv[3]);
    } else {
        rc = tcp_no_poll ? echo_connected_nopoll(fd, argv[3]) : echo_connected(fd, argv[3]);
    }
    close(fd);
    return rc;
}
