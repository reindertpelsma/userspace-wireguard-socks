/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int raw_echo(int fd, const char *message) {
    size_t want = strlen(message);
    long wrote = syscall(SYS_write, fd, message, want);
    if (wrote != (long)want) {
        perror("raw write");
        return 1;
    }
    char buf[4096];
    long got = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    if (got < 0) {
        perror("raw read");
        return 1;
    }
    buf[got] = 0;
    printf("%s", buf);
    return strcmp(buf, message) == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip> <port> <message> [exec|exec-child]\n", argv[0]);
        return 2;
    }

    if (argc >= 5 && strcmp(argv[4], "exec-child") == 0) {
        const char *fd_s = getenv("UWGS_MIXED_FD");
        if (!fd_s || !*fd_s) {
            fprintf(stderr, "UWGS_MIXED_FD is not set\n");
            return 2;
        }
        return raw_echo(atoi(fd_s), argv[3]);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
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
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    if (argc >= 5 && strcmp(argv[4], "exec") == 0) {
        char fd_s[32];
        snprintf(fd_s, sizeof(fd_s), "%d", fd);
        setenv("UWGS_MIXED_FD", fd_s, 1);
        char *args[] = {argv[0], argv[1], argv[2], argv[3], "exec-child", NULL};
        execv(argv[0], args);
        perror("execv");
        return 1;
    }

    return raw_echo(fd, argv[3]);
}
