/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#ifndef RAWMIX_HELPERS_H
#define RAWMIX_HELPERS_H

#include <stddef.h>
#include <sys/socket.h>

int rawmix_socket(int domain, int type, int protocol);
int rawmix_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t rawmix_write(int fd, const void *buf, size_t len);
ssize_t rawmix_read(int fd, void *buf, size_t len);
int rawmix_close(int fd);

#endif
