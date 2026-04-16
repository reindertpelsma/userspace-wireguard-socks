/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include "rawmix_helpers.h"

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static long rawmix_syscall6(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6) {
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8),
                     "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

static long rawmix_fixret(long ret) {
  if (ret < 0 && ret >= -4095) {
    errno = (int)-ret;
    return -1;
  }
  return ret;
}

int rawmix_socket(int domain, int type, int protocol) {
  return (int)rawmix_fixret(rawmix_syscall6(SYS_socket, domain, type, protocol,
                                            0, 0, 0));
}

int rawmix_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  return (int)rawmix_fixret(
      rawmix_syscall6(SYS_connect, fd, (long)addr, addrlen, 0, 0, 0));
}

ssize_t rawmix_write(int fd, const void *buf, size_t len) {
  return (ssize_t)rawmix_fixret(
      rawmix_syscall6(SYS_write, fd, (long)buf, (long)len, 0, 0, 0));
}

ssize_t rawmix_read(int fd, void *buf, size_t len) {
  return (ssize_t)rawmix_fixret(
      rawmix_syscall6(SYS_read, fd, (long)buf, (long)len, 0, 0, 0));
}

int rawmix_close(int fd) {
  return (int)rawmix_fixret(rawmix_syscall6(SYS_close, fd, 0, 0, 0, 0, 0));
}
