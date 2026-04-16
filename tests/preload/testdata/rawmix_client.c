/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include "rawmix_helpers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct worker_args {
  const char *ip;
  int port;
  const char *prefix;
  int worker;
  int loops;
  int failed;
  char error[256];
};

static ssize_t write_full_dynamic(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, p + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = EPIPE;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static ssize_t write_full_raw(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  size_t off = 0;
  while (off < len) {
    ssize_t n = rawmix_write(fd, p + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = EPIPE;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static ssize_t read_full_dynamic(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  size_t off = 0;
  while (off < len) {
    ssize_t n = read(fd, p + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static ssize_t read_full_raw(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  size_t off = 0;
  while (off < len) {
    ssize_t n = rawmix_read(fd, p + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static int dynamic_echo(int fd, const char *message) {
  size_t len = strlen(message);
  char *buf = malloc(len + 1);
  if (!buf) {
    errno = ENOMEM;
    return -1;
  }
  if (write_full_dynamic(fd, message, len) < 0) {
    free(buf);
    return -1;
  }
  if (read_full_dynamic(fd, buf, len) < 0) {
    free(buf);
    return -1;
  }
  buf[len] = 0;
  int ok = strcmp(buf, message) == 0 ? 0 : -1;
  free(buf);
  if (ok != 0)
    errno = EPROTO;
  return ok;
}

static int raw_echo(int fd, const char *message) {
  size_t len = strlen(message);
  char *buf = malloc(len + 1);
  if (!buf) {
    errno = ENOMEM;
    return -1;
  }
  if (write_full_raw(fd, message, len) < 0) {
    free(buf);
    return -1;
  }
  if (read_full_raw(fd, buf, len) < 0) {
    free(buf);
    return -1;
  }
  buf[len] = 0;
  int ok = strcmp(buf, message) == 0 ? 0 : -1;
  free(buf);
  if (ok != 0)
    errno = EPROTO;
  return ok;
}

static int stdio_echo_consume(int fd, const char *message) {
  size_t len = strlen(message);
  FILE *fp = fdopen(fd, "r+");
  char *buf;
  if (!fp)
    return -1;
  if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
    fclose(fp);
    return -1;
  }
  if (fwrite(message, 1, len, fp) != len) {
    fclose(fp);
    errno = EIO;
    return -1;
  }
  if (fflush(fp) != 0) {
    fclose(fp);
    return -1;
  }
  buf = malloc(len + 1);
  if (!buf) {
    fclose(fp);
    errno = ENOMEM;
    return -1;
  }
  if (fread(buf, 1, len, fp) != len) {
    free(buf);
    fclose(fp);
    errno = EIO;
    return -1;
  }
  buf[len] = 0;
  int ok = strcmp(buf, message) == 0 ? 0 : -1;
  free(buf);
  if (fclose(fp) != 0)
    return -1;
  if (ok != 0)
    errno = EPROTO;
  return ok;
}

static int make_addr(const char *ip, int port, struct sockaddr_in *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons((unsigned short)port);
  return inet_pton(AF_INET, ip, &addr->sin_addr) == 1 ? 0 : -1;
}

static int open_socket(int raw_socket_mode) {
  if (raw_socket_mode)
    return rawmix_socket(AF_INET, SOCK_STREAM, 0);
  return socket(AF_INET, SOCK_STREAM, 0);
}

static int connect_socket(int fd, int raw_connect_mode,
                          const struct sockaddr_in *addr) {
  if (raw_connect_mode)
    return rawmix_connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
  return connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
}

static int run_mixed_roundtrip(const char *ip, int port, int raw_socket_mode,
                               int raw_connect_mode, const char *label) {
  struct sockaddr_in addr;
  char msg1[128], msg2[128], msg3[128];
  int fd;

  if (make_addr(ip, port, &addr) != 0) {
    fprintf(stderr, "inet_pton failed for %s\n", ip);
    return 1;
  }
  fd = open_socket(raw_socket_mode);
  if (fd < 0) {
    perror("socket");
    return 1;
  }
  if (connect_socket(fd, raw_connect_mode, &addr) != 0) {
    perror("connect");
    rawmix_close(fd);
    return 1;
  }

  snprintf(msg1, sizeof(msg1), "%s-raw", label);
  snprintf(msg2, sizeof(msg2), "%s-dyn", label);
  snprintf(msg3, sizeof(msg3), "%s-stdio", label);

  if (raw_echo(fd, msg1) != 0) {
    perror("raw_echo");
    rawmix_close(fd);
    return 1;
  }
  if (dynamic_echo(fd, msg2) != 0) {
    perror("dynamic_echo");
    rawmix_close(fd);
    return 1;
  }
  if (stdio_echo_consume(fd, msg3) != 0) {
    perror("stdio_echo");
    return 1;
  }
  printf("%s", label);
  return 0;
}

static int run_selected_roundtrip(const char *ip, int port, int raw_socket_mode,
                                  int raw_connect_mode, const char *label,
                                  int do_raw, int do_dynamic, int do_stdio) {
  struct sockaddr_in addr;
  char msg[128];
  int fd;

  if (make_addr(ip, port, &addr) != 0) {
    fprintf(stderr, "inet_pton failed for %s\n", ip);
    return 1;
  }
  fd = open_socket(raw_socket_mode);
  if (fd < 0) {
    perror("socket");
    return 1;
  }
  if (connect_socket(fd, raw_connect_mode, &addr) != 0) {
    perror("connect");
    rawmix_close(fd);
    return 1;
  }

  if (do_raw) {
    snprintf(msg, sizeof(msg), "%s-raw", label);
    if (raw_echo(fd, msg) != 0) {
      perror("raw_echo");
      rawmix_close(fd);
      return 1;
    }
  }
  if (do_dynamic) {
    snprintf(msg, sizeof(msg), "%s-dyn", label);
    if (dynamic_echo(fd, msg) != 0) {
      perror("dynamic_echo");
      rawmix_close(fd);
      return 1;
    }
  }
  if (do_stdio) {
    snprintf(msg, sizeof(msg), "%s-stdio", label);
    if (stdio_echo_consume(fd, msg) != 0) {
      perror("stdio_echo");
      return 1;
    }
  } else if (rawmix_close(fd) != 0) {
    perror("close");
    return 1;
  }
  printf("%s", label);
  return 0;
}

static int run_one_stress_loop(const char *ip, int port, const char *prefix,
                               int worker, int loop) {
  struct sockaddr_in addr;
  char label[128];
  int raw_socket_mode = ((worker + loop) & 1) == 0;
  int raw_connect_mode = !raw_socket_mode;
  int fd;

  if (make_addr(ip, port, &addr) != 0) {
    errno = EINVAL;
    return -1;
  }
  fd = open_socket(raw_socket_mode);
  if (fd < 0)
    return -1;
  if (connect_socket(fd, raw_connect_mode, &addr) != 0) {
    rawmix_close(fd);
    return -1;
  }

  snprintf(label, sizeof(label), "%s-%d-%d", prefix, worker, loop);
  if (raw_echo(fd, label) != 0) {
    rawmix_close(fd);
    return -1;
  }
  snprintf(label, sizeof(label), "%s-%d-%d-dyn", prefix, worker, loop);
  if (dynamic_echo(fd, label) != 0) {
    rawmix_close(fd);
    return -1;
  }
  snprintf(label, sizeof(label), "%s-%d-%d-stdio", prefix, worker, loop);
  if (stdio_echo_consume(fd, label) != 0)
    return -1;
  return 0;
}

static void *stress_worker(void *arg) {
  struct worker_args *worker = (struct worker_args *)arg;
  int i;
  for (i = 0; i < worker->loops; i++) {
    if (run_one_stress_loop(worker->ip, worker->port, worker->prefix,
                            worker->worker, i) != 0) {
      worker->failed = 1;
      snprintf(worker->error, sizeof(worker->error),
               "worker %d loop %d failed: %s", worker->worker, i,
               strerror(errno));
      return NULL;
    }
  }
  return NULL;
}

static int run_stress(const char *ip, int port, const char *prefix, int threads,
                      int loops) {
  int i;
  int failed = 0;
  pthread_t *tids = calloc((size_t)threads, sizeof(*tids));
  struct worker_args *workers = calloc((size_t)threads, sizeof(*workers));
  if (!tids || !workers) {
    fprintf(stderr, "allocation failed\n");
    free(tids);
    free(workers);
    return 1;
  }
  for (i = 0; i < threads; i++) {
    workers[i].ip = ip;
    workers[i].port = port;
    workers[i].prefix = prefix;
    workers[i].worker = i;
    workers[i].loops = loops;
    if (pthread_create(&tids[i], NULL, stress_worker, &workers[i]) != 0) {
      fprintf(stderr, "pthread_create failed for worker %d\n", i);
      failed = 1;
      threads = i;
      break;
    }
  }
  for (i = 0; i < threads; i++) {
    pthread_join(tids[i], NULL);
    if (workers[i].failed) {
      fprintf(stderr, "%s\n", workers[i].error);
      failed = 1;
    }
  }
  free(tids);
  free(workers);
  if (failed)
    return 1;
  printf("rawmix-stress-ok");
  return 0;
}

static int run_print_only(const char *label) {
  printf("%s", label);
  return 0;
}

int main(int argc, char **argv) {
  int port;
  if (argc < 5) {
    fprintf(stderr,
            "usage: %s <print-only|raw-socket-libc-connect|libc-socket-raw-connect|raw-socket-libc-connect-dynamic-only|raw-socket-libc-connect-stdio-only|libc-socket-raw-connect-dynamic-only|libc-socket-raw-connect-stdio-only|stress> "
            "<ip> <port> <label> [threads loops]\n",
            argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "print-only") == 0)
    return run_print_only(argv[4]);
  port = atoi(argv[3]);
  if (strcmp(argv[1], "raw-socket-libc-connect") == 0)
    return run_mixed_roundtrip(argv[2], port, 1, 0, argv[4]);
  if (strcmp(argv[1], "raw-socket-libc-connect-dynamic-only") == 0)
    return run_selected_roundtrip(argv[2], port, 1, 0, argv[4], 0, 1, 0);
  if (strcmp(argv[1], "raw-socket-libc-connect-stdio-only") == 0)
    return run_selected_roundtrip(argv[2], port, 1, 0, argv[4], 0, 0, 1);
  if (strcmp(argv[1], "libc-socket-raw-connect") == 0)
    return run_mixed_roundtrip(argv[2], port, 0, 1, argv[4]);
  if (strcmp(argv[1], "libc-socket-raw-connect-dynamic-only") == 0)
    return run_selected_roundtrip(argv[2], port, 0, 1, argv[4], 0, 1, 0);
  if (strcmp(argv[1], "libc-socket-raw-connect-stdio-only") == 0)
    return run_selected_roundtrip(argv[2], port, 0, 1, argv[4], 0, 0, 1);
  if (strcmp(argv[1], "stress") == 0) {
    int threads = argc >= 6 ? atoi(argv[5]) : 4;
    int loops = argc >= 7 ? atoi(argv[6]) : 6;
    return run_stress(argv[2], port, argv[4], threads, loops);
  }
  fprintf(stderr, "unknown mode %s\n", argv[1]);
  return 2;
}
