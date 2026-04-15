#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int dns_tcp_connect(void) {
  const char *host = getenv("PRELOAD_DNS_TEST_HOST");
  const char *port_s = getenv("PRELOAD_DNS_TEST_PORT");
  if (!host || !*host)
    host = "127.0.0.1";
  int port = port_s ? atoi(port_s) : 5533;
  if (port <= 0 || port > 65535) {
    errno = EINVAL;
    return -1;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
    close(fd);
    errno = EINVAL;
    return -1;
  }
  if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  return fd;
}
