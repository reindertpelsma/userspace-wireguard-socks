#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t active_fd = -1;
static volatile sig_atomic_t saw_deadlock_errno = 0;
static volatile sig_atomic_t handler_calls = 0;

static void on_alarm(int sig) {
  (void)sig;
  int fd = active_fd;
  if (fd < 0)
    return;
  struct sockaddr_storage ss;
  socklen_t sl = sizeof(ss);
  errno = 0;
  if (getpeername(fd, (struct sockaddr *)&ss, &sl) < 0 && errno == EDEADLK)
    saw_deadlock_errno = 1;
  handler_calls++;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <bind-ip> <bind-port>\n", argv[0]);
    return 2;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_alarm;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGALRM, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)atoi(argv[2]));
  if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
    fprintf(stderr, "invalid bind ip %s\n", argv[1]);
    return 1;
  }

  for (int i = 0; i < 64 && !saw_deadlock_errno; i++) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      perror("socket");
      return 1;
    }
    active_fd = fd;
    ualarm(1000, 1000);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      perror("bind");
      ualarm(0, 0);
      active_fd = -1;
      close(fd);
      return 1;
    }
    ualarm(0, 0);
    active_fd = -1;
    close(fd);
  }

  if (!saw_deadlock_errno) {
    fprintf(stderr, "expected EDEADLK during signal reentry, handler_calls=%d\n",
            handler_calls);
    return 1;
  }

  puts("reentrant-ok");
  return 0;
}
