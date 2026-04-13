#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int do_gai4(const char *name) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  int rc = getaddrinfo(name, "80", &hints, &res);
  if (rc) {
    printf("ERR %d %s\n", rc, gai_strerror(rc));
    return 1;
  }
  char ip[INET_ADDRSTRLEN];
  struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
  inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
  printf("OK %s %d\n", ip, ntohs(sa->sin_port));
  freeaddrinfo(res);
  return 0;
}
static int do_gai6(const char *name) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  int rc = getaddrinfo(name, NULL, &hints, &res);
  if (rc) {
    printf("ERR %d %s\n", rc, gai_strerror(rc));
    return 1;
  }
  char ip[INET6_ADDRSTRLEN];
  struct sockaddr_in6 *sa = (struct sockaddr_in6 *)res->ai_addr;
  inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip));
  printf("OK %s\n", ip);
  freeaddrinfo(res);
  return 0;
}
static int do_legacy(const char *name) {
  struct hostent *he = gethostbyname(name);
  if (!he) {
    printf("ERR legacy\n");
    return 1;
  }
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, he->h_addr_list[0], ip, sizeof(ip));
  printf("OK %s\n", ip);
  return 0;
}
static int do_reverse(const char *ip) {
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(443);
  if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
    return 2;
  char host[256], serv[32];
  int rc = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                       serv, sizeof(serv), NI_NAMEREQD);
  if (rc) {
    printf("ERR %d %s\n", rc, gai_strerror(rc));
    return 1;
  }
  printf("OK %s %s\n", host, serv);
  return 0;
}
static int do_ghba(const char *ip) {
  struct in_addr a;
  if (inet_pton(AF_INET, ip, &a) != 1)
    return 2;
  struct hostent *he = gethostbyaddr(&a, sizeof(a), AF_INET);
  if (!he) {
    printf("ERR reverse\n");
    return 1;
  }
  printf("OK %s\n", he->h_name);
  return 0;
}
static int do_resq(const char *name, int type) {
  unsigned char answer[2048];
  int n = res_query(name, 1, type, answer, sizeof(answer));
  if (n < 0) {
    printf("ERR res_query\n");
    return 1;
  }
  printf("OK %d %u\n", n, ((unsigned)answer[6] << 8) | answer[7]);
  return 0;
}
struct arg {
  int loops;
  const char *name;
};
static void *worker(void *vp) {
  struct arg *a = (struct arg *)vp;
  for (int i = 0; i < a->loops; i++) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(a->name, "80", &hints, &res) != 0)
      return (void *)1;
    freeaddrinfo(res);
  }
  return NULL;
}
static int do_concurrent(const char *name, int threads, int loops) {
  pthread_t *ids = calloc((size_t)threads, sizeof(*ids));
  if (!ids)
    return 2;
  struct arg a = {loops, name};
  for (int i = 0; i < threads; i++)
    if (pthread_create(&ids[i], NULL, worker, &a) != 0)
      return 2;
  int failed = 0;
  for (int i = 0; i < threads; i++) {
    void *ret = NULL;
    pthread_join(ids[i], &ret);
    if (ret)
      failed = 1;
  }
  free(ids);
  if (failed) {
    printf("ERR concurrent\n");
    return 1;
  }
  printf("OK concurrent %d %d\n", threads, loops);
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 3)
    return 2;
  if (!strcmp(argv[1], "gai4"))
    return do_gai4(argv[2]);
  if (!strcmp(argv[1], "gai6"))
    return do_gai6(argv[2]);
  if (!strcmp(argv[1], "legacy"))
    return do_legacy(argv[2]);
  if (!strcmp(argv[1], "reverse"))
    return do_reverse(argv[2]);
  if (!strcmp(argv[1], "ghba"))
    return do_ghba(argv[2]);
  if (!strcmp(argv[1], "resq") && argc >= 4)
    return do_resq(argv[2], atoi(argv[3]));
  if (!strcmp(argv[1], "concurrent") && argc >= 5)
    return do_concurrent(argv[2], atoi(argv[3]), atoi(argv[4]));
  return 2;
}
