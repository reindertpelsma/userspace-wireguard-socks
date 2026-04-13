#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern int dns_tcp_connect(void);

#define DNS_MAX_NAME 255
#define DNS_MAX_ADDRS 8
#define DNS_LABEL_MAX 63
#define DNS_IO_TIMEOUT_MS_DEFAULT 500
#define DNS_IO_TIMEOUT_MS_MAX 10000

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static void wr16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xff);
}

static int timeout_ms(void) {
  const char *s = getenv("PRELOAD_DNS_TIMEOUT_MS");
  if (!s || !*s)
    return DNS_IO_TIMEOUT_MS_DEFAULT;
  char *end = NULL;
  long v = strtol(s, &end, 10);
  if (end == s || *end != '\0')
    return DNS_IO_TIMEOUT_MS_DEFAULT;
  if (v < 1)
    v = 1;
  if (v > DNS_IO_TIMEOUT_MS_MAX)
    v = DNS_IO_TIMEOUT_MS_MAX;
  return (int)v;
}

static void set_fd_timeouts(int fd) {
  int ms = timeout_ms();
  struct timeval tv = {.tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000};
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static ssize_t read_full(int fd, void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = read(fd, (char *)buf + off, len - off);
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static ssize_t write_full(int fd, const void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, (const char *)buf + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    off += (size_t)n;
  }
  return (ssize_t)off;
}

static int is_valid_hostname_for_lookup(const char *name) {
  if (!name || !*name)
    return 0;
  size_t n = strlen(name);
  if (n > DNS_MAX_NAME || name[0] == '.' || name[n - 1] == '.')
    return 0;
  size_t label_len = 0;
  int last_hyphen = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c == '.') {
      if (label_len == 0 || label_len > DNS_LABEL_MAX || last_hyphen)
        return 0;
      label_len = 0;
      last_hyphen = 0;
      continue;
    }
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      label_len++;
      last_hyphen = 0;
      continue;
    }
    if (c == '-') {
      if (label_len == 0)
        return 0;
      label_len++;
      last_hyphen = 1;
      continue;
    }
    return 0;
  }
  return label_len != 0 && label_len <= DNS_LABEL_MAX && !last_hyphen;
}

static int encode_qname(const char *name, uint8_t *out, size_t out_sz,
                        size_t *used) {
  if (!is_valid_hostname_for_lookup(name))
    return -1;
  size_t pos = 0;
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t len = dot ? (size_t)(dot - p) : strlen(p);
    if (len == 0 || len > DNS_LABEL_MAX || pos + 1 + len + 1 > out_sz)
      return -1;
    out[pos++] = (uint8_t)len;
    memcpy(out + pos, p, len);
    pos += len;
    if (!dot)
      break;
    p = dot + 1;
  }
  out[pos++] = 0;
  *used = pos;
  return 0;
}

static int expand_name(const uint8_t *msg, size_t msg_len, size_t *off,
                       char *out, size_t out_sz) {
  size_t p = *off, ret_off = p, outp = 0, jumps = 0;
  int jumped = 0;
  while (p < msg_len) {
    uint8_t c = msg[p];
    if ((c & 0xC0) == 0xC0) {
      if (p + 1 >= msg_len)
        return -1;
      uint16_t ptr = (uint16_t)(((c & 0x3F) << 8) | msg[p + 1]);
      if (ptr >= msg_len || ++jumps > 32)
        return -1;
      if (!jumped)
        ret_off = p + 2;
      p = ptr;
      jumped = 1;
      continue;
    }
    if (c == 0) {
      if (!jumped)
        ret_off = p + 1;
      if (outp >= out_sz)
        return -1;
      out[outp] = '\0';
      *off = ret_off;
      return 0;
    }
    if ((c & 0xC0) != 0)
      return -1;
    p++;
    if (c > DNS_LABEL_MAX || p + c > msg_len)
      return -1;
    if (outp) {
      if (outp + 1 >= out_sz)
        return -1;
      out[outp++] = '.';
    }
    if (outp + c >= out_sz)
      return -1;
    memcpy(out + outp, msg + p, c);
    outp += c;
    p += c;
  }
  return -1;
}

static int skip_name(const uint8_t *msg, size_t msg_len, size_t *off) {
  char tmp[DNS_MAX_NAME + 1];
  return expand_name(msg, msg_len, off, tmp, sizeof(tmp));
}

static int build_dns_query(const char *name, uint16_t qtype, uint16_t id,
                           uint8_t *out, size_t out_sz, size_t *used) {
  if (out_sz < 12 + 5)
    return -1;
  memset(out, 0, 12);
  wr16(out + 0, id);
  wr16(out + 2, 0x0100);
  wr16(out + 4, 1);
  size_t pos = 12, qname_len = 0;
  if (encode_qname(name, out + pos, out_sz - pos, &qname_len) < 0)
    return -1;
  pos += qname_len;
  wr16(out + pos, qtype);
  pos += 2;
  wr16(out + pos, 1);
  pos += 2;
  *used = pos;
  return 0;
}

static uint16_t make_dns_id(const void *tag) {
  uintptr_t v =
      (uintptr_t)tag ^ (uintptr_t)pthread_self() ^ (uintptr_t)getpid();
  v ^= v >> 16;
  return (uint16_t)(v & 0xffffu);
}

static int dns_tcp_exchange_raw(const uint8_t *query, size_t qlen,
                                uint16_t expected_id, uint8_t *answer,
                                size_t anslen) {
  int fd = dns_tcp_connect();
  if (fd < 0)
    return -1;
  set_fd_timeouts(fd);
  uint8_t lenbuf[2];
  wr16(lenbuf, (uint16_t)qlen);
  if (write_full(fd, lenbuf, 2) < 0 || write_full(fd, query, qlen) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  if (read_full(fd, lenbuf, 2) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  size_t rlen = rd16(lenbuf);
  if (rlen < 12 || rlen > anslen) {
    close(fd);
    errno = EPROTO;
    return -1;
  }
  if (read_full(fd, answer, rlen) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  close(fd);
  if (rd16(answer) != expected_id || (rd16(answer + 2) & 0x8000u) == 0) {
    errno = EPROTO;
    return -1;
  }
  return (int)rlen;
}

static int dns_parse_rcode(const uint8_t *msg, size_t len) {
  return len < 12 ? -1 : (int)(rd16(msg + 2) & 0x000f);
}

static int dns_extract_addrs(const uint8_t *msg, size_t len, int family,
                             uint8_t addrs[][16], size_t *count) {
  int rcode = dns_parse_rcode(msg, len);
  if (rcode == 3)
    return EAI_NONAME;
  if (rcode != 0)
    return EAI_FAIL;
  uint16_t qd = rd16(msg + 4), an = rd16(msg + 6), ns = rd16(msg + 8),
           ar = rd16(msg + 10);
  size_t off = 12;
  for (uint16_t i = 0; i < qd; i++) {
    if (skip_name(msg, len, &off) < 0 || off + 4 > len)
      return EAI_FAIL;
    off += 4;
  }
  size_t total = (size_t)an + ns + ar, max = *count;
  *count = 0;
  for (size_t i = 0; i < total; i++) {
    if (skip_name(msg, len, &off) < 0 || off + 10 > len)
      return EAI_FAIL;
    uint16_t type = rd16(msg + off), class_ = rd16(msg + off + 2),
             rdlen = rd16(msg + off + 8);
    off += 10;
    if (off + rdlen > len)
      return EAI_FAIL;
    if (class_ == 1) {
      if (family == AF_INET && type == 1 && rdlen == 4 && *count < max) {
        memcpy(addrs[*count], msg + off, 4);
        (*count)++;
      } else if (family == AF_INET6 && type == 28 && rdlen == 16 &&
                 *count < max) {
        memcpy(addrs[*count], msg + off, 16);
        (*count)++;
      }
    }
    off += rdlen;
  }
  return *count ? 0 : EAI_NONAME;
}

static int dns_extract_ptr_name(const uint8_t *msg, size_t len, char *name,
                                size_t name_sz) {
  int rcode = dns_parse_rcode(msg, len);
  if (rcode == 3)
    return EAI_NONAME;
  if (rcode != 0)
    return EAI_FAIL;
  uint16_t qd = rd16(msg + 4), an = rd16(msg + 6), ns = rd16(msg + 8),
           ar = rd16(msg + 10);
  size_t off = 12;
  for (uint16_t i = 0; i < qd; i++) {
    if (skip_name(msg, len, &off) < 0 || off + 4 > len)
      return EAI_FAIL;
    off += 4;
  }
  size_t total = (size_t)an + ns + ar;
  for (size_t i = 0; i < total; i++) {
    if (skip_name(msg, len, &off) < 0 || off + 10 > len)
      return EAI_FAIL;
    uint16_t type = rd16(msg + off), class_ = rd16(msg + off + 2),
             rdlen = rd16(msg + off + 8);
    off += 10;
    if (off + rdlen > len)
      return EAI_FAIL;
    if (class_ == 1 && type == 12) {
      size_t rd_off = off;
      return expand_name(msg, len, &rd_off, name, name_sz) == 0 ? 0 : EAI_FAIL;
    }
    off += rdlen;
  }
  return EAI_NONAME;
}

static int resolve_name_via_dns(const char *name, int family,
                                uint8_t addrs[][16], size_t *count) {
  uint8_t query[512], answer[4096];
  size_t qlen = 0;
  uint16_t qtype = family == AF_INET ? 1 : 28, id = make_dns_id(name);
  if (build_dns_query(name, qtype, id, query, sizeof(query), &qlen) < 0)
    return EAI_NONAME;
  int n = dns_tcp_exchange_raw(query, qlen, id, answer, sizeof(answer));
  if (n < 0)
    return EAI_AGAIN;
  return dns_extract_addrs(answer, (size_t)n, family, addrs, count);
}

static int dns_make_reverse_name(const void *addr, int af, char *out,
                                 size_t out_sz) {
  if (af == AF_INET) {
    const uint8_t *a = (const uint8_t *)addr;
    int n = snprintf(out, out_sz, "%u.%u.%u.%u.in-addr.arpa", a[3], a[2], a[1],
                     a[0]);
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
  }
  if (af == AF_INET6) {
    const uint8_t *a = (const uint8_t *)addr;
    char *p = out;
    size_t left = out_sz;
    for (int i = 15; i >= 0; i--) {
      int lo = a[i] & 0x0f, hi = (a[i] >> 4) & 0x0f;
      int n = snprintf(p, left, "%x.%x%s", lo, hi, i == 0 ? ".ip6.arpa" : ".");
      if (n <= 0 || (size_t)n >= left)
        return -1;
      p += n;
      left -= (size_t)n;
    }
    return 0;
  }
  return -1;
}

static int resolve_name_raw(const char *name, int family, uint8_t addrs[][16],
                            size_t *count) {
  if (!name || !count)
    return EAI_NONAME;
  if (family != AF_INET && family != AF_INET6)
    return EAI_FAMILY;
  if (strcmp(name, "localhost") == 0) {
    *count = 1;
    if (family == AF_INET) {
      addrs[0][0] = 127;
      addrs[0][1] = 0;
      addrs[0][2] = 0;
      addrs[0][3] = 1;
    } else {
      static const uint8_t loop6[16] = {[15] = 1};
      memcpy(addrs[0], loop6, 16);
    }
    return 0;
  }
  if (inet_pton(family, name, addrs[0]) == 1) {
    *count = 1;
    return 0;
  }
  if (!is_valid_hostname_for_lookup(name))
    return EAI_NONAME;
  return resolve_name_via_dns(name, family, addrs, count);
}

static int reverse_lookup_raw(const void *addr, int af, char *name,
                              size_t name_sz) {
  if (af == AF_INET) {
    const uint8_t *a = (const uint8_t *)addr;
    if (a[0] == 127 && a[1] == 0 && a[2] == 0 && a[3] == 1) {
      memcpy(name, "localhost", 10);
      return 0;
    }
  } else if (af == AF_INET6) {
    static const uint8_t loop6[16] = {[15] = 1};
    if (memcmp(addr, loop6, 16) == 0) {
      memcpy(name, "localhost", 10);
      return 0;
    }
  } else
    return EAI_FAMILY;
  char rev[128];
  if (dns_make_reverse_name(addr, af, rev, sizeof(rev)) < 0)
    return EAI_FAIL;
  uint8_t query[512], answer[4096];
  size_t qlen = 0;
  uint16_t id = make_dns_id(addr);
  if (build_dns_query(rev, 12, id, query, sizeof(query), &qlen) < 0)
    return EAI_FAIL;
  int n = dns_tcp_exchange_raw(query, qlen, id, answer, sizeof(answer));
  if (n < 0)
    return EAI_AGAIN;
  return dns_extract_ptr_name(answer, (size_t)n, name, name_sz);
}

static int parse_service_port(const char *service, int *port_out) {
  if (!service) {
    *port_out = 0;
    return 0;
  }
  char *end = NULL;
  long v = strtol(service, &end, 10);
  if (end && *end == '\0' && v >= 0 && v <= 65535) {
    *port_out = (int)v;
    return 0;
  }
  return EAI_SERVICE;
}

static struct addrinfo *alloc_ai_node(int family, int socktype, int protocol,
                                      int port, const uint8_t *addr,
                                      const char *canon) {
  struct addrinfo *ai = calloc(1, sizeof(*ai));
  if (!ai)
    return NULL;
  ai->ai_family = family;
  ai->ai_socktype = socktype;
  ai->ai_protocol = protocol;
  ai->ai_addrlen = family == AF_INET ? sizeof(struct sockaddr_in)
                                     : sizeof(struct sockaddr_in6);
  ai->ai_addr = calloc(1, ai->ai_addrlen);
  if (!ai->ai_addr) {
    free(ai);
    return NULL;
  }
  if (canon) {
    ai->ai_canonname = strdup(canon);
    if (!ai->ai_canonname) {
      free(ai->ai_addr);
      free(ai);
      return NULL;
    }
  }
  if (family == AF_INET) {
    struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);
    memcpy(&sa->sin_addr, addr, 4);
  } else {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons((uint16_t)port);
    memcpy(&sa6->sin6_addr, addr, 16);
  }
  return ai;
}

void freeaddrinfo(struct addrinfo *res) {
  while (res) {
    struct addrinfo *next = res->ai_next;
    free(res->ai_addr);
    free(res->ai_canonname);
    free(res);
    res = next;
  }
}

const char *gai_strerror(int ecode) {
  switch (ecode) {
  case 0:
    return "success";
  case EAI_NONAME:
    return "name or service not known";
  case EAI_AGAIN:
    return "temporary failure in name resolution";
  case EAI_FAIL:
    return "non-recoverable failure in name resolution";
  case EAI_FAMILY:
    return "ai_family not supported";
  case EAI_MEMORY:
    return "memory allocation failure";
  case EAI_SERVICE:
    return "service not supported";
#ifdef EAI_OVERFLOW
  case EAI_OVERFLOW:
    return "argument buffer overflow";
#endif
  default: {
    static const char *(*real_fn)(int) = NULL;
    if (!real_fn)
      real_fn = dlsym(RTLD_NEXT, "gai_strerror");
    return real_fn ? real_fn(ecode) : "unknown error";
  }
  }
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  if (!res)
    return EAI_FAIL;
  *res = NULL;
  int family = AF_UNSPEC, socktype = 0, protocol = 0, flags = 0;
  if (hints) {
    family = hints->ai_family;
    socktype = hints->ai_socktype;
    protocol = hints->ai_protocol;
    flags = hints->ai_flags;
  }
  if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6)
    return EAI_FAMILY;
  int port = 0, rc = parse_service_port(service, &port);
  if (rc)
    return rc;
  if (!node) {
    uint8_t a4[4] = {0, 0, 0, 0}, a6[16] = {0};
    if (!(flags & AI_PASSIVE)) {
      a4[0] = 127;
      a4[3] = 1;
      a6[15] = 1;
    }
    struct addrinfo *head = NULL, **tail = &head;
    if (family == AF_UNSPEC || family == AF_INET6) {
      struct addrinfo *ai6 =
          alloc_ai_node(AF_INET6, socktype, protocol, port, a6, NULL);
      if (!ai6)
        return EAI_MEMORY;
      *tail = ai6;
      tail = &ai6->ai_next;
    }
    if (family == AF_UNSPEC || family == AF_INET) {
      struct addrinfo *ai4 =
          alloc_ai_node(AF_INET, socktype, protocol, port, a4, NULL);
      if (!ai4) {
        freeaddrinfo(head);
        return EAI_MEMORY;
      }
      *tail = ai4;
    }
    *res = head;
    return 0;
  }
  struct addrinfo *head = NULL, **tail = &head;
  uint8_t addrs[DNS_MAX_ADDRS][16];
  if (family == AF_UNSPEC || family == AF_INET6) {
    size_t n6 = DNS_MAX_ADDRS;
    rc = resolve_name_raw(node, AF_INET6, addrs, &n6);
    if (rc == 0)
      for (size_t i = 0; i < n6; i++) {
        struct addrinfo *ai =
            alloc_ai_node(AF_INET6, socktype, protocol, port, addrs[i],
                          (flags & AI_CANONNAME) ? node : NULL);
        if (!ai) {
          freeaddrinfo(head);
          return EAI_MEMORY;
        }
        *tail = ai;
        tail = &ai->ai_next;
      }
    else if (family == AF_INET6)
      return rc;
  }
  if (family == AF_UNSPEC || family == AF_INET) {
    size_t n4 = DNS_MAX_ADDRS;
    rc = resolve_name_raw(node, AF_INET, addrs, &n4);
    if (rc == 0)
      for (size_t i = 0; i < n4; i++) {
        struct addrinfo *ai =
            alloc_ai_node(AF_INET, socktype, protocol, port, addrs[i],
                          (flags & AI_CANONNAME) ? node : NULL);
        if (!ai) {
          freeaddrinfo(head);
          return EAI_MEMORY;
        }
        *tail = ai;
        tail = &ai->ai_next;
      }
    else if (family == AF_INET) {
      freeaddrinfo(head);
      return rc;
    }
  }
  if (!head)
    return EAI_NONAME;
  *res = head;
  return 0;
}

static __thread struct hostent tls_he;
static __thread char tls_name[256];
static __thread char *tls_aliases[1];
static __thread char *tls_addr_list[2];
static __thread unsigned char tls_addr[16];

static struct hostent *make_tls_hostent(const char *name, int family,
                                        const uint8_t *addr) {
  memset(&tls_he, 0, sizeof(tls_he));
  strncpy(tls_name, name, sizeof(tls_name) - 1);
  tls_name[sizeof(tls_name) - 1] = '\0';
  tls_aliases[0] = NULL;
  tls_addr_list[0] = (char *)tls_addr;
  tls_addr_list[1] = NULL;
  memcpy(tls_addr, addr, family == AF_INET ? 4 : 16);
  tls_he.h_name = tls_name;
  tls_he.h_aliases = tls_aliases;
  tls_he.h_addrtype = family;
  tls_he.h_length = family == AF_INET ? 4 : 16;
  tls_he.h_addr_list = tls_addr_list;
  return &tls_he;
}

static int fill_hostent_buf(const char *name, int af, const uint8_t *addr,
                            struct hostent *ret, char *buf, size_t buflen,
                            struct hostent **result, int *h_errnop) {
  size_t addrlen = af == AF_INET ? 4 : 16;
  uintptr_t p = (uintptr_t)buf;
  uintptr_t aligned =
      (p + sizeof(char *) - 1) & ~(uintptr_t)(sizeof(char *) - 1);
  size_t pad = (size_t)(aligned - p);
  if (pad > buflen)
    return ERANGE;
  buf += pad;
  buflen -= pad;
  if (buflen < 3 * sizeof(char *))
    return ERANGE;
  char **aliases = (char **)buf;
  buf += sizeof(char *);
  buflen -= sizeof(char *);
  char **addr_list = (char **)buf;
  buf += 2 * sizeof(char *);
  buflen -= 2 * sizeof(char *);
  size_t namelen = strlen(name) + 1;
  if (buflen < namelen + addrlen)
    return ERANGE;
  char *name_copy = buf;
  memcpy(name_copy, name, namelen);
  buf += namelen;
  buflen -= namelen;
  p = (uintptr_t)buf;
  aligned = (p + sizeof(void *) - 1) & ~(uintptr_t)(sizeof(void *) - 1);
  pad = (size_t)(aligned - p);
  if (pad > buflen)
    return ERANGE;
  buf += pad;
  buflen -= pad;
  if (buflen < addrlen)
    return ERANGE;
  memcpy(buf, addr, addrlen);
  aliases[0] = NULL;
  addr_list[0] = buf;
  addr_list[1] = NULL;
  ret->h_name = name_copy;
  ret->h_aliases = aliases;
  ret->h_addrtype = af;
  ret->h_length = (int)addrlen;
  ret->h_addr_list = addr_list;
  *result = ret;
  if (h_errnop)
    *h_errnop = 0;
  return 0;
}

struct hostent *gethostbyname(const char *name) {
  uint8_t addrs[DNS_MAX_ADDRS][16];
  size_t n = DNS_MAX_ADDRS;
  int rc = resolve_name_raw(name, AF_INET, addrs, &n);
  if (rc || !n) {
    h_errno = HOST_NOT_FOUND;
    return NULL;
  }
  return make_tls_hostent(name, AF_INET, addrs[0]);
}
struct hostent *gethostbyname2(const char *name, int af) {
  uint8_t addrs[DNS_MAX_ADDRS][16];
  size_t n = DNS_MAX_ADDRS;
  int rc = resolve_name_raw(name, af, addrs, &n);
  if (rc || !n) {
    h_errno = HOST_NOT_FOUND;
    return NULL;
  }
  return make_tls_hostent(name, af, addrs[0]);
}
int gethostbyname_r(const char *name, struct hostent *ret, char *buf,
                    size_t buflen, struct hostent **result, int *h_errnop) {
  uint8_t addrs[DNS_MAX_ADDRS][16];
  size_t n = DNS_MAX_ADDRS;
  int rc = resolve_name_raw(name, AF_INET, addrs, &n);
  if (rc || !n) {
    *result = NULL;
    if (h_errnop)
      *h_errnop = HOST_NOT_FOUND;
    return ENOENT;
  }
  return fill_hostent_buf(name, AF_INET, addrs[0], ret, buf, buflen, result,
                          h_errnop);
}
int gethostbyname2_r(const char *name, int af, struct hostent *ret, char *buf,
                     size_t buflen, struct hostent **result, int *h_errnop) {
  uint8_t addrs[DNS_MAX_ADDRS][16];
  size_t n = DNS_MAX_ADDRS;
  int rc = resolve_name_raw(name, af, addrs, &n);
  if (rc || !n) {
    *result = NULL;
    if (h_errnop)
      *h_errnop = HOST_NOT_FOUND;
    return ENOENT;
  }
  return fill_hostent_buf(name, af, addrs[0], ret, buf, buflen, result,
                          h_errnop);
}
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type) {
  char name[256];
  if ((type == AF_INET && len != 4) || (type == AF_INET6 && len != 16)) {
    h_errno = NO_RECOVERY;
    return NULL;
  }
  int rc = reverse_lookup_raw(addr, type, name, sizeof(name));
  if (rc) {
    h_errno = HOST_NOT_FOUND;
    return NULL;
  }
  return make_tls_hostent(name, type, (const uint8_t *)addr);
}
int gethostbyaddr_r(const void *addr, socklen_t len, int type,
                    struct hostent *ret, char *buf, size_t buflen,
                    struct hostent **result, int *h_errnop) {
  char name[256];
  if ((type == AF_INET && len != 4) || (type == AF_INET6 && len != 16)) {
    *result = NULL;
    if (h_errnop)
      *h_errnop = NO_RECOVERY;
    return EINVAL;
  }
  int rc = reverse_lookup_raw(addr, type, name, sizeof(name));
  if (rc) {
    *result = NULL;
    if (h_errnop)
      *h_errnop = HOST_NOT_FOUND;
    return ENOENT;
  }
  return fill_hostent_buf(name, type, (const uint8_t *)addr, ret, buf, buflen,
                          result, h_errnop);
}

int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
                socklen_t hostlen, char *serv, socklen_t servlen, int flags) {
  int af = sa ? sa->sa_family : 0, port = 0;
  const void *addr = NULL;
  if (!sa)
    return EAI_FAIL;
  if (af == AF_INET) {
    if (salen < (socklen_t)sizeof(struct sockaddr_in))
      return EAI_FAIL;
    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
    port = ntohs(sin->sin_port);
    addr = &sin->sin_addr;
  } else if (af == AF_INET6) {
    if (salen < (socklen_t)sizeof(struct sockaddr_in6))
      return EAI_FAIL;
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
    port = ntohs(sin6->sin6_port);
    addr = &sin6->sin6_addr;
  } else
    return EAI_FAMILY;
  if (serv && servlen) {
    int n = snprintf(serv, servlen, "%u", (unsigned)port);
    if (n < 0 || n >= servlen)
      return EAI_OVERFLOW;
  }
  if (host && hostlen) {
    if (flags & NI_NUMERICHOST) {
      if (!inet_ntop(af, addr, host, hostlen))
        return EAI_OVERFLOW;
    } else {
      char tmp[256];
      int rc = reverse_lookup_raw(addr, af, tmp, sizeof(tmp));
      if (rc) {
        if (flags & NI_NAMEREQD)
          return rc;
        if (!inet_ntop(af, addr, host, hostlen))
          return EAI_OVERFLOW;
      } else {
        size_t need = strlen(tmp) + 1;
        if (need > hostlen)
          return EAI_OVERFLOW;
        memcpy(host, tmp, need);
      }
    }
  }
  return 0;
}

int res_init(void) { return 0; }
int res_send(const unsigned char *msg, int msglen, unsigned char *answer,
             int anslen) {
  if (!msg || msglen < 12 || !answer || anslen <= 0) {
    errno = EINVAL;
    return -1;
  }
  return dns_tcp_exchange_raw(msg, (size_t)msglen, rd16(msg), answer,
                              (size_t)anslen);
}
int res_nsend(res_state statp, const unsigned char *msg, int msglen,
              unsigned char *answer, int anslen) {
  (void)statp;
  return res_send(msg, msglen, answer, anslen);
}
int res_query(const char *dname, int class, int type, unsigned char *answer,
              int anslen) {
  uint8_t query[512];
  size_t qlen = 0;
  uint16_t id = make_dns_id(dname);
  if (!dname || class != 1 ||
      build_dns_query(dname, (uint16_t)type, id, query, sizeof(query), &qlen) <
          0) {
    h_errno = NO_RECOVERY;
    errno = EINVAL;
    return -1;
  }
  int n = dns_tcp_exchange_raw(query, qlen, id, answer, (size_t)anslen);
  if (n < 0) {
    h_errno = TRY_AGAIN;
    return -1;
  }
  int rcode = dns_parse_rcode(answer, (size_t)n);
  h_errno = (rcode == 0) ? NETDB_SUCCESS
                         : (rcode == 3 ? HOST_NOT_FOUND : NO_RECOVERY);
  return n;
}
int res_nquery(res_state statp, const char *dname, int class, int type,
               unsigned char *answer, int anslen) {
  (void)statp;
  return res_query(dname, class, type, answer, anslen);
}
int res_search(const char *dname, int class, int type, unsigned char *answer,
               int anslen) {
  return res_query(dname, class, type, answer, anslen);
}
int res_nsearch(res_state statp, const char *dname, int class, int type,
                unsigned char *answer, int anslen) {
  (void)statp;
  return res_search(dname, class, type, answer, anslen);
}
int res_querydomain(const char *name, const char *domain, int class, int type,
                    unsigned char *answer, int anslen) {
  char full[512];
  if (!name) {
    h_errno = NO_RECOVERY;
    errno = EINVAL;
    return -1;
  }
  if (!domain || !*domain) {
    if (strlen(name) >= sizeof(full)) {
      h_errno = NO_RECOVERY;
      errno = ENAMETOOLONG;
      return -1;
    }
    strcpy(full, name);
  } else {
    int n = snprintf(full, sizeof(full), "%s.%s", name, domain);
    if (n < 0 || (size_t)n >= sizeof(full)) {
      h_errno = NO_RECOVERY;
      errno = ENAMETOOLONG;
      return -1;
    }
  }
  return res_query(full, class, type, answer, anslen);
}
int res_nquerydomain(res_state statp, const char *name, const char *domain,
                     int class, int type, unsigned char *answer, int anslen) {
  (void)statp;
  return res_querydomain(name, domain, class, type, answer, anslen);
}
