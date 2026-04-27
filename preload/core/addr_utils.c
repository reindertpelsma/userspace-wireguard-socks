/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Address utilities: sockaddr → printable IP+port, port byte-order
 * conversions, loopback checks, and a tiny snprintf-equivalent for
 * formatting fdproxy protocol lines. All freestanding, no libc.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "freestanding.h"
#include "dispatch.h"

/* ntohs/ntohl in inline form — async-signal-safe and freestanding.
 * We use our own to avoid the libc dep on arpa/inet.h for the static
 * Phase 2 build. */
static inline uint16_t uwg_ntohs(uint16_t n) {
    return (uint16_t)((n >> 8) | (n << 8));
}
static inline uint32_t uwg_ntohl(uint32_t n) {
    return ((n & 0xFFu) << 24) | ((n & 0xFF00u) << 8) |
           ((n & 0xFF0000u) >> 8) | ((n & 0xFF000000u) >> 24);
}

/* Detect if a sockaddr's address bytes are loopback. AF_INET 127/8,
 * AF_INET6 ::1. Anything else (including 0.0.0.0 / ::) is NOT
 * loopback for our purposes. */
int uwg_addr_is_loopback(const struct sockaddr *addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t a = uwg_ntohl(sin->sin_addr.s_addr);
        return (a >> 24) == 127;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        const uint8_t *b = sin6->sin6_addr.s6_addr;
        for (int i = 0; i < 15; i++) if (b[i] != 0) return 0;
        return b[15] == 1;
    }
    return 0;
}

/* Format an unsigned int into the given buffer in decimal, returns
 * number of bytes written (NOT including a NUL terminator). The
 * caller should ensure `buf` has at least 11 bytes (max u32 = 10
 * digits + NUL — but we don't write NUL here). */
static int uwg_fmt_uint(char *buf, unsigned int v) {
    if (v == 0) { buf[0] = '0'; return 1; }
    /* unsigned int is at most 32 bits → max 10 decimal digits.
     * Sized to 12 with a small margin; this lets gcc 15+ prove the
     * caller's tmp[12] is large enough and silences -Wstringop-
     * overflow for the macro-inlined call sites. */
    char tmp[12];
    int i = 0;
    while (v && i < (int)sizeof(tmp)) { tmp[i++] = (char)('0' + v % 10); v /= 10; }
    int n = i;
    for (int k = 0; k < n; k++) buf[k] = tmp[n - 1 - k];
    return n;
}

/* IPv4 dotted-quad formatter. Returns bytes written. */
static int uwg_fmt_ipv4(char *buf, uint32_t addr_be) {
    /* addr_be is in network byte order. */
    uint32_t h = uwg_ntohl(addr_be);
    int off = 0;
    off += uwg_fmt_uint(buf + off, (h >> 24) & 0xff); buf[off++] = '.';
    off += uwg_fmt_uint(buf + off, (h >> 16) & 0xff); buf[off++] = '.';
    off += uwg_fmt_uint(buf + off, (h >> 8) & 0xff);  buf[off++] = '.';
    off += uwg_fmt_uint(buf + off,  h        & 0xff);
    return off;
}

/* IPv6 RFC4291 ::-compressed formatter. Returns bytes written.
 * Implements the "longest run of zero groups gets ::" rule. */
static int uwg_fmt_ipv6(char *buf, const uint8_t *a) {
    /* 16 bytes → 8 16-bit groups. */
    uint16_t g[8];
    for (int i = 0; i < 8; i++) {
        g[i] = (uint16_t)((a[i * 2] << 8) | a[i * 2 + 1]);
    }
    /* Find longest run of zero groups (length ≥ 2). */
    int best_start = -1, best_len = 0;
    int cur_start = -1, cur_len = 0;
    for (int i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur_start < 0) { cur_start = i; cur_len = 1; }
            else cur_len++;
            if (cur_len > best_len) { best_start = cur_start; best_len = cur_len; }
        } else {
            cur_start = -1; cur_len = 0;
        }
    }
    if (best_len < 2) best_start = -1;

    int off = 0;
    int i = 0;
    int just_emitted_dcolon = 0;
    while (i < 8) {
        if (i == best_start) {
            buf[off++] = ':'; buf[off++] = ':';
            i += best_len;
            just_emitted_dcolon = 1;
            continue;
        }
        /* Leading colon for non-first group, BUT not when the previous
         * iteration just emitted "::" (that already provides the
         * separator — a third colon would yield "2001:4860:4860:::8888"
         * instead of the canonical "2001:4860:4860::8888"). */
        if (i > 0 && !just_emitted_dcolon) buf[off++] = ':';
        just_emitted_dcolon = 0;
        /* hex format the group, no leading zeros */
        uint16_t v = g[i];
        char tmp[5];
        int k = 0;
        if (v == 0) tmp[k++] = '0';
        else {
            while (v) {
                int d = v & 0xf;
                tmp[k++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
                v >>= 4;
            }
        }
        while (k) buf[off++] = tmp[--k];
        i++;
    }
    return off;
}

/* Parse a sockaddr into printable IP + port + family.
 * Writes a NUL-terminated string to `ip_buf` and the port (host order).
 * Returns 0 on success, -EINVAL if the address family isn't supported. */
int uwg_addr_format(const struct sockaddr *addr, char *ip_buf, size_t ip_len,
                    uint16_t *port, int *family) {
    if (!addr || !ip_buf || ip_len == 0) return -22;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        int n = uwg_fmt_ipv4(ip_buf, sin->sin_addr.s_addr);
        if ((size_t)(n + 1) > ip_len) return -22;
        ip_buf[n] = 0;
        if (port) *port = uwg_ntohs(sin->sin_port);
        if (family) *family = AF_INET;
        return 0;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        int n = uwg_fmt_ipv6(ip_buf, sin6->sin6_addr.s6_addr);
        if ((size_t)(n + 1) > ip_len) return -22;
        ip_buf[n] = 0;
        if (port) *port = uwg_ntohs(sin6->sin6_port);
        if (family) *family = AF_INET6;
        return 0;
    }
    return -22;
}

/* Build a CONNECT/LISTEN line in `out`, returning bytes written
 * (excluding a trailing NUL — but we DO include the trailing newline
 * since the protocol expects it).
 * Returns -EOVERFLOW if `out` is too small. */
int uwg_fmt_connect_line(char *out, size_t out_len, const char *cmd,
                         const char *proto,
                         const char *dest_ip, uint16_t dest_port,
                         const char *bind_ip, uint16_t bind_port) {
    /* Format: "CMD proto dest_ip dest_port bind_ip bind_port\n" */
    if (!out || out_len == 0) return -75; /* -EOVERFLOW */
    size_t off = 0;

#define EMIT_STR(s) do { \
    const char *_p = (s); \
    while (*_p) { if (off + 1 >= out_len) return -75; out[off++] = *_p++; } \
} while (0)
#define EMIT_CHAR(c) do { if (off + 1 >= out_len) return -75; out[off++] = (c); } while (0)
#define EMIT_UINT(v) do { \
    char tmp[12]; int n = uwg_fmt_uint(tmp, (unsigned int)(v)); \
    if (off + (size_t)n + 1 >= out_len) return -75; \
    for (int _i = 0; _i < n; _i++) out[off++] = tmp[_i]; \
} while (0)

    EMIT_STR(cmd);
    EMIT_CHAR(' ');
    EMIT_STR(proto);
    EMIT_CHAR(' ');
    EMIT_STR(dest_ip);
    EMIT_CHAR(' ');
    EMIT_UINT(dest_port);
    EMIT_CHAR(' ');
    EMIT_STR(bind_ip);
    EMIT_CHAR(' ');
    EMIT_UINT(bind_port);
    EMIT_CHAR('\n');
    out[off] = 0;
    return (int)off;

#undef EMIT_STR
#undef EMIT_CHAR
#undef EMIT_UINT
}

/* Parse "OK <bind_ip> <bind_port>" or "OKLISTEN <token> <bind_ip> <bind_port>"
 * style replies. The fdproxy protocol uses space-separated fields.
 * On success: writes ip into ip_buf (NUL-terminated), port via *port.
 * Returns 0 on success, -EINVAL on parse failure. */
static int parse_uint_field(const char *s, uint16_t *out) {
    unsigned int v = 0;
    int saw_digit = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned int)(*s - '0');
        if (v > 0xFFFFu) return -22;
        s++;
        saw_digit = 1;
    }
    if (!saw_digit) return -22;
    *out = (uint16_t)v;
    return 0;
}

/* Fill `sa` with an IPv4 or IPv6 sockaddr from the text representation
 * `ip` (NUL-terminated) plus host-order `port`. On entry, *sa_len is
 * the user-provided buffer size; on success, *sa_len is updated to
 * the FULL size of the constructed sockaddr (POSIX semantics for
 * recvfrom: caller learns the actual address length even if their
 * buffer was smaller, in which case `sa` was truncated).
 *
 * Returns 0 on success or -EINVAL if the text doesn't parse. */
int uwg_addr_from_text(int family, const char *ip, uint16_t port,
                       struct sockaddr *sa, uint32_t *sa_len) {
    if (!sa || !sa_len || !ip) return -22;
    if (family == AF_INET) {
        struct sockaddr_in sin;
        for (size_t i = 0; i < sizeof(sin); i++) ((char *)&sin)[i] = 0;
        sin.sin_family = AF_INET;
        sin.sin_port = (uint16_t)((port >> 8) | (port << 8));
        /* Parse dotted-quad without libc. */
        uint32_t acc = 0;
        int octet = 0, saw_digit = 0, dots = 0;
        for (const char *p = ip; ; p++) {
            if (*p == '.' || *p == 0) {
                if (!saw_digit) return -22;
                acc = (acc << 8) | (uint32_t)(octet & 0xff);
                octet = 0; saw_digit = 0;
                if (*p == 0) break;
                dots++;
                if (dots > 3) return -22;
            } else if (*p >= '0' && *p <= '9') {
                octet = octet * 10 + (*p - '0');
                if (octet > 255) return -22;
                saw_digit = 1;
            } else {
                return -22;
            }
        }
        if (dots != 3) return -22;
        /* sin.sin_addr.s_addr is in network byte order. */
        sin.sin_addr.s_addr = (uint32_t)((acc & 0x000000ff) << 24 |
                                          (acc & 0x0000ff00) <<  8 |
                                          (acc & 0x00ff0000) >>  8 |
                                          (acc & 0xff000000) >> 24);
        uint32_t copy = *sa_len < sizeof(sin) ? *sa_len : (uint32_t)sizeof(sin);
        for (uint32_t i = 0; i < copy; i++) ((char *)sa)[i] = ((char *)&sin)[i];
        *sa_len = (uint32_t)sizeof(sin);
        return 0;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        for (size_t i = 0; i < sizeof(sin6); i++) ((char *)&sin6)[i] = 0;
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = (uint16_t)((port >> 8) | (port << 8));
        if (uwg_parse_ipv6(ip, sin6.sin6_addr.s6_addr) < 0) return -22;
        uint32_t copy = *sa_len < sizeof(sin6) ? *sa_len : (uint32_t)sizeof(sin6);
        for (uint32_t i = 0; i < copy; i++) ((char *)sa)[i] = ((char *)&sin6)[i];
        *sa_len = (uint32_t)sizeof(sin6);
        return 0;
    }
    return -22;
}

/*
 * Freestanding IPv6 text parser. Replaces libc's inet_pton(AF_INET6, …)
 * for the Phase 2 static-binary build, where libc isn't linked in.
 *
 * Accepts the canonical RFC 4291 forms:
 *   - Full 8-group: "2001:db8:85a3:0:0:8a2e:370:7334"
 *   - Compressed-zero "::" run: "2001:db8::8a2e:370:7334" / "::1" / "::"
 *   - IPv4-in-IPv6 mapped: "::ffff:192.168.1.1"
 *
 * Writes 16 raw bytes (network byte order) to `out`. Returns 0 on
 * success, -1 on parse failure.
 */
int uwg_parse_ipv6(const char *s, uint8_t out[16]) {
    if (!s || !out) return -1;
    uint8_t pre[16] = {0};   /* groups before "::" */
    uint8_t post[16] = {0};  /* groups after "::" */
    int pre_groups = 0, post_groups = 0;
    int saw_double_colon = 0;
    int in_post = 0;

    /* Reject leading colon unless it's "::". */
    if (s[0] == ':' && s[1] != ':') return -1;
    if (s[0] == ':' && s[1] == ':') {
        saw_double_colon = 1;
        in_post = 1;
        s += 2;
        if (*s == 0) {
            for (int i = 0; i < 16; i++) out[i] = 0;
            return 0;
        }
    }

    for (;;) {
        /* Parse one hex group (1-4 hex digits) OR detect IPv4 tail. */
        const char *start = s;
        uint32_t v = 0;
        int hex_digits = 0;
        while (*s) {
            int d;
            if (*s >= '0' && *s <= '9') d = *s - '0';
            else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
            else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
            else break;
            v = (v << 4) | (uint32_t)d;
            hex_digits++;
            s++;
            if (hex_digits > 4) return -1;
        }
        if (hex_digits == 0) return -1;

        /* If next char is '.', this group was actually the start of an
         * IPv4-tail (e.g. "192.168.1.1" → 4 octets = 2 groups). Re-parse
         * from `start` as IPv4 dotted-quad. */
        if (*s == '.') {
            uint32_t a = 0;
            int octets = 0, octet = 0, saw_dot_digit = 0;
            for (const char *p = start;; p++) {
                if (*p == '.' || *p == 0) {
                    if (!saw_dot_digit) return -1;
                    a = (a << 8) | (uint32_t)(octet & 0xff);
                    octets++;
                    octet = 0; saw_dot_digit = 0;
                    if (*p == 0) break;
                    if (octets > 3) return -1;
                } else if (*p >= '0' && *p <= '9') {
                    octet = octet * 10 + (*p - '0');
                    if (octet > 255) return -1;
                    saw_dot_digit = 1;
                } else {
                    return -1;
                }
            }
            if (octets != 4) return -1;
            /* Append the 4 IPv4 bytes as 2 IPv6 groups (4 bytes total). */
            uint8_t *dst = in_post ? &post[post_groups * 2] : &pre[pre_groups * 2];
            int *cnt = in_post ? &post_groups : &pre_groups;
            if (*cnt + 2 > 8) return -1;
            dst[0] = (uint8_t)((a >> 24) & 0xff);
            dst[1] = (uint8_t)((a >> 16) & 0xff);
            dst[2] = (uint8_t)((a >>  8) & 0xff);
            dst[3] = (uint8_t)(a & 0xff);
            *cnt += 2;
            break;  /* end of address */
        }

        /* Store the 16-bit group. */
        {
            uint8_t *dst = in_post ? &post[post_groups * 2] : &pre[pre_groups * 2];
            int *cnt = in_post ? &post_groups : &pre_groups;
            if (*cnt + 1 > 8) return -1;
            dst[0] = (uint8_t)((v >> 8) & 0xff);
            dst[1] = (uint8_t)(v & 0xff);
            (*cnt)++;
        }

        if (*s == 0) break;
        if (*s != ':') return -1;
        s++;
        if (*s == ':') {
            if (saw_double_colon) return -1;  /* only one "::" allowed */
            saw_double_colon = 1;
            in_post = 1;
            s++;
            if (*s == 0) break;  /* trailing "::" */
        }
    }

    /* Reassemble: if we had "::", pre_groups + 0-padding + post_groups.
     * Without "::", must have all 8 groups. */
    int total = pre_groups + post_groups;
    if (saw_double_colon) {
        if (total > 8) return -1;
        int zero_groups = 8 - total;
        for (int i = 0; i < pre_groups * 2; i++) out[i] = pre[i];
        for (int i = 0; i < zero_groups * 2; i++) out[pre_groups * 2 + i] = 0;
        for (int i = 0; i < post_groups * 2; i++) {
            out[pre_groups * 2 + zero_groups * 2 + i] = post[i];
        }
    } else {
        if (total != 8) return -1;
        for (int i = 0; i < 16; i++) out[i] = pre[i];
    }
    return 0;
}

int uwg_parse_ok_reply(const char *reply, char *ip_buf, size_t ip_len,
                       uint16_t *port) {
    if (!reply || !ip_buf || ip_len == 0) return -22;
    /* Skip leading "OK " */
    if (reply[0] != 'O' || reply[1] != 'K') return -22;
    const char *p = reply + 2;
    /* Some replies are "OK ip port", others "OKLISTEN token ip port",
     * others "OKUDP ip port". Skip non-space chars after OK, then
     * look for space-delimited fields. */
    while (*p && *p != ' ' && *p != '\t') p++;

    /* For OKLISTEN we need to skip the token field too. Detect by
     * presence of a non-IP-shaped first field after the prefix. We
     * keep it simple: scan to find the LAST 2 space-separated
     * fields, which are always <ip> <port>. */
    /* Walk fields; remember the last two field starts. */
    const char *f1 = NULL, *f2 = NULL;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n') break;
        f1 = f2;
        f2 = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
    }
    /* f1 = ip start, f2 = port start. (For "OK ip port" with no
     * intermediate fields, this still gives us ip and port.) */
    if (!f1 || !f2) return -22;

    /* Copy ip up to whitespace into ip_buf. */
    size_t i = 0;
    const char *ip_end = f1;
    while (*ip_end && *ip_end != ' ' && *ip_end != '\t' && *ip_end != '\n') {
        if (i + 1 >= ip_len) return -22;
        ip_buf[i++] = *ip_end++;
    }
    ip_buf[i] = 0;

    return parse_uint_field(f2, port);
}
