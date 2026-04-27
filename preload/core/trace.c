/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Optional per-call trace log for debugging Phase 1 dispatcher behaviour.
 * Enabled by setting UWGS_PRELOAD_TRACE=/path/to/log to a writable file.
 * Each dispatcher prepends `uwg_trace("op=connect fd=%d ...")` and we
 * format to a fixed-size stack buffer + uwg_passthrough_syscall3(SYS_write).
 *
 * Deliberately uses inline-asm syscalls + bypass-secret so the trace
 * itself doesn't recurse through SIGSYS or shim_libc. Async-signal-safe.
 *
 * The trace fd is opened lazily on first uwg_trace call and stays open
 * for the process lifetime. Failure to open the file is silent (no
 * tracing happens, but no error is propagated to the caller).
 */

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "syscall.h"

static int uwg_trace_fd = -1;
static int uwg_trace_inited;

static const char *uwg_trace_getenv(const char *name) {
    extern char **environ;
    if (!environ) return NULL;
    size_t nlen = 0;
    while (name[nlen]) nlen++;
    for (char **e = environ; *e; e++) {
        const char *p = *e;
        size_t i = 0;
        while (i < nlen && p[i] && p[i] == name[i]) i++;
        if (i == nlen && p[i] == '=') return p + i + 1;
    }
    return NULL;
}

static void uwg_trace_init_once(void) {
    if (uwg_trace_inited) return;
    uwg_trace_inited = 1;
    const char *path = uwg_trace_getenv("UWGS_PRELOAD_TRACE");
    if (!path || !*path) return;
    /* O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC */
    long fd = uwg_passthrough_syscall3(
        SYS_openat, -100 /* AT_FDCWD */, (long)path,
        01 | 0100 | 02000 | 02000000);
    if (fd < 0) return;
    /* Best-effort chmod 0666 on first create — don't care if it fails. */
    uwg_trace_fd = (int)fd;
}

static size_t fmt_long(char *out, size_t cap, long v, int hex) {
    if (cap == 0) return 0;
    char tmp[24];
    int neg = 0;
    unsigned long u;
    if (!hex && v < 0) { neg = 1; u = (unsigned long)(-v); }
    else u = (unsigned long)v;
    int n = 0;
    if (u == 0) tmp[n++] = '0';
    else if (hex) {
        while (u) {
            int d = (int)(u & 0xf);
            tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
            u >>= 4;
        }
    } else {
        while (u) { tmp[n++] = (char)('0' + (int)(u % 10)); u /= 10; }
    }
    size_t off = 0;
    if (neg && off < cap) out[off++] = '-';
    if (hex) {
        if (off + 2 < cap) { out[off++] = '0'; out[off++] = 'x'; }
    }
    while (n > 0 && off < cap) out[off++] = tmp[--n];
    return off;
}

void uwg_tracef(const char *fmt, ...) {
    uwg_trace_init_once();
    if (uwg_trace_fd < 0) return;

    char buf[512];
    size_t off = 0;
    va_list ap;
    va_start(ap, fmt);
    for (const char *p = fmt; *p && off < sizeof(buf) - 2; p++) {
        if (*p != '%') { buf[off++] = *p; continue; }
        p++;
        if (!*p) break;
        switch (*p) {
        case 'd': {
            long v = va_arg(ap, int);
            off += fmt_long(buf + off, sizeof(buf) - off, v, 0);
            break;
        }
        case 'l': {
            /* %ld */
            long v = va_arg(ap, long);
            off += fmt_long(buf + off, sizeof(buf) - off, v, 0);
            break;
        }
        case 'x': {
            long v = va_arg(ap, int);
            off += fmt_long(buf + off, sizeof(buf) - off, v, 1);
            break;
        }
        case 'p': {
            void *v = va_arg(ap, void *);
            off += fmt_long(buf + off, sizeof(buf) - off, (long)v, 1);
            break;
        }
        case 's': {
            const char *v = va_arg(ap, const char *);
            if (!v) v = "(null)";
            while (*v && off < sizeof(buf) - 2) buf[off++] = *v++;
            break;
        }
        case '%': buf[off++] = '%'; break;
        default: buf[off++] = '%'; if (off < sizeof(buf) - 2) buf[off++] = *p; break;
        }
    }
    va_end(ap);
    if (off < sizeof(buf)) buf[off++] = '\n';
    (void)uwg_passthrough_syscall3(SYS_write, uwg_trace_fd, (long)buf, (long)off);
}
