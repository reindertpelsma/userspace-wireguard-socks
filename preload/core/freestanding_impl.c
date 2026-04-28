/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Single-TU implementations of memcpy / memset / strncmp for the
 * Phase 2 freestanding (-DUWG_FREESTANDING) static-binary build.
 * The .so build (no UWG_FREESTANDING) uses libc's optimized versions
 * and never compiles this file.
 *
 * GCC / Clang may emit calls to these symbols even when source uses
 * the freestanding.h-provided uwg_*_impl inlines for small fixed
 * cases. The strong definitions here satisfy the link without
 * pulling in libc.
 */

#ifdef UWG_FREESTANDING

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
    }
    return dst;
}

int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

/*
 * sched_yield wrapper — shared_state.h's rwlock primitives call
 * sched_yield() to back off under contention. The .so build resolves
 * this via libc; the freestanding build provides it via the inline
 * syscall machinery.
 */
#include <sys/syscall.h>
#include "syscall.h"

int sched_yield(void) {
    return (int)uwg_syscall0(SYS_sched_yield);
}

#endif /* UWG_FREESTANDING */
