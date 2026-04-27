/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Freestanding replacements for the small libc surface that
 * the preload/core sources rely on. The Phase 1 .so build links these
 * AGAINST glibc's versions (so memcpy/memset come from libc) — the
 * macros below collapse to the libc symbols. The Phase 2 static
 * blob build defines UWG_FREESTANDING and the macros expand to
 * tiny inline implementations with no external symbols.
 *
 * inet_pton (used by addr_utils.c for IPv6 parsing) is NOT in this
 * header — it's lifted into addr_utils.c as a private function
 * gated by UWG_FREESTANDING.
 */

#ifndef UWG_PRELOAD_CORE_FREESTANDING_H
#define UWG_PRELOAD_CORE_FREESTANDING_H

#include <stddef.h>

#ifdef UWG_FREESTANDING

/* Minimal memcpy — the compiler may also synthesize __builtin_memcpy
 * inline; the symbol stub here is for the rare cases where it doesn't
 * (large copies, volatile, etc.). */
static inline void *uwg_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static inline void *uwg_memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

static inline int uwg_strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

#define memcpy  uwg_memcpy
#define memset  uwg_memset
#define strncmp uwg_strncmp

#else
/* Phase 1 .so build — keep using libc's memcpy/memset/strncmp so we
 * benefit from the optimized SIMD versions glibc provides. */
#include <string.h>
#endif

#endif /* UWG_PRELOAD_CORE_FREESTANDING_H */
