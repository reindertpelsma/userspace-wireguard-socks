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

/* Freestanding build path. Use __builtin_* intrinsics so the compiler
 * inlines small fixed-size cases and falls back to a call for large
 * copies. The fallback symbols (memcpy/memset/strncmp) need to exist
 * at link time — we provide them as weak strong symbols below to
 * avoid pulling in libc.
 *
 * The names match libc exactly so source files that #include
 * <string.h> (or have it pulled in transitively via system headers)
 * see consistent extern declarations, and our weak definitions
 * satisfy the link without conflict. */

void *memcpy(void *dst, const void *src, __SIZE_TYPE__ n);
void *memset(void *dst, int c, __SIZE_TYPE__ n);
int   strncmp(const char *a, const char *b, __SIZE_TYPE__ n);

/* When the compiler decides to emit a call instead of inlining, it
 * calls these symbols. Static inline so each TU has its own copy
 * (no link-step duplicate-symbol issue). The compiler usually optimizes
 * the call away for small constant sizes. */
static inline void *uwg_memcpy_impl(void *dst, const void *src, __SIZE_TYPE__ n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (__SIZE_TYPE__ i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
static inline void *uwg_memset_impl(void *dst, int c, __SIZE_TYPE__ n) {
    unsigned char *d = (unsigned char *)dst;
    for (__SIZE_TYPE__ i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
static inline int uwg_strncmp_impl(const char *a, const char *b, __SIZE_TYPE__ n) {
    for (__SIZE_TYPE__ i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

#else
/* Phase 1 .so build — keep using libc's memcpy/memset/strncmp so we
 * benefit from the optimized SIMD versions glibc provides. */
#include <string.h>
#endif

#endif /* UWG_PRELOAD_CORE_FREESTANDING_H */
