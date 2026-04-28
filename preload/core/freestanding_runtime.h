/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Runtime abstractions that diverge between the .so build (libc-linked,
 * uses __thread + extern environ) and the freestanding static-blob
 * build (no libc, manual TID-keyed storage, env from auxv).
 */

#ifndef UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H
#define UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

/* Process-wide environment vector. Set during early init:
 *   - .so build: assigned from libc's `extern char **environ` in the
 *     constructor.
 *   - freestanding build: parsed from auxv at uwg_static_init() time.
 * All env-walking code (uwg_getenv, dns_force.c, fdproxy_sock.c, …)
 * reads via uwg_environ instead of libc's environ. */
extern char **uwg_environ;

/* Per-thread sigaltstack lookup. Replaces the __thread-keyed storage
 * that the .so build uses. The freestanding build can't use __thread
 * because TLS requires runtime support (__tls_get_addr) absent in
 * static binaries.
 *
 * Backed by a small TID-indexed open-addressing table. The cost of a
 * lookup is one CAS-free linear probe over a few cache lines —
 * negligible compared to the per-syscall overhead. */
void *uwg_get_thread_sigaltstack(void);
void  uwg_set_thread_sigaltstack(void *stack);

#endif /* UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H */
