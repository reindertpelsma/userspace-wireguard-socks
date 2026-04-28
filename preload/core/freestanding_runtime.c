/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Implementations for the freestanding-runtime abstractions
 * (uwg_environ, per-thread sigaltstack lookup). Both .so and
 * freestanding builds compile this file — the divergence is in how
 * uwg_environ gets populated (constructor for .so; auxv parser for
 * freestanding).
 *
 * The per-thread lookup uses a fixed-size TID-keyed table instead
 * of __thread storage because freestanding static binaries can't
 * link against the TLS runtime (__tls_get_addr).
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "syscall.h"
#include "freestanding_runtime.h"

/* Global env pointer. Both builds populate it during init. */
char **uwg_environ;

/*
 * Per-thread sigaltstack lookup.
 *
 * Open-addressing table indexed by TID. 256 slots is enough for
 * typical apps (chromium-class fork-heavy might exceed but Phase 2
 * adds dynamic sizing if needed). Lookup is a linear probe from
 * hash(tid) — a few cache-line touches at most.
 *
 * The table is per-process (each fork gets its own). Cross-fork
 * the child sees the parent's TID entries; a lookup returns NULL
 * because gettid() in the child differs, and uwg_core_init_thread
 * re-allocates a sigaltstack lazily.
 */
#ifndef UWG_THREAD_SLOTS
#define UWG_THREAD_SLOTS 256
#endif

struct uwg_thread_slot {
    _Atomic int32_t tid;     /* 0 = empty */
    _Atomic uintptr_t stack; /* mmap'd sigaltstack pointer */
};

static struct uwg_thread_slot uwg_thread_table[UWG_THREAD_SLOTS];

static int32_t uwg_current_tid_local(void) {
    return (int32_t)uwg_syscall0(SYS_gettid);
}

static uint32_t uwg_thread_hash(int32_t tid) {
    /* Knuth multiplicative hash — distributes well over the table. */
    uint32_t h = (uint32_t)tid * 2654435761u;
    return h % UWG_THREAD_SLOTS;
}

void *uwg_get_thread_sigaltstack(void) {
    int32_t tid = uwg_current_tid_local();
    uint32_t start = uwg_thread_hash(tid);
    for (size_t step = 0; step < UWG_THREAD_SLOTS; step++) {
        size_t idx = (start + step) % UWG_THREAD_SLOTS;
        int32_t slot_tid = atomic_load_explicit(&uwg_thread_table[idx].tid,
                                                memory_order_acquire);
        if (slot_tid == tid) {
            return (void *)atomic_load_explicit(&uwg_thread_table[idx].stack,
                                                memory_order_acquire);
        }
        if (slot_tid == 0) return NULL; /* empty slot terminates lookup */
    }
    return NULL;
}

void uwg_set_thread_sigaltstack(void *stack) {
    int32_t tid = uwg_current_tid_local();
    uint32_t start = uwg_thread_hash(tid);
    for (size_t step = 0; step < UWG_THREAD_SLOTS; step++) {
        size_t idx = (start + step) % UWG_THREAD_SLOTS;
        int32_t expected = 0;
        /* CAS to claim the empty slot for this TID. */
        if (atomic_compare_exchange_strong_explicit(
                &uwg_thread_table[idx].tid, &expected, tid,
                memory_order_acq_rel, memory_order_acquire) ||
            expected == tid) {
            atomic_store_explicit(&uwg_thread_table[idx].stack,
                                  (uintptr_t)stack, memory_order_release);
            return;
        }
    }
    /* Table full — silently drop. The thread still runs; the
     * sigaltstack just falls back to the kernel-default stack on
     * SIGSYS, which works as long as the stack has enough room. */
}
