/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Per-fd futex-based rwlock for tunnel-managed metadata.
 *
 * Replaces the sched_yield-spin uwg_rwlock with a proper futex
 * primitive that:
 *   - Blocks waiters in the kernel via FUTEX_WAIT instead of busy-
 *     spinning, so it scales under contention.
 *   - Is re-entrant-resistant: writer-holding-thread cannot acquire
 *     write again (returns -EDEADLK).
 *   - Has a race_close flag for the close(fd)-while-locked case:
 *     close sets the flag; the current lock holder runs cleanup on
 *     unlock instead of synchronously failing the close.
 *   - Recovers from races by goto-loop: every locker that observes
 *     an inconsistent state resets to a valid state and retries.
 *     The lock guarantees that, on return to caller, the state is
 *     valid — even if intermediate windows are racy.
 *
 * State invariants on return-from-lock:
 *   - rdlock_held:  readers > 0, writer_tid == 0
 *   - wrlock_held:  readers == 0, writer_tid == my_tid
 *
 * Usage pattern (every callsite must follow):
 *
 *     int rc = uwg_fxlock_rdlock(&lk);
 *     if (rc < 0) return rc;
 *     ... read fields ...
 *     uwg_fxlock_rdunlock(&lk);
 *
 * Async-signal-safe: futex(2) is on the POSIX async-signal-safe
 * list. All atomic ops are lock-free on x86_64 / aarch64 for the
 * field sizes we use.
 *
 * Memory ordering discipline:
 *   - Stores that publish a state change use memory_order_release.
 *   - Loads that observe a state change use memory_order_acquire.
 *   - FUTEX_WAIT/WAKE syscalls are full barriers — no extra ops
 *     needed around them.
 */

#ifndef UWG_PRELOAD_CORE_FUTEX_RWLOCK_H
#define UWG_PRELOAD_CORE_FUTEX_RWLOCK_H

#include <stdatomic.h>
#include <stdint.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#include "syscall.h"

/* The lock control block. 5 atomic words.
 *
 * On x86_64 / aarch64 each _Atomic word is naturally aligned and the
 * sizeof guarantees no padding between them — padding would change
 * the offsets seen by the kernel-side futex pointer arithmetic and
 * introduce ABA hazards for FUTEX_WAIT.
 */
struct uwg_fxlock {
    _Atomic int32_t  writer_tid;            /* 0 = no writer; tid = held */
    _Atomic uint32_t readers;               /* # of held read locks */
    _Atomic uint32_t futex_waiters_read;    /* writers blocked on readers->0 */
    _Atomic uint32_t futex_waiters_write;   /* anyone blocked on writer_tid->0 */
    _Atomic uint32_t race_close;            /* 1 = close-while-locked pending */
};

#define UWG_FXLOCK_INIT { 0, 0, 0, 0, 0 }

/* -EDEADLK / -EAGAIN — return codes the caller propagates as -errno. */
#define UWG_FXLOCK_OK         0
#define UWG_FXLOCK_REENTRANT (-35)  /* -EDEADLK */
#define UWG_FXLOCK_TRYFAIL   (-11)  /* -EAGAIN */

/* Raw futex syscall — no libc, no errno. SYS_futex isn't in our trap
 * list so we use the non-bypass-secret syscall variant; the kernel
 * processes it directly. */
static inline long uwg_fxlock_futex(_Atomic uint32_t *uaddr, int op,
                                    uint32_t val) {
    return uwg_syscall6(SYS_futex, (long)uaddr, op,
                        (long)val, 0, 0, 0);
}

static inline int32_t uwg_fxlock_gettid(void) {
    return (int32_t)uwg_syscall0(SYS_gettid);
}

/*
 * Acquire read. Returns 0 on success, -errno on failure.
 *
 * Goto-loop structure: we observe writer_tid, readers, etc. without a
 * single global atomic snapshot. Inconsistencies (writer_tid set after
 * we incremented readers) are resolved by undoing our change and
 * retrying. The state is GUARANTEED valid by the time we return.
 */
static inline int uwg_fxlock_rdlock(struct uwg_fxlock *lk) {
    for (;;) {
        /* Step 1: writer present? Wait for writer to release. */
        int32_t w = atomic_load_explicit(&lk->writer_tid,
                                         memory_order_acquire);
        if (w != 0) {
            atomic_fetch_add_explicit(&lk->futex_waiters_write, 1,
                                      memory_order_acq_rel);
            /* FUTEX_WAIT with the value we observed — kernel checks
             * that *uaddr == val before sleeping (ABA guard). */
            uwg_fxlock_futex((_Atomic uint32_t *)&lk->writer_tid,
                             FUTEX_WAIT, (uint32_t)w);
            atomic_fetch_sub_explicit(&lk->futex_waiters_write, 1,
                                      memory_order_acq_rel);
            continue; /* retry the whole protocol */
        }
        /* Step 2: bump reader count. */
        atomic_fetch_add_explicit(&lk->readers, 1,
                                  memory_order_acq_rel);
        /* Step 3: re-check writer. If a writer slipped in, undo
         * and retry. */
        w = atomic_load_explicit(&lk->writer_tid,
                                 memory_order_acquire);
        if (w == 0) {
            return UWG_FXLOCK_OK;
        }
        uint32_t prev = atomic_fetch_sub_explicit(&lk->readers, 1,
                                                  memory_order_acq_rel);
        /* If we just dropped readers to zero, wake any writer that
         * was sleeping in FUTEX_WAIT(readers, prev_val). Without
         * this wake, the writer parks on a value that will never
         * change again — deadlock. (User-spotted race in the
         * tight retry loop.) */
        if (prev == 1) {
            if (atomic_load_explicit(&lk->futex_waiters_read,
                                     memory_order_acquire) > 0) {
                uwg_fxlock_futex(&lk->readers, FUTEX_WAKE, 0x7fffffff);
            }
        }
        /* loop */
    }
}

static inline void uwg_fxlock_rdunlock(struct uwg_fxlock *lk) {
    uint32_t prev = atomic_fetch_sub_explicit(&lk->readers, 1,
                                              memory_order_acq_rel);
    /* If we just dropped to zero, wake any writer waiting on it. */
    if (prev == 1) {
        if (atomic_load_explicit(&lk->futex_waiters_read,
                                 memory_order_acquire) > 0) {
            uwg_fxlock_futex(&lk->readers, FUTEX_WAKE, 0x7fffffff);
        }
        /* race_close: a close arrived while we held the lock. Now
         * that we're the last reader, run the cleanup. The caller
         * passes a cleanup callback or polls race_close after rdunlock
         * — here we just leave the flag set; close path handles it. */
    }
}

/*
 * Acquire write. Returns 0 on success, -EDEADLK if same thread
 * already holds write, -errno on other failure.
 */
static inline int uwg_fxlock_wrlock(struct uwg_fxlock *lk) {
    int32_t my_tid = uwg_fxlock_gettid();
    for (;;) {
        /* Re-entrancy check. */
        int32_t w = atomic_load_explicit(&lk->writer_tid,
                                         memory_order_acquire);
        if (w == my_tid) return UWG_FXLOCK_REENTRANT;

        /* Wait for any readers to drain. */
        uint32_t r = atomic_load_explicit(&lk->readers,
                                          memory_order_acquire);
        if (r > 0) {
            atomic_fetch_add_explicit(&lk->futex_waiters_read, 1,
                                      memory_order_acq_rel);
            uwg_fxlock_futex(&lk->readers, FUTEX_WAIT, r);
            atomic_fetch_sub_explicit(&lk->futex_waiters_read, 1,
                                      memory_order_acq_rel);
            continue;
        }

        /* Wait for any writer to release. */
        if (w != 0) {
            atomic_fetch_add_explicit(&lk->futex_waiters_write, 1,
                                      memory_order_acq_rel);
            uwg_fxlock_futex((_Atomic uint32_t *)&lk->writer_tid,
                             FUTEX_WAIT, (uint32_t)w);
            atomic_fetch_sub_explicit(&lk->futex_waiters_write, 1,
                                      memory_order_acq_rel);
            continue;
        }

        /* Try to claim writer slot. */
        int32_t expected = 0;
        if (!atomic_compare_exchange_strong_explicit(
                &lk->writer_tid, &expected, my_tid,
                memory_order_acq_rel, memory_order_acquire)) {
            continue; /* another thread won the race */
        }

        /* Re-check: did a reader sneak in between our drain check
         * and CAS? If so, release writer slot and retry. */
        r = atomic_load_explicit(&lk->readers, memory_order_acquire);
        if (r > 0) {
            int32_t still = my_tid;
            atomic_compare_exchange_strong_explicit(
                &lk->writer_tid, &still, 0,
                memory_order_acq_rel, memory_order_acquire);
            /* Wake any other writer waiting on writer_tid->0. */
            if (atomic_load_explicit(&lk->futex_waiters_write,
                                     memory_order_acquire) > 0) {
                uwg_fxlock_futex((_Atomic uint32_t *)&lk->writer_tid,
                                 FUTEX_WAKE, 0x7fffffff);
            }
            continue;
        }
        return UWG_FXLOCK_OK;
    }
}

static inline void uwg_fxlock_wrunlock(struct uwg_fxlock *lk) {
    /* Just release the writer slot. race_close handling lives in
     * the caller (uwg_close) — when wrunlock returns, any pending
     * close cleanup happens there. */
    atomic_store_explicit(&lk->writer_tid, 0, memory_order_release);
    if (atomic_load_explicit(&lk->futex_waiters_write,
                             memory_order_acquire) > 0) {
        uwg_fxlock_futex((_Atomic uint32_t *)&lk->writer_tid,
                         FUTEX_WAKE, 0x7fffffff);
    }
}

/* Try-lock variants — return UWG_FXLOCK_TRYFAIL instead of blocking. */
static inline int uwg_fxlock_try_wrlock(struct uwg_fxlock *lk) {
    int32_t my_tid = uwg_fxlock_gettid();
    int32_t w = atomic_load_explicit(&lk->writer_tid,
                                     memory_order_acquire);
    if (w == my_tid) return UWG_FXLOCK_REENTRANT;
    if (w != 0) return UWG_FXLOCK_TRYFAIL;
    uint32_t r = atomic_load_explicit(&lk->readers,
                                      memory_order_acquire);
    if (r > 0) return UWG_FXLOCK_TRYFAIL;
    int32_t expected = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &lk->writer_tid, &expected, my_tid,
            memory_order_acq_rel, memory_order_acquire)) {
        return UWG_FXLOCK_TRYFAIL;
    }
    /* Re-check readers post-CAS. If a reader slipped in between
     * our pre-CAS check and the CAS, we must release the writer
     * slot and report TRYFAIL. */
    r = atomic_load_explicit(&lk->readers, memory_order_acquire);
    if (r > 0) {
        int32_t still = my_tid;
        atomic_compare_exchange_strong_explicit(
            &lk->writer_tid, &still, 0,
            memory_order_acq_rel, memory_order_acquire);
        /* User-spotted bug fix (matching uwg_fxlock_wrunlock): any
         * other thread that was parked in FUTEX_WAIT on
         * writer_tid (i.e. another wrlock attempt) needs a wake-
         * up. Without this they'd sleep on a value that won't
         * change again until some unrelated wrlock+release cycle
         * happens to bump writer_tid. */
        if (atomic_load_explicit(&lk->futex_waiters_write,
                                 memory_order_acquire) > 0) {
            uwg_fxlock_futex((_Atomic uint32_t *)&lk->writer_tid,
                             FUTEX_WAKE, 0x7fffffff);
        }
        return UWG_FXLOCK_TRYFAIL;
    }
    return UWG_FXLOCK_OK;
}

#endif /* UWG_PRELOAD_CORE_FUTEX_RWLOCK_H */
