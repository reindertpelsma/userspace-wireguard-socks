/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * fxlock_contention_stress: dedicated multi-lock multi-thread
 * contention harness for the per-fd futex_rwlock primitive.
 *
 * Why this exists (vs. fxlock_stress.c):
 *   - fxlock_stress hammers ONE lock with 32 threads. That catches
 *     basic mutual-exclusion races but not contention-pool patterns
 *     where threads pick different locks at random — closer to the
 *     real workload, where each tunnel fd has its own rwlock and
 *     threads roam across fds.
 *   - This harness simulates that: a small pool of locks (forced
 *     contention) hammered by N threads with randomized op choice
 *     (rd / wr / try_wr) at realistic ratios.
 *
 * Invariants checked on every op:
 *   - During wrlock(L): nobody else has any lock on L.
 *     (Verified by a per-lock holder_count atomic that bumps on
 *     entry and drops on exit; under wr it must be exactly 1.)
 *   - During rdlock(L): no thread holds wr on L.
 *     (Verified by holder_count >= 1, and the writer_marker is 0.)
 *   - Per-lock shared_value is consistent across the read window:
 *     two reads of the same field within the rdlock window see
 *     equal values.
 *   - try_wr behaves correctly: returns OK only when nobody else
 *     holds, returns TRYFAIL otherwise. We don't retry on TRYFAIL —
 *     that's the contract.
 *
 * Termination:
 *   - Each thread runs N_OPS_PER_THREAD ops, then exits.
 *   - main joins all threads, prints stats, returns 0 if no
 *     invariant violations were observed.
 *
 * Tuning:
 *   - N_THREADS (default 16) and N_LOCKS (default 8) are picked so
 *     N_THREADS > N_LOCKS, guaranteeing real contention. Increase
 *     N_THREADS or decrease N_LOCKS to make the test meaner.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "futex_rwlock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#ifndef N_THREADS
#define N_THREADS 16
#endif

#ifndef N_LOCKS
#define N_LOCKS 8
#endif

#ifndef N_OPS_PER_THREAD
#define N_OPS_PER_THREAD 200000
#endif

/* Op-mix percentages — must sum to 100. */
#define PCT_RD      70
#define PCT_WR      25
#define PCT_TRY_WR   5

struct lockslot {
    struct uwg_fxlock lk;
    /* holder_count: bumped on lock entry, decremented on unlock.
     * Under wrlock: must be exactly 1.
     * Under rdlock: must be >= 1.
     * Outside any lock: must be 0. */
    _Atomic int       holder_count;
    /* writer_marker: nonzero while a writer holds. Set to tid on
     * wrlock, cleared to 0 on wrunlock. Used by readers to detect
     * a writer slipping in (which would be an invariant violation
     * because rdlock guarantees writer_tid == 0 on return). */
    _Atomic int       writer_marker;
    /* shared_value: arbitrary protected field. Writers stamp their
     * tid+iter; readers verify two samples within the rdlock
     * window are equal. */
    _Atomic uint64_t  shared_value;
};

/* Pool of locks under contention. */
static struct lockslot pool[N_LOCKS];

/* Per-class violation counters — printed at end. */
static _Atomic int v_wr_holder_count;     /* holder_count != 1 under wr */
static _Atomic int v_wr_marker_seen;      /* writer_marker != my_tid under wr */
static _Atomic int v_rd_holder_count;     /* holder_count < 1 under rd */
static _Atomic int v_rd_writer_seen;      /* writer_marker != 0 under rd */
static _Atomic int v_rd_torn_read;        /* shared_value differed mid-rd */
static _Atomic int v_trywr_succeeded;     /* try_wr OK but holder_count > 1 */

/* Per-op-type counters — sanity-check for distribution. */
static _Atomic uint64_t c_rd, c_wr, c_try_wr_ok, c_try_wr_fail;

/* Lightweight per-thread PRNG (xorshift64*) — no libc dependency. */
static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static int my_tid_int(void) {
    /* gettid via raw syscall — same as the lock primitive uses. */
    return (int)uwg_fxlock_gettid();
}

static void *worker(void *arg) {
    int worker_idx = (int)(long)arg;
    int my_tid = my_tid_int();
    uint64_t prng = ((uint64_t)my_tid << 32) ^ ((uint64_t)worker_idx * 0x9E3779B97F4A7C15ull);

    for (int i = 0; i < N_OPS_PER_THREAD; i++) {
        int slot_idx = (int)(xorshift64(&prng) % N_LOCKS);
        struct lockslot *s = &pool[slot_idx];
        uint32_t pick = (uint32_t)(xorshift64(&prng) % 100);

        if (pick < PCT_RD) {
            /* rdlock + verify */
            int rc = uwg_fxlock_rdlock(&s->lk);
            if (rc != 0) {
                fprintf(stderr, "rdlock rc=%d slot=%d worker=%d\n", rc, slot_idx, worker_idx);
                abort();
            }
            int hc = atomic_fetch_add(&s->holder_count, 1) + 1;
            if (hc < 1) atomic_fetch_add(&v_rd_holder_count, 1);
            int wm = atomic_load(&s->writer_marker);
            if (wm != 0) atomic_fetch_add(&v_rd_writer_seen, 1);

            uint64_t v1 = atomic_load(&s->shared_value);
            /* Tiny user-space hold to widen the contention window. */
            for (volatile int j = 0; j < 4; j++) { (void)j; }
            uint64_t v2 = atomic_load(&s->shared_value);
            if (v1 != v2) atomic_fetch_add(&v_rd_torn_read, 1);

            atomic_fetch_sub(&s->holder_count, 1);
            uwg_fxlock_rdunlock(&s->lk);
            atomic_fetch_add(&c_rd, 1);

        } else if (pick < PCT_RD + PCT_WR) {
            /* wrlock + verify */
            int rc = uwg_fxlock_wrlock(&s->lk);
            if (rc != 0) {
                fprintf(stderr, "wrlock rc=%d slot=%d worker=%d\n", rc, slot_idx, worker_idx);
                abort();
            }
            int hc = atomic_fetch_add(&s->holder_count, 1) + 1;
            if (hc != 1) atomic_fetch_add(&v_wr_holder_count, 1);
            atomic_store(&s->writer_marker, my_tid);

            uint64_t marker = ((uint64_t)my_tid << 32) | (uint64_t)i;
            atomic_store(&s->shared_value, marker);
            for (volatile int j = 0; j < 4; j++) { (void)j; }
            int wm_check = atomic_load(&s->writer_marker);
            if (wm_check != my_tid) atomic_fetch_add(&v_wr_marker_seen, 1);

            atomic_store(&s->writer_marker, 0);
            atomic_fetch_sub(&s->holder_count, 1);
            uwg_fxlock_wrunlock(&s->lk);
            atomic_fetch_add(&c_wr, 1);

        } else {
            /* try_wrlock — non-retrying. */
            int rc = uwg_fxlock_try_wrlock(&s->lk);
            if (rc == UWG_FXLOCK_OK) {
                int hc = atomic_fetch_add(&s->holder_count, 1) + 1;
                if (hc != 1) atomic_fetch_add(&v_trywr_succeeded, 1);
                atomic_store(&s->writer_marker, my_tid);
                /* Brief hold to widen window. */
                for (volatile int j = 0; j < 4; j++) { (void)j; }
                atomic_store(&s->writer_marker, 0);
                atomic_fetch_sub(&s->holder_count, 1);
                uwg_fxlock_wrunlock(&s->lk);
                atomic_fetch_add(&c_try_wr_ok, 1);
            } else if (rc == UWG_FXLOCK_TRYFAIL) {
                atomic_fetch_add(&c_try_wr_fail, 1);
            } else {
                fprintf(stderr, "try_wr unexpected rc=%d\n", rc);
                abort();
            }
        }
    }
    return NULL;
}

int main(void) {
    for (int i = 0; i < N_LOCKS; i++) {
        struct uwg_fxlock zero = UWG_FXLOCK_INIT;
        pool[i].lk = zero;
        atomic_store(&pool[i].holder_count, 0);
        atomic_store(&pool[i].writer_marker, 0);
        atomic_store(&pool[i].shared_value, 0);
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    pthread_t threads[N_THREADS];
    for (long i = 0; i < N_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
            fprintf(stderr, "pthread_create %ld failed\n", i);
            abort();
        }
    }
    for (int i = 0; i < N_THREADS; i++) pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double)(t1.tv_sec - t0.tv_sec) +
                  (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    /* Final state must be quiescent. */
    int leftover_holders = 0, leftover_writers = 0;
    for (int i = 0; i < N_LOCKS; i++) {
        if (atomic_load(&pool[i].holder_count) != 0) leftover_holders++;
        if (atomic_load(&pool[i].writer_marker) != 0) leftover_writers++;
    }

    int v_total = atomic_load(&v_wr_holder_count) +
                  atomic_load(&v_wr_marker_seen) +
                  atomic_load(&v_rd_holder_count) +
                  atomic_load(&v_rd_writer_seen) +
                  atomic_load(&v_rd_torn_read) +
                  atomic_load(&v_trywr_succeeded) +
                  leftover_holders + leftover_writers;

    uint64_t total_ops = atomic_load(&c_rd) + atomic_load(&c_wr) +
                         atomic_load(&c_try_wr_ok) + atomic_load(&c_try_wr_fail);
    printf("threads=%d locks=%d ops/thread=%d total_ops=%llu wall=%.3fs throughput=%.0fK/s\n",
           N_THREADS, N_LOCKS, N_OPS_PER_THREAD,
           (unsigned long long)total_ops, secs,
           (double)total_ops / 1000.0 / secs);
    printf("rd=%llu wr=%llu try_wr_ok=%llu try_wr_fail=%llu\n",
           (unsigned long long)atomic_load(&c_rd),
           (unsigned long long)atomic_load(&c_wr),
           (unsigned long long)atomic_load(&c_try_wr_ok),
           (unsigned long long)atomic_load(&c_try_wr_fail));
    printf("violations: wr_holder=%d wr_marker=%d rd_holder=%d rd_writer=%d rd_torn=%d trywr_overlap=%d leftover_holders=%d leftover_writers=%d\n",
           atomic_load(&v_wr_holder_count),
           atomic_load(&v_wr_marker_seen),
           atomic_load(&v_rd_holder_count),
           atomic_load(&v_rd_writer_seen),
           atomic_load(&v_rd_torn_read),
           atomic_load(&v_trywr_succeeded),
           leftover_holders, leftover_writers);
    printf("RESULT %s\n", v_total == 0 ? "OK" : "FAIL");
    return v_total == 0 ? 0 : 1;
}
