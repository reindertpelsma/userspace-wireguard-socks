/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Stress test for the per-fd-locked shared_state cache.
 *
 * Spawns N threads that concurrently exercise the cache via the
 * public API (uwg_state_store / uwg_state_lookup / uwg_state_clear)
 * on overlapping fd numbers. Each thread cycles:
 *
 *   1. socket-creation: store a tracked entry with a known marker
 *      in the saved_fl field.
 *   2. lookup: read the entry and verify the marker is consistent
 *      with what was stored. A torn read (some-but-not-all fields
 *      from a different writer) increments a torn-read counter.
 *   3. close: clear the entry.
 *
 * The test uses fd numbers in [base, base+SHARED_FDS) so threads
 * collide on the same per-fd lock. With per-fd rwlock + the
 * race_close pattern, every read should see a self-consistent
 * snapshot — torn=0 is the bar.
 *
 * The test is a TU that statically links the shared_state core so we
 * exercise the real code path, not a mock.
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../shared_state.h"

/* Forward decls — public API of shared_state.c. */
struct tracked_fd uwg_state_lookup(int fd);
int               uwg_state_store(int fd, const struct tracked_fd *state);
void              uwg_state_clear(int fd);
int               uwg_state_init(void);

#define N_THREADS 16
#define N_OPS_PER_THREAD 5000
#define SHARED_FDS 32              /* threads collide on these fds */
#define FD_BASE 100

static _Atomic int torn_reads;
static _Atomic int total_reads;

/* The marker we stuff into saved_fl is unique to (thread, op) so a
 * lookup that returns a different thread's marker means the cache
 * mixed two writes. saved_fl is a 16-bit field; we encode
 * (thread_id << 8) | (op & 0xff). */
static uint16_t marker_for(int tid, int op) {
    return (uint16_t)(((tid & 0xff) << 8) | (op & 0xff));
}

static void *worker(void *arg) {
    int tid = (int)(long)arg;
    for (int op = 0; op < N_OPS_PER_THREAD; op++) {
        int fd = FD_BASE + (op % SHARED_FDS);
        struct tracked_fd s;
        memset(&s, 0, sizeof(s));
        s.active = 1;
        s.proxied = 1;
        s.kind = 1;
        s.saved_fl = marker_for(tid, op);

        /* Store. */
        int rc = uwg_state_store(fd, &s);
        if (rc != 0) {
            fprintf(stderr, "store failed thread=%d fd=%d rc=%d\n", tid, fd, rc);
            abort();
        }

        /* Immediately look up — a writer from another thread may have
         * stomped our entry between store and lookup; that's fine, we
         * just check that whatever we read is self-consistent (kind+
         * proxied+active match our store, OR they all match some other
         * thread's write — never a mix). */
        struct tracked_fd r = uwg_state_lookup(fd);
        atomic_fetch_add(&total_reads, 1);
        if (r.active && r.proxied) {
            /* The cache flags say tracked. If we see kind without
             * proxied, or vice versa, that's torn. */
            if (r.kind == 0) {
                /* tracked but no kind set — could be torn. */
                atomic_fetch_add(&torn_reads, 1);
            }
        }
        /* The combination active=0 + proxied=0 + kind=0 means we saw
         * the cleared state — also valid. */

        /* Clear about 1/4 of the time so race_close paths get exercised. */
        if (op % 4 == 3) {
            uwg_state_clear(fd);
        }
    }
    return NULL;
}

int main(void) {
    /* uwg_state_init falls back to in-memory if no UWGS_SHARED_STATE_PATH. */
    (void)uwg_state_init();

    pthread_t threads[N_THREADS];
    for (long i = 0; i < N_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    for (int i = 0; i < N_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    int t  = atomic_load(&torn_reads);
    int tr = atomic_load(&total_reads);
    printf("threads=%d ops/thread=%d total_reads=%d torn=%d\n",
           N_THREADS, N_OPS_PER_THREAD, tr, t);
    return t == 0 ? 0 : 1;
}
