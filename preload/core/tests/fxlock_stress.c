#define _GNU_SOURCE
#include "futex_rwlock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>

#define N_THREADS 32
#define N_OPS_PER_THREAD 100000

static struct uwg_fxlock lk = UWG_FXLOCK_INIT;
static _Atomic uint64_t shared_value;  // protected by lk
static _Atomic int wrong_value_count;

static void *worker(void *arg) {
    int tid = (int)(long)arg;
    for (int i = 0; i < N_OPS_PER_THREAD; i++) {
        // Mix of reads and writes
        if (i % 3 == 0) {
            // Write
            int rc = uwg_fxlock_wrlock(&lk);
            if (rc != 0) { printf("wrlock failed thread=%d rc=%d\n", tid, rc); abort(); }
            uint64_t marker = ((uint64_t)tid << 32) | (uint64_t)i;
            atomic_store(&shared_value, marker);
            // Briefly hold to expose races
            for (volatile int j = 0; j < 10; j++);
            // Verify nobody wrote in our window
            uint64_t check = atomic_load(&shared_value);
            if (check != marker) {
                atomic_fetch_add(&wrong_value_count, 1);
            }
            uwg_fxlock_wrunlock(&lk);
        } else {
            // Read
            int rc = uwg_fxlock_rdlock(&lk);
            if (rc != 0) { printf("rdlock failed thread=%d rc=%d\n", tid, rc); abort(); }
            uint64_t v1 = atomic_load(&shared_value);
            for (volatile int j = 0; j < 5; j++);
            uint64_t v2 = atomic_load(&shared_value);
            if (v1 != v2) {
                // Write happened during our read — race condition
                atomic_fetch_add(&wrong_value_count, 1);
            }
            uwg_fxlock_rdunlock(&lk);
        }
    }
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    for (long i = 0; i < N_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) abort();
    }
    for (int i = 0; i < N_THREADS; i++) pthread_join(threads[i], NULL);
    printf("threads=%d ops/thread=%d total=%d wrong=%d\n",
           N_THREADS, N_OPS_PER_THREAD, N_THREADS * N_OPS_PER_THREAD,
           atomic_load(&wrong_value_count));
    return wrong_value_count == 0 ? 0 : 1;
}
