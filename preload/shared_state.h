/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#ifndef UWG_SHARED_STATE_H
#define UWG_SHARED_STATE_H

#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

#ifndef MAX_TRACKED_FD
#define MAX_TRACKED_FD 65536
#endif

enum managed_kind {
  KIND_NONE = 0,
  KIND_TCP_STREAM = 1,
  KIND_UDP_CONNECTED = 2,
  KIND_UDP_LISTENER = 3,
  KIND_TCP_LISTENER = 4,
};

struct tracked_fd {
  int active;
  int domain;
  int type;
  int protocol;
  int proxied;
  int kind;
  int bound;
  int bind_family;
  uint16_t bind_port;
  char bind_ip[46];
  int remote_family;
  uint16_t remote_port;
  char remote_ip[46];
  int saved_fl;
  int saved_fdfl;
};

struct uwg_rwlock {
  _Atomic uint32_t readers;
  _Atomic uint32_t writer;
  uint32_t reserved;
};

static inline void uwg_rwlock_rdlock(struct uwg_rwlock *lock) {
  for (;;) {
    while (atomic_load_explicit(&lock->writer, memory_order_acquire) != 0)
      sched_yield();
    atomic_fetch_add_explicit(&lock->readers, 1, memory_order_acquire);
    if (atomic_load_explicit(&lock->writer, memory_order_acquire) == 0)
      return;
    atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
  }
}

static inline void uwg_rwlock_rdunlock(struct uwg_rwlock *lock) {
  atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
}

static inline void uwg_rwlock_wrlock(struct uwg_rwlock *lock) {
  for (;;) {
    uint32_t expected = 0;
    if (atomic_compare_exchange_weak_explicit(
            &lock->writer, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      while (atomic_load_explicit(&lock->readers, memory_order_acquire) != 0)
        sched_yield();
      return;
    }
    sched_yield();
  }
}

static inline void uwg_rwlock_wrunlock(struct uwg_rwlock *lock) {
  atomic_store_explicit(&lock->writer, 0, memory_order_release);
}

#define UWG_SHARED_MAGIC 0x55574753u
#define UWG_SHARED_VERSION 1u

struct uwg_shared_state {
  uint32_t magic;
  uint32_t version;
  uint64_t syscall_passthrough_secret;
  struct uwg_rwlock lock;
  struct tracked_fd tracked[MAX_TRACKED_FD];
};

#endif
