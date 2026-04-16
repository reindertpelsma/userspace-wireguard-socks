/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#ifndef UWG_SHARED_STATE_H
#define UWG_SHARED_STATE_H

#include <sched.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#ifndef MAX_TRACKED_FD
#define MAX_TRACKED_FD 65536
#endif

#ifndef UWG_GUARD_SLOTS
#define UWG_GUARD_SLOTS 256
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
  int hot_ready;
  int bound;
  int reuse_addr;
  int reuse_port;
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
  _Atomic int32_t writer_tid;
};

struct uwg_guardlock {
  _Atomic uint32_t readers;
  _Atomic uint32_t writer;
  _Atomic int32_t writer_tid;
  uint32_t reserved;
  _Atomic int32_t reader_tids[UWG_GUARD_SLOTS];
};

static inline int uwg_rwlock_writer_owned_by(struct uwg_rwlock *lock,
                                             int32_t tid) {
  return atomic_load_explicit(&lock->writer, memory_order_acquire) != 0 &&
         atomic_load_explicit(&lock->writer_tid, memory_order_acquire) == tid;
}

static inline int uwg_rwlock_rdlock(struct uwg_rwlock *lock, int32_t tid) {
  for (;;) {
    if (uwg_rwlock_writer_owned_by(lock, tid))
      return -1;
    while (atomic_load_explicit(&lock->writer, memory_order_acquire) != 0)
      sched_yield();
    atomic_fetch_add_explicit(&lock->readers, 1, memory_order_acquire);
    if (atomic_load_explicit(&lock->writer, memory_order_acquire) == 0)
      return 0;
    atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
    if (uwg_rwlock_writer_owned_by(lock, tid))
      return -1;
  }
}

static inline void uwg_rwlock_rdunlock(struct uwg_rwlock *lock) {
  atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
}

static inline int uwg_rwlock_wrlock(struct uwg_rwlock *lock, int32_t tid) {
  for (;;) {
    if (uwg_rwlock_writer_owned_by(lock, tid))
      return -1;
    uint32_t expected = 0;
    if (atomic_compare_exchange_weak_explicit(
            &lock->writer, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      atomic_store_explicit(&lock->writer_tid, tid, memory_order_release);
      while (atomic_load_explicit(&lock->readers, memory_order_acquire) != 0)
        sched_yield();
      return 0;
    }
    sched_yield();
  }
}

static inline void uwg_rwlock_wrunlock(struct uwg_rwlock *lock) {
  atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
  atomic_store_explicit(&lock->writer, 0, memory_order_release);
}

#define UWG_SHARED_MAGIC 0x55574753u
#define UWG_SHARED_VERSION 5u

static inline int uwg_guard_hold_slot(struct uwg_guardlock *lock, int32_t tid) {
  for (size_t i = 0; i < UWG_GUARD_SLOTS; i++) {
    int32_t owner =
        atomic_load_explicit(&lock->reader_tids[i], memory_order_acquire);
    if (owner == tid)
      return 0;
    if (owner != 0)
      continue;
    int32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &lock->reader_tids[i], &expected, tid, memory_order_acq_rel,
            memory_order_acquire) ||
        expected == tid)
      return 0;
  }
  return -1;
}

static inline void uwg_guard_release_slot(struct uwg_guardlock *lock,
                                          int32_t tid) {
  for (size_t i = 0; i < UWG_GUARD_SLOTS; i++) {
    int32_t expected = tid;
    if (atomic_compare_exchange_strong_explicit(
            &lock->reader_tids[i], &expected, 0, memory_order_acq_rel,
            memory_order_acquire) ||
        atomic_load_explicit(&lock->reader_tids[i], memory_order_acquire) == 0)
      return;
  }
}

static inline void uwg_guard_rdlock(struct uwg_guardlock *lock, int32_t tid) {
  while (uwg_guard_hold_slot(lock, tid) != 0)
    sched_yield();
  for (;;) {
    while (atomic_load_explicit(&lock->writer, memory_order_acquire) != 0)
      sched_yield();
    atomic_fetch_add_explicit(&lock->readers, 1, memory_order_acquire);
    if (atomic_load_explicit(&lock->writer, memory_order_acquire) == 0)
      return;
    atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
  }
}

static inline void uwg_guard_rdunlock(struct uwg_guardlock *lock, int32_t tid) {
  atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
  uwg_guard_release_slot(lock, tid);
}

static inline void uwg_guard_wrlock(struct uwg_guardlock *lock, int32_t tid) {
  for (;;) {
    uint32_t expected = 0;
    if (atomic_compare_exchange_weak_explicit(
            &lock->writer, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      atomic_store_explicit(&lock->writer_tid, tid, memory_order_release);
      while (atomic_load_explicit(&lock->readers, memory_order_acquire) != 0)
        sched_yield();
      return;
    }
    sched_yield();
  }
}

static inline void uwg_guard_wrunlock(struct uwg_guardlock *lock) {
  atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
  atomic_store_explicit(&lock->writer, 0, memory_order_release);
}

struct uwg_shared_state {
  uint32_t magic;
  uint32_t version;
  uint64_t syscall_passthrough_secret;
  struct uwg_rwlock lock;
  struct uwg_guardlock guard;
  struct tracked_fd tracked[MAX_TRACKED_FD];
};

#endif
