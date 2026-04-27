/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Shared state mmap consumer for the SIGSYS dispatch path.
 *
 * The Go wrapper (uwgwrapper) creates a file at UWGS_SHARED_STATE_PATH
 * and mmap-shared with the wrapped process. The file's layout is the
 * `struct uwg_shared_state` defined in preload/shared_state.h, which is
 * the canonical ABI between Go (internal/uwgshared) and C (preload/).
 *
 * This file is the freestanding-safe core of the table operations:
 *   - uwg_state_init()         — mmap the file, validate magic/version
 *   - uwg_state_lookup(fd)     — look up a tracked_fd by fd, returns
 *                                 a stack-local snapshot (atomic-safe
 *                                 read; uses the rwlock from
 *                                 shared_state.h).
 *   - uwg_state_store(fd, &s)  — store a tracked_fd state for fd.
 *   - uwg_state_clear(fd)      — release a tracked slot.
 *
 * Async-signal-safety:
 *   - uwg_state_init() must be called BEFORE the seccomp filter is
 *     installed (init time, not signal time). It uses open() and
 *     mmap() which are not safe from signal context.
 *   - uwg_state_lookup / store / clear ARE safe from signal context
 *     because they use only:
 *       * atomic loads/stores via stdatomic.h (lock-free on x86_64
 *         and aarch64 for the data sizes we use)
 *       * the rwlock primitives from shared_state.h (themselves
 *         atomic + sched_yield, which is on the POSIX async-signal-
 *         safe list)
 *       * NO malloc/realloc/free
 *       * NO libc functions other than memset (compiler-emitted,
 *         freestanding-safe).
 *
 *   The reconciliation logic in the existing uwgpreload.c (which
 *   uses realloc and pthread_once) is NOT lifted here. The wrapper-
 *   side launcher will run reconciliation at init time, before
 *   handing off to the wrapped process. Inside the wrapped process
 *   we treat the table as authoritative.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"

/* In-memory fallback when no shared-state file is available — what
 * makes phase1.so work as a drop-in replacement for the legacy preload.
 *
 * Declared without explicit initializers so the entire 10MB struct
 * (mostly the 65K-slot tracked[] array) lives in .bss instead of
 * .data; otherwise the .so balloons by ~10MB on disk. The few fields
 * that need non-zero defaults (magic/version) get populated at first
 * lookup via the lazy_local_init helper below. */
static struct uwg_shared_state uwg_state_local;
static struct uwg_shared_state *uwg_state = &uwg_state_local;
static _Atomic int uwg_state_local_inited;

static void lazy_local_init(void) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &uwg_state_local_inited, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        uwg_state_local.magic = UWG_SHARED_MAGIC;
        uwg_state_local.version = UWG_SHARED_VERSION;
    }
}

/* Initialization guard. CAS-based — async-signal-safe. */
static _Atomic int uwg_state_init_state; /* 0=unstarted, 1=in-progress, 2=done */

/* Cached tid lookup. gettid is its own syscall and is async-signal-safe. */
static int32_t uwg_current_tid(void) {
    return (int32_t)uwg_syscall0(SYS_gettid);
}

/*
 * Hash function for (pid, fd) pairs. Identical to the one in
 * uwgpreload.c so the C and Go sides agree on slot placement.
 */
static uint32_t uwg_state_hash(int32_t pid, int fd) {
    uint32_t h = (uint32_t)pid * 2654435761u;
    h ^= (uint32_t)fd * 0x9E3779B1u;
    h ^= h >> 16;
    return h % MAX_TRACKED_SLOTS;
}

/*
 * Slot-finder. Walks the table from hash(pid,fd) doing linear probe.
 * Caller must hold the appropriate lock (rd or wr).
 *
 * If `create` is set and no slot exists, allocates a free slot and
 * returns its index. If `create` is unset and no slot exists, returns -1.
 */
static int uwg_state_find_slot_locked(int32_t pid, int fd, int create,
                                      size_t *out_idx) {
    if (!uwg_state) return -1;
    uint32_t start = uwg_state_hash(pid, fd);
    int free_idx = -1;
    for (size_t step = 0; step < MAX_TRACKED_SLOTS; step++) {
        size_t idx = (start + step) % MAX_TRACKED_SLOTS;
        struct tracked_slot *slot = &uwg_state->tracked[idx];
        int32_t owner = slot->owner_pid;
        int slot_fd = slot->fd;
        if (owner == pid && slot_fd == fd) {
            if (out_idx) *out_idx = idx;
            return 0;
        }
        if (owner == 0 || owner == -1 || slot_fd == -1) {
            if (free_idx < 0) free_idx = (int)idx;
            /* Don't break — keep searching for an existing entry. */
        }
    }
    if (create && free_idx >= 0) {
        struct tracked_slot *slot = &uwg_state->tracked[free_idx];
        slot->owner_pid = pid;
        slot->fd = fd;
        memset(&slot->state, 0, sizeof(slot->state));
        if (out_idx) *out_idx = (size_t)free_idx;
        return 0;
    }
    return -1;
}

int uwg_state_init(void) {
    /* Single-init guard via CAS. */
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &uwg_state_init_state, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        /* Another thread is initializing or already done. Spin until
         * done — sched_yield is async-signal-safe. */
        while (atomic_load_explicit(&uwg_state_init_state,
                                    memory_order_acquire) != 2) {
            (void)uwg_syscall0(SYS_sched_yield);
        }
        return uwg_state ? 0 : -19; /* -ENODEV if init failed */
    }

    /* We're the initializer. Find the path. */
    extern char **environ;
    const char *path = NULL;
    for (char **e = environ; e && *e; e++) {
        const char *s = *e;
        if (strncmp(s, "UWGS_SHARED_STATE_PATH=", 23) == 0) {
            path = s + 23;
            break;
        }
    }
    if (!path || !*path) {
        /* No shared file → keep the static fallback (uwg_state already
         * points at uwg_state_local). Lazy-init magic/version so a
         * later mmap-mismatch check still sees a valid table. */
        lazy_local_init();
        atomic_store_explicit(&uwg_state_init_state, 2, memory_order_release);
        return 0;
    }

    long fd = uwg_syscall3(SYS_openat, -100 /* AT_FDCWD */,
                           (long)path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        atomic_store_explicit(&uwg_state_init_state, 2, memory_order_release);
        return (int)fd;
    }

    /* MAP_SHARED so writes propagate between Go side and us. */
    long mm = uwg_syscall6(SYS_mmap, 0, sizeof(struct uwg_shared_state),
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    (void)uwg_syscall1(SYS_close, fd);
    if (mm < 0) {
        atomic_store_explicit(&uwg_state_init_state, 2, memory_order_release);
        return (int)mm;
    }

    struct uwg_shared_state *s = (struct uwg_shared_state *)mm;
    if (s->magic != UWG_SHARED_MAGIC || s->version != UWG_SHARED_VERSION) {
        (void)uwg_syscall2(SYS_munmap, mm, sizeof(*s));
        atomic_store_explicit(&uwg_state_init_state, 2, memory_order_release);
        return -22; /* -EINVAL — magic/version mismatch */
    }

    uwg_state = s;
    atomic_store_explicit(&uwg_state_init_state, 2, memory_order_release);
    return 0;
}

/*
 * Snapshot: read-only lookup. Returns a stack-local copy of
 * `struct tracked_fd`. Caller can inspect fields without further
 * locking since the copy is local.
 *
 * If no slot exists OR the table isn't mapped, returns a zeroed
 * struct (all fields 0 → caller will see active=0, proxied=0,
 * kind=KIND_NONE → "not a tunnel fd, pass through").
 */
struct tracked_fd uwg_state_lookup(int fd) {
    struct tracked_fd out;
    memset(&out, 0, sizeof(out));
    if (!uwg_state || fd < 0) return out;

    int32_t pid = (int32_t)uwg_syscall0(SYS_getpid);
    int32_t tid = uwg_current_tid();

    if (uwg_rwlock_rdlock(&uwg_state->lock, tid) != 0) {
        /* We already hold it as writer — read without re-entering
         * the lock since we already have exclusive access. */
        size_t idx;
        if (uwg_state_find_slot_locked(pid, fd, 0, &idx) == 0) {
            out = uwg_state->tracked[idx].state;
        }
        return out;
    }
    size_t idx;
    if (uwg_state_find_slot_locked(pid, fd, 0, &idx) == 0) {
        out = uwg_state->tracked[idx].state;
    }
    uwg_rwlock_rdunlock(&uwg_state->lock);
    return out;
}

/*
 * Store: write a tracked_fd state for (current_pid, fd). Allocates
 * a slot if necessary. Returns 0 on success, -ENOMEM if the table
 * is full, -ENODEV if not mapped.
 */
int uwg_state_store(int fd, const struct tracked_fd *state) {
    if (!uwg_state) return -19;
    if (fd < 0) return -22;

    int32_t pid = (int32_t)uwg_syscall0(SYS_getpid);
    int32_t tid = uwg_current_tid();

    int reentrant = uwg_rwlock_wrlock(&uwg_state->lock, tid) != 0;
    /* If reentrant we already hold the writer lock from a higher
     * frame; either way we have exclusive access at this point. */

    size_t idx;
    int rc = uwg_state_find_slot_locked(pid, fd, 1, &idx);
    if (rc == 0) {
        uwg_state->tracked[idx].state = *state;
    }

    if (!reentrant) uwg_rwlock_wrunlock(&uwg_state->lock);
    return (rc == 0) ? 0 : -12; /* -ENOMEM */
}

/*
 * Clear: release the slot for (current_pid, fd). No-op if not present.
 */
void uwg_state_clear(int fd) {
    if (!uwg_state || fd < 0) return;

    int32_t pid = (int32_t)uwg_syscall0(SYS_getpid);
    int32_t tid = uwg_current_tid();

    int reentrant = uwg_rwlock_wrlock(&uwg_state->lock, tid) != 0;
    size_t idx;
    if (uwg_state_find_slot_locked(pid, fd, 0, &idx) == 0) {
        uwg_state->tracked[idx].owner_pid = -1;
        uwg_state->tracked[idx].fd = -1;
        memset(&uwg_state->tracked[idx].state, 0,
               sizeof(uwg_state->tracked[idx].state));
    }
    if (!reentrant) uwg_rwlock_wrunlock(&uwg_state->lock);
}

/* The state pointer + secret read at init are accessible to the
 * rest of core via these helpers. */
const struct uwg_shared_state *uwg_state_ptr(void) { return uwg_state; }

uint64_t uwg_state_secret(void) {
    return uwg_state ? uwg_state->syscall_passthrough_secret : 0;
}
