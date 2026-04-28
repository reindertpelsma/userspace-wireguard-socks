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
#include "freestanding.h"
#include "freestanding_runtime.h"
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

/*
 * Per-process direct-indexed fast cache.
 *
 * The hash table in uwg_shared_state.tracked[] requires a global
 * rwlock acquire + linear probe per lookup. Under chromium-class
 * call rates (thousands of recvmsg/sec across many threads), that
 * locking is the dominant cost — and 99% of fds aren't tunnel-
 * managed (chromium has many internal pipes / eventfds / IPC
 * sockets), so almost every lookup is wasted work.
 *
 * The cache is a per-fd compact entry indexed by fd number directly
 * — instant lookup, no probing, no shared-state lock. For fds in
 * range, the hot fields (proxied, kind, saved_fl) come straight
 * from a one-byte atomic read. Cache misses (fd >= UWG_FD_CACHE_SIZE
 * or owner_pid mismatch) fall through to the existing slow path.
 *
 * Per-process: each process gets its own BSS-allocated cache. No
 * cross-process synchronization needed. Atomic stores ensure the
 * lock-free reads see consistent state.
 *
 * Configurable size: UWG_FD_CACHE_SIZE compile-time. Default 4096
 * covers the typical ulimit -n=1024 with headroom; cost is ~64KB
 * BSS per process. Bumping to 65536 costs ~1MB per process —
 * acceptable for low-process-count workloads, expensive for
 * chromium-class fork-heavy ones.
 */
#ifndef UWG_FD_CACHE_SIZE
#define UWG_FD_CACHE_SIZE 4096
#endif

/*
 * Per-fd race-safe cache.
 *
 * Each direct-indexed cache entry is paired with a futex-based rwlock
 * (preload/core/futex_rwlock.h). All cache reads acquire rdlock; all
 * cache writes acquire wrlock. This eliminates the torn-read class of
 * races where a writer mutates owner_pid + flags + saved_fl between
 * two atomic loads in the reader, and a stale combination is observed.
 *
 * The lock array is co-located in BSS and zero-initialized — that's
 * the lock's "no writer / no readers" state.
 *
 * Memory cost: one fxlock (24 bytes) per entry, plus the 16-byte cache
 * entry itself = 40 bytes per fd × UWG_FD_CACHE_SIZE (4096) = 160KB
 * BSS per process.
 *
 * Cache fields are now plain (non-atomic) — the lock provides ordering.
 */
struct uwg_fd_cache_entry {
    int32_t  owner_pid;          /* 0 = empty/invalid; pid = valid */
    uint16_t flags;              /* bit0=tracked, bit1=proxied, ... */
    uint16_t saved_fl;           /* raw O_NONBLOCK etc */
    uint32_t generation;         /* bumped on every store/clear */
    uint32_t reserved;           /* padding to 16 bytes */
};
_Static_assert(sizeof(struct uwg_fd_cache_entry) == 16,
               "fd cache entry must stay compact");

#define UWG_CACHE_F_TRACKED   0x0001u
#define UWG_CACHE_F_PROXIED   0x0002u
#define UWG_CACHE_F_HOT_READY 0x0020u
#define UWG_CACHE_KIND_SHIFT  2
#define UWG_CACHE_KIND_MASK   0x001Cu  /* bits 2-4 */

#include "futex_rwlock.h"

static struct uwg_fd_cache_entry uwg_fd_cache[UWG_FD_CACHE_SIZE];
static struct uwg_fxlock         uwg_fd_cache_lock[UWG_FD_CACHE_SIZE];

/* Set under wrlock. Stores the compact cache fields atomically (from
 * the reader's POV) because all readers go through rdlock. */
static inline void uwg_fd_cache_store_locked(int fd, int32_t pid,
                                             const struct tracked_fd *s) {
    /* Caller holds wrlock on uwg_fd_cache_lock[fd]. */
    struct uwg_fd_cache_entry *e = &uwg_fd_cache[fd];
    uint16_t flags = UWG_CACHE_F_TRACKED;
    if (s->proxied)   flags |= UWG_CACHE_F_PROXIED;
    if (s->hot_ready) flags |= UWG_CACHE_F_HOT_READY;
    flags |= (uint16_t)((s->kind & 0x7) << UWG_CACHE_KIND_SHIFT);
    e->generation++;
    e->flags     = flags;
    e->saved_fl  = (uint16_t)(s->saved_fl & 0xFFFF);
    e->owner_pid = pid;
}

/* Fast-path test: returns 1 if fd is DEFINITELY not tracked (cached
 * negative for current pid), 0 if caller must fall through to the
 * shared-hash slow path. Acquires per-fd rdlock so the read of
 * (owner_pid, flags) is consistent with the writer that last
 * populated the entry. */
static inline int uwg_fd_cache_negative(int fd, int32_t pid) {
    if (fd < 0 || fd >= UWG_FD_CACHE_SIZE) return 0;
    int rc = uwg_fxlock_rdlock(&uwg_fd_cache_lock[fd]);
    if (rc < 0) return 0; /* re-entrant or race — treat as miss */
    struct uwg_fd_cache_entry *e = &uwg_fd_cache[fd];
    int negative = 0;
    if (e->owner_pid == pid && !(e->flags & UWG_CACHE_F_TRACKED)) {
        negative = 1;
    }
    uwg_fxlock_rdunlock(&uwg_fd_cache_lock[fd]);
    return negative;
}

/* Public store wrapper that acquires its own wrlock. Called from
 * uwg_state_store after the shared hash table has been updated. */
static inline void uwg_fd_cache_store(int fd, int32_t pid,
                                      const struct tracked_fd *s) {
    if (fd < 0 || fd >= UWG_FD_CACHE_SIZE) return;
    int rc = uwg_fxlock_wrlock(&uwg_fd_cache_lock[fd]);
    if (rc < 0) return; /* re-entrant — caller is mid-write; skip */
    uwg_fd_cache_store_locked(fd, pid, s);
    uwg_fxlock_wrunlock(&uwg_fd_cache_lock[fd]);
}

/* Public negative-store wrapper (lookup found the fd not tracked).
 * Acquires its own wrlock. */
static inline void uwg_fd_cache_store_negative(int fd, int32_t pid) {
    if (fd < 0 || fd >= UWG_FD_CACHE_SIZE) return;
    int rc = uwg_fxlock_wrlock(&uwg_fd_cache_lock[fd]);
    if (rc < 0) return;
    struct uwg_fd_cache_entry *e = &uwg_fd_cache[fd];
    e->generation++;
    e->flags     = 0;
    e->saved_fl  = 0;
    e->owner_pid = pid;
    uwg_fxlock_wrunlock(&uwg_fd_cache_lock[fd]);
}

/* Cache invalidate: writer side of close/clear. Sets race_close so
 * any active reader sees the entry going away on its next look,
 * then takes wrlock and zeroes the entry. The race_close flag is
 * set BEFORE the wrlock so a concurrent reader that just finished
 * its rdunlock can observe the flag and treat the cache as miss. */
static inline void uwg_fd_cache_invalidate(int fd) {
    if (fd < 0 || fd >= UWG_FD_CACHE_SIZE) return;
    /* race_close: visible to any concurrent rdlock holder before they
     * unlock, so they know not to re-trust the entry. The flag is
     * cleared inside the wrlock below. */
    atomic_store_explicit(&uwg_fd_cache_lock[fd].race_close, 1,
                          memory_order_release);
    int rc = uwg_fxlock_wrlock(&uwg_fd_cache_lock[fd]);
    if (rc < 0) {
        /* Re-entrant write (same thread already holds wrlock). The
         * caller is in the middle of a write transaction; just clear
         * the entry directly — we already hold the lock. */
        struct uwg_fd_cache_entry *e = &uwg_fd_cache[fd];
        e->generation++;
        e->owner_pid = 0;
        e->flags     = 0;
        e->saved_fl  = 0;
        atomic_store_explicit(&uwg_fd_cache_lock[fd].race_close, 0,
                              memory_order_release);
        return;
    }
    struct uwg_fd_cache_entry *e = &uwg_fd_cache[fd];
    e->generation++;
    e->owner_pid = 0;
    e->flags     = 0;
    e->saved_fl  = 0;
    atomic_store_explicit(&uwg_fd_cache_lock[fd].race_close, 0,
                          memory_order_release);
    uwg_fxlock_wrunlock(&uwg_fd_cache_lock[fd]);
}

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
    /* Distinguish three slot states for proper open-addressing semantics:
     *
     *   TRULY EMPTY (owner == 0 && fd == 0)
     *     The initial state of every slot in zero-filled BSS / mmap.
     *     Under linear probing this is the lookup terminator: any matching
     *     entry would have been placed at or before this slot, so a
     *     lookup can break immediately. This is the fast-path for
     *     untracked fds (most chromium recvmsg targets) — without this,
     *     every lookup walked the full 65k-slot table.
     *
     *   TOMBSTONE (owner == -1 || fd == -1)
     *     Set by uwg_state_clear(). A lookup must continue scanning past
     *     a tombstone (the original entry might have collided and been
     *     placed later in the chain). An insert can reuse the first
     *     tombstone it finds.
     *
     *   OCCUPIED (owner > 0 && fd >= 0)
     *     Match by (pid, fd) pair.
     */
    for (size_t step = 0; step < MAX_TRACKED_SLOTS; step++) {
        size_t idx = (start + step) % MAX_TRACKED_SLOTS;
        struct tracked_slot *slot = &uwg_state->tracked[idx];
        int32_t owner = slot->owner_pid;
        int slot_fd = slot->fd;
        if (owner == pid && slot_fd == fd) {
            if (out_idx) *out_idx = idx;
            return 0;
        }
        int truly_empty = (owner == 0 && slot_fd == 0);
        int tombstone   = (owner == -1 || slot_fd == -1);
        if (truly_empty || tombstone) {
            if (free_idx < 0) free_idx = (int)idx;
        }
        if (truly_empty) {
            /* Lookup terminator under linear probing — no matching entry
             * can exist past this point. Break for both lookup AND
             * create paths (create reuses the empty slot via free_idx). */
            break;
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
    const char *path = NULL;
    for (char **e = uwg_environ; e && *e; e++) {
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

    /* Fast-path negative cache: most chromium fds aren't tunnel-managed
     * (internal pipes / eventfds / IPC sockets). The cache lets us
     * skip the global rwlock acquire + linear probe entirely. */
    if (uwg_fd_cache_negative(fd, pid)) return out;

    int32_t tid = uwg_current_tid();
    int found = 0;

    if (uwg_rwlock_rdlock(&uwg_state->lock, tid) != 0) {
        /* We already hold it as writer — read without re-entering
         * the lock since we already have exclusive access. */
        size_t idx;
        if (uwg_state_find_slot_locked(pid, fd, 0, &idx) == 0) {
            out = uwg_state->tracked[idx].state;
            found = 1;
        }
    } else {
        size_t idx;
        if (uwg_state_find_slot_locked(pid, fd, 0, &idx) == 0) {
            out = uwg_state->tracked[idx].state;
            found = 1;
        }
        uwg_rwlock_rdunlock(&uwg_state->lock);
    }

    /* Populate the cache so future lookups skip the slow path. */
    if (found) {
        uwg_fd_cache_store(fd, pid, &out);
    } else {
        uwg_fd_cache_store_negative(fd, pid);
    }
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
    /* Populate the per-process fast cache so subsequent lookups can
     * skip the global rwlock acquire. */
    if (rc == 0) uwg_fd_cache_store(fd, pid, state);
    return (rc == 0) ? 0 : -12; /* -ENOMEM */
}

/*
 * Clear: release the slot for (current_pid, fd). No-op if not present.
 */
void uwg_state_clear(int fd) {
    if (!uwg_state || fd < 0) return;

    int32_t pid = (int32_t)uwg_syscall0(SYS_getpid);
    int32_t tid = uwg_current_tid();

    /* Cache invalidate first so concurrent readers don't see a stale
     * "tracked" entry after we've cleared the shared slot. */
    uwg_fd_cache_invalidate(fd);
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
