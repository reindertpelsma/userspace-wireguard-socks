<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Lock map — `internal/fdproxy` and `preload/uwgpreload.c`

Internal reference. Read this before changing anything that touches a
mutex in either file. The two files share state via `mmap`, so the
locking story spans a process boundary and a language boundary; getting
the matrix right is the whole job.

Companion docs:
[overview](README.md) · [security-conventions](security-conventions.md).

If you add a new lock, add it here in the same shape. If you find a site
this doc doesn't list, the site is wrong, the doc is stale, or both —
either way fix it.

## TL;DR

There are **5 locks** total. Two live in Go (`internal/fdproxy/fdproxy.go`),
three live in shared C-mappable memory (`preload/shared_state.h`,
acquired from both the preload `.so` and any reader of the mmap region).

| # | Name | Type | Where | Covers | Lock order |
|---|---|---|---|---|---|
| 1 | `Server.mu` | `sync.Mutex` (Go) | `Server` | server-level maps: `tcpMembers`, `tcpGroups`, `udpGroups`; `nextID` (also via atomic) | OUTER. Acquired before `g.mu`. |
| 2 | `tcpListenerGroup.mu` / `udpListenerGroup.mu` | `sync.Mutex` (Go) | each `*ListenerGroup` | per-group: `members`, `order`, `accepts`, `peerOwner`, `peerLRU`, `replyBind`, `up`, `loop`, `dummy` | INNER. Acquired while holding `Server.mu` is allowed. The reverse is forbidden. |
| 3 | `tcpListenerGroup.writeMu` / `udpListenerGroup.writeMu` | `sync.Mutex` (Go) | each `*ListenerGroup` | serializes upstream-frame writes (`g.up.Write`) | LEAF. Never held while taking any other lock. |
| 4 | `uwg_shared_state.lock` (`uwg_rwlock`) | rwlock in mmap (C atomics) | `preload/shared_state.h` | the entire `tracked[]` table — every `tracked_slot` (and its embedded `tracked_fd`) | The "tracked-table" lock. Held by exactly one writer, or N readers, across the preload `.so` *AND* any other process mapping the region (the manager). |
| 5 | `uwg_shared_state.guard` (`uwg_guardlock`) | rwlock-with-reader-list in mmap (C atomics) | `preload/shared_state.h` | the "hot path" guard — acquired around fast-path syscalls so the slow path can stop the world to mutate `tracked[]` | Independent of #4. Always read-acquired before doing fast-path work; write-acquired by reconciliation paths that need an exclusive snapshot. |

Atomic-only state (no mutex needed):
- `Server.nextID` — `atomic.AddUint64`
- `tcpListenerGroup.next` — `atomic.AddUint64`
- All `_Atomic` fields inside `uwg_rwlock` and `uwg_guardlock` — by definition

Channels used as one-shot signals (close-only, never send-after-close):
- `Server` Listener Close: closes underlying `net.UnixListener`
- `tcpListenerMember.closed`, `tcpListenerGroup.closed`, `udpListenerGroup.closed` — closed exactly once via the `sync.Once`-equivalent pattern (select-default in the close path)

---

## Lock 1 — `Server.mu` (`sync.Mutex`)

**Declared:** `fdproxy.go:68`

**Covers:**
- `s.tcpMembers map[string]*tcpListenerMember`
- `s.tcpGroups map[string]*tcpListenerGroup`
- `s.udpGroups map[string]*udpListenerGroup`
- (`s.nextID` is `atomic.Uint64`, no lock needed for it)

**Acquired at:** (every `s.mu.Lock()` / `defer s.mu.Unlock()` site)

| Line | Function | Pattern | Releases at |
|---|---|---|---|
| 242 | `Server.Close` | Lock | 251 (Unlock) |
| 420 | `Server.localConn` | Lock | 422 (Unlock) |
| 547 | `Server.addTCPListenerMember` (existing-group branch) | Lock | 562 (Unlock — early return after publishing member) |
| 547 | `Server.addTCPListenerMember` (early reject branch) | Lock | 551 (Unlock — early return EADDRINUSE) |
| 547 | `Server.addTCPListenerMember` (new-group branch) | Lock | 584 (Unlock — before calling `group.start(req)` which must NOT hold s.mu) |
| 1052 | `Server.addUDPListenerMember` (existing-group branch) | Lock | 1061 (Unlock) |
| 1052 | `Server.addUDPListenerMember` (early reject branch) | Lock | 1056 (Unlock — EADDRINUSE) |
| 1052 | `Server.addUDPListenerMember` (new-group branch) | Lock | 1077 (Unlock — before `group.start(req)`) |
| 741 | `tcpListenerGroup.removeMember` | Lock | 743 (Unlock) — short critical section to delete from `tcpMembers` only |
| 792 | `tcpListenerGroup.close` | Lock | 799 (Unlock) — delete group from `tcpGroups`, members from `tcpMembers` |
| 1328 | `udpListenerGroup.removeMember` | Lock | 1335 (Unlock) — paired with g.mu inside |
| 1369 | `udpListenerGroup.close` | Lock | 1373 (Unlock) — delete group from `udpGroups` |

**Release patterns to be careful about:**
- `addTCPListenerMember` and `addUDPListenerMember` deliberately publish the new group to `s.tcpGroups`/`s.udpGroups` BEFORE releasing `s.mu`, then call `group.start()` AFTER releasing it. This is intentional — `start()` does network I/O and must not hold a coarse mutex. The race that this used to cause (`replyBind` written by `start()` without lock, read by a concurrent second arrival under `s.mu` only) was fixed by gating `replyBind` reads/writes under `g.mu` via `setReplyBind`/`getReplyBind`.

**Lock order:**
- May be acquired at the top of a chain: `s.mu → g.mu` is allowed.
- May NOT be acquired while holding `g.mu`: that would create the reverse `g.mu → s.mu` order and deadlock with `addMemberLocked` and `removeMember`.
- `g.close()` looks like it violates this — at line 779 it takes `g.mu`, releases it at 790, *then* takes `g.server.mu` at 792. That's release-then-acquire, not nested, so no deadlock. **Don't refactor this** without proving no caller holds `g.mu` at entry.

---

## Lock 2 — `tcpListenerGroup.mu` and `udpListenerGroup.mu` (`sync.Mutex`)

**Declared:** `fdproxy.go:107` (TCP), `fdproxy.go:139` (UDP)

**Covers (TCP group):**
- `g.members map[string]*tcpListenerMember`
- `g.order []string`
- `g.accepts map[uint64]*tcpAcceptedConn`
- `g.replyBind` (via `setReplyBind`/`getReplyBind`)
- `g.up`, `g.loop`, `g.dummy`, `g.allowLoopback`, `g.allowTunnel`

**Covers (UDP group):**
- `g.members map[string]net.Conn`
- `g.order []string`
- `g.peerOwner map[string]udpPeerOwnerEntry`
- `g.peerLRU []udpPeerOwnerStamp`
- `g.peerSeq` (only mutated under g.mu)
- `g.replyBind` (via setters)
- `g.up`, `g.loop`, `g.dummy`, `g.allowLoopback`, `g.allowTunnel`

**TCP `g.mu` sites:**

| Line | Function | Notes |
|---|---|---|
| 712-714 | `addMemberLocked` | Name is misleading — it acquires `g.mu` itself; "Locked" historically meant "called while holding s.mu". Caller does hold `s.mu`, but `g.mu` is acquired *here*. |
| 723-725 | `setReplyBind` | Writer-side of the replyBind race fix |
| 729-731 | `getReplyBind` | Reader-side |
| 745-757 | `removeMember` (member-deletion path) | Read+delete from `members`, splice from `order`, count remaining. Caller does NOT hold s.mu (already released at line 743). |
| 779-790 | `close` (drain path) | Reads members + accepts under `g.mu`, releases before calling `g.server.mu` (lock 1) for the parent-map cleanup |
| 903-905 | `serveLoopback` | Read `len(g.members)` and `g.dummy` for the per-iteration check |
| 921-922 | `pickMember` (defer) | round-robin over `g.order` |
| 940-941 | `registerAccepted` (defer) | insert into `g.accepts` |
| 956-971 | `attach` | five separate Unlock points for each early-error branch |
| 1017-1021 | `closeAccepted` | read+delete from `g.accepts` |
| 1037-1039 | `removeAccepted` | delete from `g.accepts` |

**UDP `g.mu` sites:**

| Line | Function | Notes |
|---|---|---|
| 1088-1090 | `setReplyBind` | Writer |
| 1094-1095 | `getReplyBind` (defer) | Reader |
| 1100-1101 | `addMemberLocked` (defer) | Same naming caveat as TCP |
| 1263-1265 | `serveLoopback` | Read `len(g.members)` and `g.dummy` |
| 1284-1285 | `randomMemberToken` (defer) | random pick from `g.order` |
| 1300-1314 | `recordPeerOwner` | Insert into `peerOwner`, append to `peerLRU`, evict LRU when at cap |
| 1318-1319 | `ownerFor` (defer) | Lookup peerOwner |
| 1329-1334 | `removeMember` (sole-member-empty-check path) | **Acquired while holding `s.mu`** — this is the only place where the s.mu→g.mu nesting actually happens. Lock order is enforced: `s.server.mu.Lock()` at 1328, `g.mu.Lock()` at 1329, `g.mu.Unlock()` at 1334, `s.server.mu.Unlock()` at 1335. |
| 1337-1353 | `removeMember` (member-deletion path) | Same shape as TCP — caller no longer holds `s.mu` here |
| 1380-1385 | `close` | Drain `members` and `peerOwner`, release before parent-map cleanup |

**Lock order:**
- May be acquired while holding `s.mu` (the sole nested case is `udpListenerGroup.removeMember` line 1328-1335). All others acquire `g.mu` standalone.
- May NOT be acquired while holding `g.writeMu` (that would invert the lock order vs. send paths).
- May NOT acquire `s.mu` while holding `g.mu` (deadlock).

---

## Lock 3 — `tcpListenerGroup.writeMu` and `udpListenerGroup.writeMu` (`sync.Mutex`)

**Declared:** `fdproxy.go:105` (TCP), `fdproxy.go:137` (UDP)

**Covers:**
- Serializes writes to `g.up` so framed protocol bytes don't interleave on the wire when multiple goroutines have a pending frame.

**Acquired at:**

| Line | Function | Pattern |
|---|---|---|
| 1008-1009 | `tcpListenerGroup.sendFrame` (defer) | Lock + defer Unlock around `socketproto.WriteFrame` |
| 1193-1195 | `udpListenerGroup.serveMember` (per-frame write) | Lock just around the WriteFrame call |

**Lock order:** **LEAF.** Held only briefly around an I/O call. Never acquired while holding `g.mu` or `s.mu`; never acquires either of them. Take it last, release it first. If you find yourself wanting to acquire `g.mu` from inside a `writeMu`-held section, restructure — likely you should release `writeMu` first.

---

## Lock 4 — `uwg_shared_state.lock` (`uwg_rwlock`, in mmap'd memory)

**Declared:** `preload/shared_state.h:61` (`struct uwg_rwlock`); the live instance is at `shared_state->lock` (`shared_state.h:197`).

**Implementation:** custom rwlock built on three `_Atomic` fields:
- `readers` (uint32) — count of in-flight readers
- `writer` (uint32) — 0/1 flag
- `writer_tid` (int32) — TID of the holding writer, used for reentrancy detection

**Covers:**
- The whole `tracked[MAX_TRACKED_SLOTS]` array. Every read or mutation of any `struct tracked_slot` (and its embedded `tracked_fd`) must hold this lock in the right mode.

**Acquired from C / preload:**

The Go-side `uwgsocks` daemon does NOT acquire this lock. The lock is shared between the preload `.so` (the wrapped app's process) and any reader that mmaps the same region — typically only the preload itself. The manager (uwgsocks daemon) reaches the wrapped app's tunnel state via the fdproxy Unix socket protocol, not by reading shared memory. So lock 4 is intra-process across threads of the wrapped app.

| Line | Function | Mode |
|---|---|---|
| 912 | `uwgpreload.c: ensure_shared_state_writer` | wrlock |
| 929 | `uwgpreload.c: ensure_shared_state_writer` (release) | wrunlock |
| 934 | `uwgpreload.c: ensure_shared_state_writer` (retry) | wrlock |
| 942 | (release) | wrunlock |
| 1041 | `tracked_rdlock()` | rdlock |
| 1053-1054 | `tracked_wrlock()` | wrlock with reentry detection |
| 1065 | (rd→wr promotion failure path) | rdunlock |
| 1072 | `tracked_wrunlock()` | wrunlock |
| 1126 | bind path | wrlock |
| 1148 | listen path | rdlock |
| 1173 | accept path | wrlock |
| 1198 | connect path | wrlock |
| 1214 | another mutator | wrlock |

**Lock order:**
- INDEPENDENT of the Go-side locks (different process, different memory). Cannot be held alongside any Go mutex because Go threads never take it.
- Reentrancy: `uwg_rwlock_writer_owned_by(lock, tid)` returns 1 when the same TID has the write lock; both `rdlock` and `wrlock` return -1 immediately rather than deadlocking. Callers MUST handle the -1 return.

**Crash semantics — the load-bearing risk:**
- This lock has NO kernel-mediated owner-death notification (unlike Linux robust futexes with `FUTEX_OWNER_DIED`).
- If the preload thread holding the write lock crashes (segfault, OOM kill, signal), the lock is **permanently stuck**. Any subsequent reader or writer in the same process spins forever in the `sched_yield()` loop.
- **fork() considerations:** the lock state is in the mmap region with `MAP_SHARED`, so a `fork()` in the wrapped app reproduces the lock state exactly. If the parent held the write lock at fork time, both processes now think they hold it. The `pthread_atfork` hook in `uwgpreload.c:232` calls `atfork_child_reset` to scrub local state, but it CANNOT undo a held shared lock — that would require the parent to release first.
- **Currently no test covers** the "preload dies holding the lock" scenario. Add one (see Phase 4 in the audit plan).

---

## Lock 5 — `uwg_shared_state.guard` (`uwg_guardlock`, in mmap'd memory)

**Declared:** `preload/shared_state.h:67` (`struct uwg_guardlock`); the live instance is at `shared_state->guard` (`shared_state.h:198`).

**Implementation:** more elaborate than lock 4 — adds an array of reader TIDs (`reader_tids[UWG_GUARD_SLOTS]`, 256 slots) so the writer can identify which threads are still in the read section. Same atomic primitives.

**Covers:**
- The "hot path" — the fast preload functions that the wrapped app calls many times per second (socket(2), connect(2), etc.). Acquired in read mode around hot-path inspection of `tracked_fd` state. Acquired in write mode by reconciliation paths that need an exclusive snapshot of all hot-path readers (so it can stop them before mutating `tracked[]`).

**Acquired at (preload):**

| Line | Mode | Purpose |
|---|---|---|
| 1920 | `hot_path_rdlock()` | hot-path syscall enters fast section |
| 1925 | `hot_path_wrlock()` | promote when hot path needs to mutate |
| 1966 | `hot_path_wrlock()` | mutator path |
| 1986 | `hot_path_rdlock()` | hot path read |
| 2011 | `hot_path_wrlock()` | mutator |

**Lock order:**
- Independent of lock 4 in the abstract, but in practice many call sites take **lock 4 (tracked) THEN lock 5 (guard)** when they need to update tracked state and signal the hot path. The reverse order does NOT appear in code; if you add a site that goes guard → tracked, document why or restructure.
- Same crash-safety concern as lock 4: no kernel owner-death notification.

---

## What lives outside any lock (and why it's safe)

- **`Server.nextID` / `tcpListenerGroup.next`**: `atomic.AddUint64`. Monotonic ID generators with no other invariants.
- **`Server.allowedUIDs map[uint32]struct{}`**: written exactly once during `ListenWithOptions` before the goroutine that calls `Serve` is started, then read-only thereafter. Safe via happens-before of goroutine creation. **If you ever add a "modify allowed UIDs at runtime" feature, this map needs a mutex.**
- **`Server.ownUID`**: same — set once at construction, never mutated.
- **`tcpListenerMember.closed`, `tcpListenerGroup.closed`, `udpListenerGroup.closed`**: `chan struct{}` used as one-shot signals. Closed once via select-default pattern (`fdproxy.go:746-749`, `:786-792`, `:1376-1378`); reads via `<-ch` to test closure. Safe by Go's channel-close memory model.

## State assumptions across unlock / relock — the ABA class

A whole bug class lives in functions that hold a lock, mutate state,
release the lock to do I/O, then re-acquire the lock and assume the
state is still what it was. **It usually isn't.**

The dangerous shape:

```go
g.mu.Lock()
member := g.members[token]
g.mu.Unlock()

// Some I/O against `member`:
n, err := member.local.Write(buf)

g.mu.Lock()
// ⚠️ DANGEROUS: `member` may have been removed and the slot reused.
// `g.members[token]` may even point at a different *tcpListenerMember now.
g.mu.Unlock()
```

The classic version is the **fd-table-reuse / ABA race**:

1. Thread 1 locks, reads slot `N` → fd `X`, unlocks for I/O.
2. Thread 2 locks, removes slot `N` (closes fd `X`), unlocks.
3. Thread 3 locks, reclaims slot `N` for a brand-new fd `Y`, unlocks.
4. Thread 1 re-locks, sees slot `N` is non-empty, *assumes it is still
   fd `X`* — but it is fd `Y`. Operates on the wrong socket.

The token is the same. The slot index is the same. The pointer might
even be the same after Go reuses memory. The thing the pointer
*describes* is different. No race detector catches this because no
field is concurrently read+written; the bug is at the **identity
level**, not the memory level.

**Defenses we use:**

- **Per-entry generation counters.** When a slot is reused, the
  generation increments. Holders read the generation alongside the
  pointer; if the generation has moved when they re-lock, they bail.
  We don't yet use this in fdproxy; flagged below as a follow-up.
- **Avoid the pattern entirely.** Prefer "do all the lookup + decision
  + mutation under one lock acquisition, only do I/O after with a
  *copy* of the data you need". Most fdproxy functions follow this
  rule — `pickMember`, `recordPeerOwner`, `attach` all decide under
  the lock and act with a closed-over local.
- **Treat tokens as opaque + revalidate.** When a function unavoidably
  has to relock, it must re-look-up the token in the map and accept
  that the result may be `nil` or a different pointer. Never reuse a
  cached pointer across an unlock.

**Functions in fdproxy that mix locks and I/O — re-audit when you
change them:**

| Line | Function | Pattern | Notes |
|---|---|---|---|
| 745-757 | `tcpListenerGroup.removeMember` | locks → reads + mutates → unlocks → calls `member.local.Close()` | Safe: close happens on a `member` snapshot; map state already updated. |
| 779-799 | `tcpListenerGroup.close` | locks → drains members map into local → unlocks → closes each → relocks server.mu briefly | Safe: drain-into-local is the right pattern. |
| 866-918 | `tcpListenerGroup.serveUpstream` | reads frames from `g.up`, then takes `g.mu` to dispatch | Outer loop is I/O without the lock; per-frame critical section is short. Re-audit if frame parsing grows. |
| 989-1015 | `tcpListenerGroup.readAttached` | streams bytes from a local conn to upstream; takes `g.writeMu` per frame | `g.writeMu` only — no `g.mu` interaction, so no ABA on group state. |
| 1167-1200 | `udpListenerGroup.serveMember` | reads from local, takes `g.writeMu` per write | Same — `writeMu` is leaf-only. |
| 1252-1281 | `udpListenerGroup.dispatchDatagram` | takes `g.mu` to look up owner, releases, sends via `g.up.Write` | **Higher risk:** if `g.up` is closed concurrently we may write to a stale conn. Mitigated because `g.up.Close()` makes Write return EBADF, which the caller treats as the connection ending. Acceptable today; revisit if `g.up` ever becomes hot-swappable. |

**The general rule for new code:**

> If a function takes a lock more than once, it must NOT assume any
> state observed under the first acquisition is still valid at the
> second. Either (a) hold the lock for the whole sequence, (b) carry
> a snapshot of everything you need across the unlock, or (c) revalidate
> identity (generation counter, token-still-present check) at relock.

If none of those work, the function is structurally wrong — restructure
rather than paper over with a comment.

## What needs careful eyes when changing

**Read this list any time you touch `addTCPListenerMember`, `addUDPListenerMember`, `removeMember`, or `close`:**

1. The "publish-then-start" pattern is load-bearing. `start()` does I/O and runs WITHOUT `s.mu`. Any field read by another goroutine via `s.mu` lookup must be either set BEFORE the publish, or set under `g.mu` and read under `g.mu` (the `replyBind` pattern).
2. Lock-order is `s.mu → g.mu`. There is exactly one nested case (`udpListenerGroup.removeMember` line 1328). All other group mutex acquisitions are standalone — caller does not hold `s.mu`.
3. `g.mu` and `g.writeMu` are independent. Never hold both. The mental model: `g.mu` is "what does the group know"; `g.writeMu` is "what is the group sending". They protect different things.
4. The "Locked" suffix on `addMemberLocked` is misleading. The function name says "the group's mu is locked here", not "the caller is holding it". Always verify which lock your caller actually holds before assuming a `*Locked` function is safe to call.

**Read this list any time you touch `preload/uwgpreload.c` or `shared_state.h`:**

1. The shared rwlocks have no owner-death recovery. A crash with a held write lock is a permanent hang for that mmap region.
2. `pthread_atfork` cannot release locks held by the parent at fork time. If you need fork safety, the only working pattern today is "release everything before fork" — there's no `pthread_atfork(prepare)` hook calling `wrunlock` because we don't know which locks any given thread holds at any given time.
3. The hot-path guard's `reader_tids[]` array has 256 slots. If a wrapped app spawns more than 256 concurrent threads doing fast-path syscalls, `uwg_guard_hold_slot` returns -1 and the caller spins. There is no fallback. Document this when changing UWG_GUARD_SLOTS.
4. Memory ordering: every `_Atomic` access uses an explicit `memory_order_*`. The pattern is acq for loads, rel for stores, acq_rel for CAS. Don't relax these without proving the same happens-before; the gVisor/Go-side and C-side don't share a memory model.

## Open audit follow-ups (not yet code)

These come out of the lock-map exercise itself; track separately.

1. **Lock-leak watchdog test for the C-side rwlocks.** Hold the write lock from a fake preload, kill the process, assert the manager either reclaims or exits cleanly.
2. **Robust mutex rewrite for locks 4 and 5.** Linux supports
   `PTHREAD_MUTEX_ROBUST | PTHREAD_PROCESS_SHARED` mutexes that the
   kernel reclaims on owner death. The design is sound — a working
   test fixture (forks a child holding the wrlock, SIGKILLs it,
   asserts the parent's reacquire returns within ms instead of
   hanging) shipped successfully in isolation in this session's
   history. Folding it into the live preload+ptrace path broke
   `TestUWGWrapperBothMixedInterop` and
   `TestUWGWrapperPtraceOnlyAccidentalPreloadUsesSecretPassthrough`
   for reasons not yet diagnosed (suspected interaction between
   futex waits and ptrace stop signals, OR a pthread_atfork edge
   case where the child re-uses a kernel-tracked mutex without a
   fresh `set_robust_list`). Reverted at commit eadb501; v1.1 work
   should resurrect both the rewrite and the test in one focused
   PR after diagnosing the integration carefully.
3. **Stress tests for lock 1 and lock 2.** N goroutines doing add/remove/lookup; verify no race with `-race`. The two we found this session were probably not the only ones.
4. **Static lock-order checker.** `go/analysis` pass that flags any function which acquires `g.mu` then `s.mu` (the wrong order). ~50 LOC, catches future regressions.
5. **Per-entry generation counters** to defeat the ABA class above.
   Cheap to add (a `uint64` per slot, incremented on reuse). Optional —
   today no fdproxy function actually does the bad pattern, but a
   regression would be silent. Add it if any new code needs to lock,
   unlock for I/O, then relock and reference the same slot.
6. **`Server.allowedUIDs` mutability**: today it's set-once-then-readonly.
   Stays unlocked by design — fdproxy is per-user and integrated through
   `uwgwrapper`; multi-uid rotation is out of scope. Documented here so a
   future "add UID at runtime" feature gets the right treatment (lock it
   or make the map explicitly immutable on mutation).
