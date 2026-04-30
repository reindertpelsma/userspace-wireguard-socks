# Phase 1.5 — Execve Supervisor

> **Scope.** Re-arm `uwgpreload-phase1.so` on every dynamic-binary `execve`
> boundary so chromium-class fork+exec workloads work with the kernel-
> side seccomp filter enabled. Static-binary `execve` is **Phase 2**
> (different injection mechanism via `PTRACE_TRACEME` + mmap of
> `uwgpreload-static`).

## The problem this solves

Phase 1's seccomp filter is installed by the constructor of
`uwgpreload-phase1.so` at LD_PRELOAD load time. That filter is preserved
across `execve` (kernel-inherited). The SIGSYS handler that pairs with
the filter, however, lives in process memory and is **reset on execve**.
Between the post-execve syscall return and the new image's libc-init
firing constructors, libc-init issues syscalls (`mmap`, `read`, `close`,
…) that hit our trapped list. With no SIGSYS handler installed, the
kernel's default disposition for SIGSYS terminates the process.

For long-running, deeply-forking workloads (chromium, electron, node
clusters), this means subprocesses die seconds after spawn. Phase 1's
workaround is `UWGS_DISABLE_SECCOMP=1`, which falls back to shim_libc-
only interception and gives up the kernel-level safety net for raw-asm
syscalls.

Phase 1.5 closes this gap **for dynamic binaries** by attaching a
ptrace supervisor that catches `execve` via `SECCOMP_RET_TRACE` and
installs an early signal trampoline before letting the new image run
libc-init.

## What the supervisor does

The supervisor is a small Go process spawned by `uwgwrapper` ahead of
the wrapped target. The target sets `PTRACE_TRACEME` so the supervisor
becomes its tracer. From there:

1. **Filter changes.** `uwg_traced_syscalls` in `preload/core/seccomp.c`
   gains `SYS_execve` and `SYS_execveat` (currently empty list with a
   sentinel). The filter rewrites those to `SECCOMP_RET_TRACE`. With a
   tracer attached, the kernel reports a `PTRACE_EVENT_SECCOMP` to the
   supervisor instead of letting the syscall go directly.

2. **On execve event:**
   - Supervisor reads `/proc/<tid>/exe` and `/proc/<tid>/auxv` once the
     execve completes to detect static vs dynamic. Static images are
     deferred to Phase 2 (the supervisor will, for now, just
     `PTRACE_DETACH` and let the static binary run unwrapped — same as
     today).
   - For dynamic images, the supervisor injects an early `rt_sigaction`
     to install a thin SIGSYS shim that returns `-ENOSYS` for any
     trapped syscall fired before the .so constructor runs. The shim
     is a single page of injected code (mmap'd into the tracee's
     address space via `process_vm_writev` + `PTRACE_SETREGS`).
   - The supervisor sets a hardware watchpoint on the .so's
     constructor entry point so it can detach (or rearm) once the
     real handler is in place.
   - Detaches via `PTRACE_DETACH` after the constructor runs.

3. **Per-thread bookkeeping.** Threads spawned via `clone(CLONE_THREAD)`
   share the SIGSYS handler, but each thread needs its own
   `sigaltstack`. The supervisor doesn't try to handle this — the .so
   constructor's `uwg_core_init_thread` already covers it.

## What does NOT need to change

- `preload/core/sigsys.c` — handler stays as-is.
- `preload/core/syscall.h` / passthrough mechanism — unchanged.
- The seccomp filter shape — only the `RET_TRACE` list changes.
- `shim_libc/` — unchanged. The supervisor only matters in the
  exec'd-into-a-fresh-image window.

## Phase 1.5 boundary

- ✅ Dynamic binaries (LD_PRELOAD propagates, .so reloads, our
  constructor fires).
- ❌ Static binaries (no LD_PRELOAD path; no constructor; need
  Phase 2's injection).
- ❌ setuid binaries (kernel drops LD_PRELOAD for security; needs
  Phase 2 too).

## Validation status (as of v0.1.0-beta.57)

The supervisor shipped in beta.57 as `transport=systrap-supervised`.
Coverage:

- ✅ `TestSystrapSupervisedDynamicEcho` — pure dynamic round-trip
  through the supervisor (sanity check). amd64 + arm64.
- ✅ `TestSystrapSupervisedDynamicExecsStatic` — the load-bearing
  case: a wrapped dynamic `/bin/sh` exec's a static C binary
  mid-script. The supervisor's re-arm in the static child is what
  makes the tunnel TCP echo complete. amd64 + arm64.

Validation work still on the wishlist (not yet committed):

- Re-enable seccomp in `TestPhase1HeadlessChromeSmoke` (drop the
  `UWGS_DISABLE_SECCOMP=1` workaround). With systrap-supervised the
  workaround should be unnecessary because the supervisor catches
  the chromium-zygote execve boundaries.
- Add `TestPhase1_5ExecveRearm` (or rename: `TestSystrapSupervised
  ExecveRearmLoop`) that fork+execs the C stub a few times in a
  loop and asserts every child sees working interception.
- Stability soak: 20×20 (20 wrapped processes × 20 fork+exec cycles
  each) on amd64 and arm64, race-clean.
- Multi-threaded execve: a wrapped target that spawns N threads,
  one of which `execve`s a static binary; the kernel guarantees
  only the calling thread survives execve (atomic), so the
  supervisor only sees one PID re-emerge — but the test confirms
  the design assumption.
- Failed-execve resilience: wrap a target that intentionally
  execves a non-existent path; the wrapper should NOT crash, and
  the failed execve should return -ENOENT cleanly without firing
  a (non-existent) PTRACE_EVENT_EXEC.

## Slow-path investigation — RESOLVED

The phase1 chromium smoke previously showed bimodal timing
(6s fast / 23-49s slow) even WITHOUT seccomp — `uwg_state_lookup`
rwlock contention under chromium's recvmsg-heavy IPC paths. Fixed
in `phase1: per-process direct-indexed fd cache for fast lookups`
(commit `be94931`):

- Hash-table early-out distinguishes truly-empty slots (lookup
  terminator under linear probing) from tombstones (continue scan).
  Untracked-fd lookups now break at the first empty slot instead of
  walking all 65536.
- Per-process direct-indexed cache: 4096-entry table (configurable
  via `UWG_FD_CACHE_SIZE`), one 16-byte atomic entry per fd. Stores
  positive AND negative entries so both "tracked" and "not tracked"
  hit a single atomic load instead of the global rwlock.

Chromium 5/5 pass post-fix on the Scaleway box (44-78s); pre-fix
was 4/5 with high variance. The remaining time is chromium's own
init cost, not our dispatcher overhead.

## Why Phase 1.5 still matters

With the trimmed trap list (network-only) chromium-class apps work
WITHOUT the supervisor. So Phase 1.5 is no longer load-bearing for
chromium alone. **It is still required for:**

1. **read/write/close coverage on raw-asm callers.** Real apps DO
   use raw asm read/write on connected UDP sockets (some C++/Rust
   network code; some Go runtime paths). Without the trap, those
   bytes bypass our framing → fdproxy sees malformed packets.
2. **Tunnel state cleanup on raw-asm close.** A close() that bypasses
   shim_libc leaks the tracked_fd entry in shared_state until the
   slot is evicted by a future store. With many such closes the
   table fills up with stale entries.
3. **Static binaries (Phase 2 prerequisite).** Static binaries can't
   use shim_libc (no LD_PRELOAD). The kernel-level filter is the
   ONLY interception they get. The filter must include the full
   trap list, AND the supervisor must inject a SIGSYS handler before
   libc-init runs.

So Phase 1.5's actual deliverable now is the **ptrace machinery
shared with Phase 2**:

- Same supervisor process that catches PTRACE_EVENT_EXEC.
- For dynamic targets (Phase 1.5): suppress SIGSYS during the
  post-exec libc-init window, simulating each trapped syscall via
  `ptrace(SETREGS)`. Stop suppressing once the constructor has
  installed the real SIGSYS handler (detection: a marker syscall
  emitted at the end of `uwg_core_init`).
- For static targets (Phase 2): allocate an mmap region in the
  tracee, copy `uwgpreload-static` into it, jump to its init entry,
  let it install the SIGSYS handler + seccomp filter, then return
  to original `_start`.

Both paths share: ptrace attach + `PTRACE_EVENT_EXEC` handling +
remote syscall execution machinery + auxv reading. Implementing
Phase 1.5 first creates the foundation Phase 2 builds on.
