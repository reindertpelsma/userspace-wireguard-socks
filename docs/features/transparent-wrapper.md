<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Wrapper transport modes

`uwgwrapper` runs unmodified Linux applications and routes their
network syscalls through a `uwgsocks` instance. There are several
ways to perform that interception, each with different requirements
on the host and different cost/coverage tradeoffs. Pick a mode
explicitly with `--transport=...`, or let `auto` pick.

## Mode summary

| Mode | Libc hooks | Kernel trap (seccomp + SIGSYS) | Per-syscall ptrace | execve supervisor | Static target | Notes |
|---|---|---|---|---|---|---|
| `preload` | ✅ | — | — | — | ❌ | Libc-only fallback for hosts without seccomp or ptrace. Raw-asm syscalls leak past the hooks. |
| `systrap` | ✅ | ✅ | — | — | ❌ (target itself); descendants of fork+exec into a static child also lose interception. | Recommended for **containers without ptrace** (Docker default seccomp, K8s pods without `SYS_PTRACE`). Fast: hot path stays in libc, raw-asm syscalls trap into our in-process SIGSYS handler. No tracer attached. |
| `systrap-supervised` | ✅ | ✅ | only at execve / execveat (`SECCOMP_RET_TRACE`, otherwise idle) | ✅ | ✅ | The strongest mode. Same in-process SIGSYS path as `systrap`, plus a long-running ptrace supervisor that wakes on every `execve` boundary and re-arms: dynamic→static execve injects the freestanding blob into the static child; dynamic→dynamic relies on `LD_PRELOAD` propagation. Multi-threaded execve is naturally handled (kernel guarantees only the calling thread survives execve). Requires ptrace. |
| `systrap-static` | — | ✅ | ✅ at every execve | ✅ | ✅ | Like `systrap-supervised` but **assumes every binary is static** — no libc hooks at all. Useful when libc on the host is broken or our `.so` can't link. Requires ptrace. |
| `ptrace-seccomp` | — | ✅ (filter only, no SIGSYS) | ✅ | ✅ | ✅ | Per-syscall ptrace; filter pre-selects the traced subset. Auto skips this when seccomp+ptrace are both available — `systrap-supervised` is faster. |
| `ptrace-only` | — | — | ✅ (every syscall) | ✅ | ✅ | Universal fallback for hosts where seccomp is restricted but ptrace works. |
| `ptrace` | — | tries seccomp; falls back if blocked | ✅ | ✅ | ✅ | Auto-pick between `ptrace-seccomp` and `ptrace-only`. |
| `auto` | varies | varies | varies | varies | depends — see below | Probes the host for seccomp + ptrace availability AND inspects the target ELF; picks the strongest mode that can actually intercept this target. **Fails fast** if the target is static and no mode can intercept it. |

## What needs ptrace, in detail

A clear mental model for when ptrace is mandatory vs. optional:

| Scenario | ptrace needed? | Why |
|---|---|---|
| Static binary, very first injection (`systrap-static`) | **Mandatory** | Static binaries don't honour `LD_PRELOAD`, have no constructor mechanism, and the kernel doesn't load any external code for them. The only way to get our blob into the address space at startup is `PTRACE_TRACEME` + remote `mmap` + `POKEDATA` at the post-exec stop. Linux ABI; no exception. |
| Dynamic binary, very first injection (`systrap`) | Not needed | `LD_PRELOAD` propagates through `execve(2)`, the dynamic linker loads our `.so`, the constructor installs SIGSYS+seccomp before user `main` runs. |
| `execve` boundary, dynamic→dynamic | Not needed | `LD_PRELOAD` is in `envp`, kernel preserves it. New image's dynamic linker re-loads our `.so`, constructor re-installs the handler. The seccomp filter is also kernel-inherited; for our trim trap list (network syscalls only) libc-init doesn't trip it. |
| `execve` boundary, dynamic→static | **Mandatory** to keep interception | `LD_PRELOAD` is meaningless on a static binary. Without ptrace, the inherited seccomp filter is still active in the static child but no SIGSYS handler is installed; the kernel's default disposition for SIGSYS terminates the child. With ptrace + the systrap supervisor, we re-inject the blob at the post-exec stop. |
| `execve` boundary, static→anything | **Mandatory** | Same reasoning. |
| Multi-threaded process exec'ing | Mandatory if the new image is static | `execve` kills all sibling threads atomically (kernel guarantee — only the calling thread survives, becoming the new image's thread 1). After exec the surviving thread is a fresh single-threaded image, and the same dynamic-vs-static analysis applies. The supervisor only needs to handle the surviving thread. |

## `auto` cascade — what it picks per host shape

`auto` first probes seccomp + ptrace availability, then ELF-checks
the target binary for `PT_INTERP` (= dynamically linked) vs no
`PT_INTERP` (= statically linked), and picks the strongest mode
that can actually intercept this target:

### Dynamic target

| Host shape | `auto` picks | What works | What doesn't |
|---|---|---|---|
| seccomp ✅, ptrace ✅ | **`systrap-supervised`** | Everything: dynamic, dynamic→static execve, dynamic→dynamic execve, multi-threaded execve, fork+exec trees | (nothing) |
| seccomp ✅, ptrace ❌ (typical container: Docker default seccomp, K8s pods w/o `SYS_PTRACE`) | **`systrap`** (no ptrace) | The dynamic target itself; fork+exec into other dynamic binaries (`LD_PRELOAD` re-arms via the dynamic linker) | Descendants that `execve` into a static binary lose interception (seccomp filter inherited but no SIGSYS handler → child killed on first trapped syscall) |
| seccomp ❌, ptrace ✅ (sandbox-inside-sandbox edge cases) | **`ptrace`** (auto-picks ptrace-seccomp / ptrace-only inside) | Everything (slow — every syscall round-trips through the tracer) | (nothing) |
| seccomp ❌, ptrace ❌ (very restricted container) | **`preload`** (libc-only) | Libc-routed network calls in the dynamic target | Raw-asm syscalls (Go runtime internals, some C++/Rust net code), descendants that exec into anything bypassing libc |

### Static target

The libc-only `preload` mode and the no-ptrace `systrap` mode
**cannot intercept a static target at all** (no LD_PRELOAD path on
a static binary; the inherited seccomp filter without an installed
SIGSYS handler kills the child on the first trapped syscall).
Auto uses an ELF pre-flight (`PT_INTERP` absent) to detect this
and either picks a ptrace-using mode or fails fast.

| Host shape | `auto` picks | What works |
|---|---|---|
| seccomp ✅, ptrace ✅ | **`systrap-supervised`** | Everything (in-process SIGSYS for the static target, blob inject for any further static descendants) |
| seccomp ✅ or ❌, ptrace ✅ | **`ptrace-only`** | Everything (slow) |
| ptrace ❌ | **`auto` exits with an error** explaining that no mode can intercept a static binary on this host. The user must wrap a dynamic target, run on a host that allows ptrace, or pick `--transport=preload` explicitly to accept the no-interception trade-off. | n/a |

> **Kernel-availability fact.** `SECCOMP_RET_TRAP` and `SECCOMP_RET_TRACE` were added in the same kernel commit (Linux 3.5, `c2e1f2e30daa`, 2012). There is no host that ships one without the other — they're both return values of the same `seccomp(2)` syscall. So the "seccomp ✅" hosts above all support both `RET_TRAP` (powering systrap's SIGSYS path) and `RET_TRACE` (used for the execve hook in the supervisor). The independent variable is **ptrace**, which container runtimes commonly block separately from seccomp.

## Choosing a mode explicitly

- **`auto`**: let the wrapper probe + decide. Recommended for
  general use. Fails fast on a static target without a working
  interception path rather than running it un-armed.
- **`systrap-supervised`**: full hosts (most Linux ≥ 4.8 + ptrace
  allowed). Handles dynamic↔static execve seamlessly via the
  ptrace supervisor. Fastest path that's also fully correct.
- **`systrap`**: containers that ban `ptrace(2)` but allow
  `seccomp(2)` (Docker default seccomp profile, K8s pods without
  `SYS_PTRACE`). Same in-process SIGSYS as `systrap-supervised`
  but no execve supervisor, so static descendants of a fork+exec
  lose interception. The right pick when you know your container
  policy blocks ptrace and your workload is dynamic-only.
- **`preload`**: containers that ban both `seccomp(2)` and
  `ptrace(2)`. Libc-only. The cost is that any caller using
  raw-asm syscalls (parts of the Go runtime, some C++/Rust
  networking code) bypass interception silently.
- **`systrap-static`**: when your target is a statically-linked
  binary (Go-with-`CGO_ENABLED=0`, musl-static C/Rust, BusyBox),
  or when libc on the host is broken / can't link our `.so`.
  Assumes everything is static and tracks new binaries via
  `RET_TRACE` on every `execve`. **Requires ptrace.** The wrapper
  does a pre-flight ptrace probe and fails fast with a clear
  error if ptrace is blocked on this host.
- **`ptrace-only`**: debugging or hosts that block seccomp entirely
  but allow ptrace. Slow.

## Performance — relative cost per intercepted syscall

`preload` is the floor. Every other mode adds overhead that
falls into two buckets: kernel trap (cheap, in-process SIGSYS
delivery) vs ptrace round-trip (expensive, context-switch to a
tracer process and back).

| Mode | Per-libc-call cost | Per-raw-asm-call cost | Notes |
|---|---|---|---|
| `preload` | **blazing fast** — one indirect call into our libc shim, then a normal kernel syscall (~10 ns of overhead vs. an unwrapped syscall) | full kernel cost; **no interception** — raw asm goes direct to the kernel | The fastest mode, but raw-asm callers (parts of the Go runtime, some C++/Rust net code) bypass interception silently. |
| `systrap` | ~same as `preload` (libc shim is identical) | a few hundred ns — one SIGSYS delivery + in-process handler dispatch + the kernel syscall the handler issues | The libc hot path is identical to `preload`; raw-asm pays a SIGSYS round-trip *within the same process*. **No context switch to a tracer**, so even the "slow" path here is much faster than ptrace. |
| `systrap-supervised` | ~same as `systrap` | ~same as `systrap` | Hot-path cost is identical to `systrap`. The ptrace supervisor is dormant except at execve boundaries — there's no per-syscall ptrace cost. |
| `systrap-static` | n/a (no libc hooks) | ~same as `systrap` | Static targets can't use libc hooks, so every intercepted syscall pays the SIGSYS cost. Still fast in absolute terms; the SIGSYS handler runs in-process with no tracer involved. |
| `ptrace-seccomp` | **~10–100× the cost of `systrap`** for any traced syscall | same as libc-call cost | Each traced syscall is a full ptrace round-trip: tracee stops, kernel context-switches to the tracer process, the tracer runs Go code, kernel context-switches back, syscall continues. The seccomp pre-filter limits the cost to traced syscalls only. |
| `ptrace-only` | **~100–1000× the cost of `preload`** for *every* syscall | same | Universal slow path. Every `read`/`write`/etc. wakes the tracer; double context-switch per syscall. Use only when seccomp is unavailable. |

Practical implication: dynamic apps that go through libc (Go,
Rust, chromium, JVM, anything linking libc) see effectively
**`preload` performance** under any of `preload` /
`systrap` / `systrap-supervised`. The kernel-trap modes
(`systrap*`) only add the SIGSYS overhead for syscalls that
bypass libc; that overhead is **at least an order of magnitude
cheaper** than the ptrace round-trip the `ptrace*` modes pay.

## Environment variables

- `UWGS_WRAPPER_TRANSPORT=systrap` — equivalent to
  `--transport=systrap`. Useful in shell wrappers / CI.
- `UWGS_DISABLE_SYSTRAP=1` — set by the wrapper automatically when
  `transport=preload` is selected. The `.so` constructor reads
  this and skips installing the SIGSYS handler + seccomp filter.
  You can set this manually for testing the libc-only path under
  a different transport.
- `UWGS_DISABLE_SECCOMP=1` — legacy alias for
  `UWGS_DISABLE_SYSTRAP`. Both work.

## What systrap-supervised does on each execve boundary

Once attached, the supervisor waits on
`PTRACE_EVENT_SECCOMP` for `SYS_execve` / `SYS_execveat` (the
filter installed by the `.so` constructor returns
`SECCOMP_RET_TRACE` for those when `UWGS_SUPERVISED=1` is in the
environment). On every event:

1. Let the syscall continue (`PTRACE_CONT`).
2. Wait for the follow-up `PTRACE_EVENT_EXEC` stop. (Note: this
   only fires when execve **succeeds**. A failed `execve(2)`
   returns through the SECCOMP event with the original image
   intact and never produces a EXEC stop — handled correctly
   by the loop.)
3. Single-step once. The EXEC stop fires inside the kernel's
   syscall-exit path (PC has been switched to the new image's
   entry but the syscall hasn't unwound); remote `mmap` is
   unreliable from here. Single-step advances the tracee to
   the first user-space instruction where regs are user-mode
   regs and remote syscalls work.
4. Open `/proc/<pid>/exe` and inspect `PT_INTERP`:
   - present → dynamic image; `LD_PRELOAD` will re-run the
     `.so` constructor in the new image; supervisor does
     nothing.
   - absent → static image; supervisor injects the
     freestanding blob via the same machinery as
     `systrap-static` (parse blob → remote `mmap` →
     `PTRACE_POKEDATA` segments → jump to `uwg_static_init`).
5. `PTRACE_CONT` and loop.

The supervisor stays attached for the **entire lifetime** of the
process tree (it never `PTRACE_DETACH`es). Children spawned via
`fork`/`vfork`/`clone` are auto-traced via
`PTRACE_O_TRACEFORK` / `TRACEVFORK` / `TRACECLONE`. The supervisor
exits with the same status as the root traced PID; non-traced
sibling processes (the fdproxy daemon spawned by the wrapper)
are filtered out of the wait loop by PID.
