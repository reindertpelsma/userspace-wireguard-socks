<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Wrapper transport modes

`uwgwrapper` runs unmodified Linux applications and routes their
network syscalls through a `uwgsocks` instance. There are several
ways to perform that interception, each with different requirements
on the host and different cost/coverage tradeoffs. Pick a mode
explicitly with `--transport=...`, or let `auto` pick.

## Mode summary

| Mode | Libc hooks | Kernel trap (seccomp + SIGSYS) | Per-syscall ptrace | Static binaries | Notes |
|---|---|---|---|---|---|
| `preload` | ✅ | — | — | ❌ | Libc-only fallback for hosts without seccomp or ptrace. Raw-asm syscalls leak past the hooks. |
| `systrap` | ✅ | ✅ | optional (only at execve, when host allows it) | exec-into-static needs ptrace | Default. Fast: hot path stays in libc, raw-asm syscalls trap into our in-process SIGSYS handler. |
| `systrap-static` | — | ✅ | ✅ at every execve | ✅ | For statically-linked targets *and* their dynamically-linked descendants — assumes everything is static, never uses libc hooks. Fundamentally requires ptrace for blob injection. |
| `ptrace-seccomp` | — | ✅ (filter only, no SIGSYS) | ✅ | ✅ | Per-syscall ptrace; filter pre-selects the traced subset. Rarely needed (when both seccomp and ptrace are available, `systrap` is preferred). |
| `ptrace-only` | — | — | ✅ (every syscall) | ✅ | Universal fallback for hosts where seccomp is restricted but ptrace works. |
| `ptrace` | — | tries seccomp; falls back if blocked | ✅ | ✅ | Auto-pick between `ptrace-seccomp` and `ptrace-only`. |
| `auto` | varies | varies | varies | varies | Probes the host for seccomp + ptrace availability and picks the strongest mode (table below). |

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

| Host shape | `auto` picks | What works | What doesn't |
|---|---|---|---|
| seccomp ✅, ptrace ✅ | **`systrap`** with the supervisor (Phase 1.5+2; runs as plain `systrap` today until the supervisor lands) | Everything: dynamic, static, dynamic↔static execve, multi-threaded execve, fork+exec trees | (nothing — once the supervisor ships) |
| seccomp ✅, ptrace ❌ (typical container: Docker default seccomp, K8s pods w/o `SYS_PTRACE`) | **`systrap`** (no ptrace) | Single-process workloads of dynamic binaries; fork+exec into other dynamic binaries (`LD_PRELOAD` re-arms via the dynamic linker) | Wrapping a static target directly fails the pre-flight check; descendants that `execve` into a static binary lose interception (seccomp filter inherited but no SIGSYS handler → child killed on first trapped syscall) |
| seccomp ❌, ptrace ✅ (sandbox-inside-sandbox edge cases) | **`ptrace-only`** | Everything (slow — every syscall round-trips through the supervisor) | (nothing) |
| seccomp ❌, ptrace ❌ (very restricted container) | **`preload`** (libc-only) | Libc-routed network calls only | Raw-asm syscalls (Go runtime internals, some C++/Rust net code), static binaries entirely, fork+exec to anything that bypasses libc |

> **Kernel-availability fact.** `SECCOMP_RET_TRAP` and `SECCOMP_RET_TRACE` were added in the same kernel commit (Linux 3.5, `c2e1f2e30daa`, 2012). There is no host that ships one without the other — they're both return values of the same `seccomp(2)` syscall. So the "seccomp ✅" hosts above all support both `RET_TRAP` (powering systrap's SIGSYS path) and `RET_TRACE` (used for the execve hook in the supervisor). The independent variable is **ptrace**, which container runtimes commonly block separately from seccomp.

## Choosing a mode explicitly

- **Default (`auto` or `systrap`)**: most hosts. Linux ≥ 4.8 with
  unrestricted seccomp + SIGSYS support. Fast.
- **`preload`**: containers that ban `seccomp(2)` *and* `ptrace(2)`.
  The cost is that any caller using raw-asm syscalls (parts of the
  Go runtime, some C++/Rust networking code) bypass interception
  silently.
- **`systrap-static`**: when your target is a statically-linked
  binary (Go-with-`CGO_ENABLED=0`, musl-static C/Rust, BusyBox), or
  when libc on the host is broken / can't link our `.so`. Assumes
  everything is static and tracks new binaries via `RET_TRACE` on
  every `execve`. **Requires ptrace.** The wrapper does a pre-flight
  ptrace probe and fails fast with a clear error if ptrace is
  blocked on this host.
- **`ptrace-only`**: debugging or hosts that block seccomp entirely
  but allow ptrace. Slow.

## Removed modes (deprecation aliases)

For one release window, the wrapper accepts and translates these:

- `preload-and-ptrace` → runs `systrap`. The legacy
  preload+seccomp+ptrace combination had cross-process per-fd
  cache invariants (the per-fd cache is process-private; only the
  in-process `.so` side could invalidate it; raw-asm `close(2)`
  from the ptracer side could not). Today the cache is
  negative-only so the invariant happens to hold, but it's
  fragile under future changes. `systrap` covers the same use case
  via a single in-process trap path with no cross-process state to
  keep coherent.
- `preload-static` → runs `systrap-static`.
- `preload-with-optional-ptrace` → runs `auto`.

These will be removed entirely in a later release.

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

## Future direction

`systrap` will gain an adaptive execve supervisor (Phase 1.5 + 2
fusion): a small ptrace process that wakes up only on
`SECCOMP_RET_TRACE` for `execve` / `execveat`, decides per-image
whether the new binary is static or dynamic, and re-arms the
appropriate injection (libc-shim re-load via `LD_PRELOAD` for
dynamic, blob inject for static). After exec the supervisor goes
back to sleep — no per-syscall ptrace cost. This is what makes
dynamic↔static execve transitions work seamlessly within a single
wrapped process tree.

When the supervisor lands, the `auto` cascade behaviour for
"seccomp ✅, ptrace ✅" gains the static-execve handling
automatically. Hosts that block ptrace (the second row in the
cascade table) keep working with the same caveats: dynamic-only
trees are fine; exec-into-static is unreachable on those hosts.
