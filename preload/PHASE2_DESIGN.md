# Phase 2 — Static-Binary Support

> **Goal.** Give static binaries (no LD_PRELOAD path, no dlopen, no .so
> loading) the same fast in-process tunnel interception that Phase 1
> gives dynamic binaries via `uwgpreload-phase1.so`. Today static
> binaries fall back to the legacy `internal/uwgtrace/` ptracer — which
> works correctly but pays a per-syscall PTRACE round-trip and is
> measurably slower.

## Why this matters

Real-world targets that ship static-linked:
- Go binaries (`CGO_ENABLED=0` builds) — extremely common
- musl-static C/Rust binaries
- BusyBox utilities
- Single-file CLI tools (`curl --static`, etc.)

Without Phase 2, every Go binary the user runs through `uwgwrapper`
goes through the full ptracer path. That's the existing
`transport=ptrace-seccomp` mode and it works, but it's the slow path.

## The injection problem

Static binaries don't honor `LD_PRELOAD`. The kernel doesn't load
shared libraries for them. The `_start` symbol from `crt0` runs and
jumps straight to `main`. There's no constructor mechanism for
external code to get a foothold.

The only way to inject our dispatcher into a static binary's address
space at runtime is via **ptrace from outside**:

1. Parent (`uwgwrapper`) `fork()`s a child.
2. Child calls `PTRACE_TRACEME` then `execve(static_target, …)`.
3. Parent waits for the post-`execve` `PTRACE_EVENT_EXEC` stop.
4. Parent uses `ptrace(PTRACE_POKEDATA, …)` and remote-syscall
   execution (`PTRACE_SETREGS` + `PTRACE_SINGLESTEP`/`PTRACE_CONT`)
   to:
   - Allocate a region in the tracee's address space via remote
     `mmap()`.
   - Copy `uwgpreload-static`'s `.text` + `.rodata` + `.data` into
     that region.
   - Set up the tracee's stack so the next instruction-pointer
     starts at `uwgpreload-static`'s init entry, with the original
     `_start` and saved program-state on the stack.
5. Tracee runs init: per-thread sigaltstack, SIGSYS handler, seccomp
   filter — same as Phase 1's constructor.
6. Init returns to the saved `_start`, normal program execution
   begins.
7. Parent detaches.

After detach, the static binary runs at full speed with in-process
SIGSYS interception. Same fast path as Phase 1 dynamic.

## Build artifact: `uwgpreload-static`

The new build target is a position-independent freestanding blob
containing every `core/` source linked together with no libc
dependency. Today `preload/core/*.c` uses a few libc functions:

- `memcpy`, `memset` — replace with our own (trivial; both are
  one-liners).
- `strncmp` — replace with our own (already have `uwg_strlen` in
  `fdproxy_sock.c`; pattern extends).
- `inet_pton` — replace with custom IPv6 parser (we already have
  IPv4 dotted-quad parser in `addr_utils.c`).

After those replacements, `core/` compiles cleanly with
`-ffreestanding -nostdlib -fno-stack-protector -fPIC`.

The link step produces a static blob (e.g., raw binary or ELF that
we strip and embed). The blob exports a single entry point
`uwg_static_init(saved_start, argc, argv, envp)` that:

1. Sets up sigaltstack.
2. Installs SIGSYS handler.
3. Installs seccomp filter (network-only, same as Phase 1's trim).
4. Returns to `saved_start`.

## Supervisor: `uwgwrapper` injection logic

The supervisor lives in `cmd/uwgwrapper/inject_static.go` (new
file). Skeleton:

```go
// transport=preload-static
//
// 1. fork → child PTRACE_TRACEME → execve(target, ...)
// 2. parent waits for first PTRACE_EVENT_EXEC stop
// 3. parent reads /proc/<pid>/auxv to get AT_ENTRY (saved_start)
// 4. parent reads /proc/<pid>/maps to find a free region for injection
// 5. parent issues remote mmap via PTRACE_SETREGS+SYSCALL
// 6. parent PTRACE_POKEDATAs uwgpreload-static blob into that region
// 7. parent sets RIP/PC to blob's uwg_static_init, args = saved_start
// 8. parent PTRACE_CONT — tracee runs init, then jumps to saved_start
// 9. parent PTRACE_DETACH — tracee runs at full speed
```

The blob is embedded in `uwgwrapper` via `//go:embed assets/uwgpreload-static.bin`.

## Architecture matrix

Each (arch × libc) needs its own `uwgpreload-static.bin`:

- amd64: built freestanding, ~30KB
- arm64: built freestanding, ~30KB

The supervisor picks the right blob from auxv.

## Phase boundary

| Capability | Phase 1 | Phase 1.5 | Phase 2 |
|---|---|---|---|
| Dynamic binaries | ✅ shim_libc | ✅ + execve handler | (no change) |
| Static binaries | ❌ falls back to legacy ptracer | ❌ same | ✅ blob injection |
| Setuid binaries | ❌ kernel drops env/ptrace | ❌ same | ❌ Phase 3 |

## Implementation status (as of commit `c9d6f48`)

✅ **Step 1: Freestanding refactor of `core/`** — `freestanding.h`
shim, custom `uwg_parse_ipv6`, `uwg_environ` global, TID-keyed
sigaltstack table. Zero undefined externs in the freestanding build.

✅ **Step 2: Blob build target** — `preload/build_static.sh` produces
`uwgpreload-static-{amd64,arm64}.so` with `-Wl,-Bsymbolic` to bind
intra-blob references at link time. Two exported entry symbols:
`uwg_static_init` (the function the supervisor jumps to) and
`uwg_static_trap` (4× int3 / brk #0 the supervisor sets as the
return target).

✅ **Step 3: ELF parser scaffold** — `cmd/uwgwrapper/inject_static.go`
opens the blob, finds the entry/trap symbols, enumerates `PT_LOAD`
segments, computes the (low, high) vaddr span.

✅ **Step 4: Remote-syscall primitive** —
`cmd/uwgwrapper/inject_remote_syscall.go` (with per-arch ABI files)
executes any syscall inside a stopped tracee by saving regs +
overlaying the syscall instruction at PC + `PTRACE_SINGLESTEP` +
restoring. Validated with `getpid` and `mmap+munmap`.

✅ **Step 5: Blob load + relocations** —
`cmd/uwgwrapper/inject_load.go` does remote `mmap` of the contiguous
load span, `PTRACE_POKEDATA`s each segment to its right offset, and
applies `R_*_RELATIVE` entries from `.rela.dyn`. (Other relocation
types are rejected so a build-config regression fails loudly.)

✅ **Step 6: RIP handoff** — `cmd/uwgwrapper/inject_handoff.go` sets
RIP/PC to entry, the ABI argument registers to (0, 0, 0), and the
return target to `uwg_static_trap` inside the blob's executable
text segment. After `PTRACE_CONT` the function returns to the trap,
SIGTRAP fires, supervisor reads RAX/X0 (sign-extended) for the
result, and restores the original tracee state.

✅ **Step 7: validation suite** — `tests/preload/phase2_static_test.go`
covers three scenarios end-to-end on amd64 and arm64:
1. `TestPhase2StaticBinaryEchoTCP` — glibc-static C client:
   connect → write → read → echo sentinel through the tunnel.
2. `TestPhase2StaticGoBinaryEchoTCP` — `CGO_ENABLED=0` Go client:
   same flow, validates Go runtime + SIGSYS coexistence.
3. `TestPhase2StaticGoConcurrencyStress` — Go static HTTP server
   under load: 100 goroutines × 10 requests each = 1000 reqs,
   per-fd futex_rwlock + `rt_sigaction`-protect under a real Go
   M-spawning workload. Validated 5.5s end-to-end.

✅ **Step 8: `transport=preload-static`** — `cmd/uwgwrapper/main.go`
gates on `--transport=preload-static`. The orchestrator
(`cmd/uwgwrapper/inject_run.go`) does fork+`PTRACE_TRACEME`+execve,
reads envp from the post-execve stack, parses the blob, loads it,
runs `uwg_static_init(0, NULL, envp)` via the handoff trap, and
detaches.

⏳ **Step 9: per-arch blob embed** — currently the blob is loaded
from disk via `UWGS_STATIC_BLOB` or the sibling
`assets/uwgpreload-static-${arch}.so`. `//go:embed` was deferred
to keep binary-churn out of git; a placeholder strategy is TBD.

## Validation status (as of commit `265c88b`)

End-to-end on **amd64 and arm64**:
- All 3 Phase 2 stress tests pass.
- All Phase 1 lock-stress tests pass: `TestPhase1FxlockStress` (3.2M
  ops, 32 threads × 1 lock), `TestPhase1FxlockContentionStress`
  (3.2M ops, 16 threads × 8 locks at ~6.7M ops/sec), and
  `TestPhase1FxlockContentionStressMean` (9.6M ops at 8:1 thread:lock
  contention, 0 invariant violations).
- `TestPhase1CacheRaceStress`: 80k ops, 0 torn reads.
- Full preload-test suite (`go test ./tests/preload/`): green in
  ~62s on arm64, ~181s on amd64.

The lock primitive's correctness has been negative-tested: a copy
with the rdlock retry-path step-3 re-check intentionally removed
produces 745+ invariant violations and `RESULT FAIL`, confirming
the contention harness has teeth for the exact race class found in
the user-spotted retry-path deadlock.

## Known limitations

**Natural-exit hang under `transport=preload-static`** (diagnosed,
workaround documented). When a Go static binary's `main` returns
naturally (defer→runtime.exit→exit_group), if the Go `Server.Serve`
goroutine is parked in `accept4` (trapped) inside our SIGSYS
handler's fdproxy control read, `close(listenerFd)` (not trapped)
can't abort the in-flight accept; the fdproxy reply never comes,
and from Go's runtime view the M is still running user code so
`runtime.exit`'s bookkeeping can't drain. Workaround in stress
harnesses: explicit `os.Exit(0)` at end of main bypasses both. Real
fixes (deferred): non-blocking fdproxy control with timeouts, OR
trap `close()` and signal in-flight ops to abort on listener close.
See `tests/preload/phase2_natural_exit_diag_test.go` for the
diagnostic + per-thread `/proc` dumper (gated by
`UWG_PHASE2_DIAG=1`).

**TestPhase2StaticBinaryEchoTCP fails on the (arm64 × musl ×
glibc-style static-PIE C binary) corner of the matrix.** First
`send()` after `connect()` returns `ENOBUFS` (errno 105). The
amd64 musl path, the arm64 glibc path, and both arches' Go-static
paths are all green; only this 4-way intersection fails. Likely a
syscall-arg or errno-translation bug specific to arm64-musl-PIE;
worth a focused investigation but not blocking the Phase 2
v0.1.x release as Go-static (the dominant real-world target) is
fully validated. Tracked in the soak-test-matrix follow-up.

**Minecraft soak (validated 2026-04-28):** Paper 1.21.11 server
running under `uwgwrapper --transport=preload`, binding
`100.64.94.1:25577` via `fdproxy /uwg/socket` (not via the kernel)
serves Server-List-Ping requests over the WireGuard tunnel
end-to-end. This validates Java/JVM/Netty + LD_PRELOAD-based bind
interception + tunnel-side TCP listener + reverse-direction
client-tunnel→server-tunnel TCP flow. The reverse_forward path
(Paper bound on host loopback, uwgsocks reverse-forwards from
tunnel address) is also validated as a simpler operational mode.
See `/tmp/mc-soak/` on the amd64 test host for live artifacts.

## Open questions for later

- How to handle clone() — child inherits seccomp filter but not
  sigaltstack. Requires per-thread init via clone()-shim. Phase 1
  already has this for dynamic via constructor on first hooked call.
  Static needs equivalent — can be handled inside the injected blob
  by hooking the kernel's clone-return path.
- ASLR considerations — the blob is position-independent, so we
  can put it wherever mmap returns.
- Stack alignment after the saved_start jump — must respect the
  ABI's 16-byte stack alignment on amd64, etc.
- `//go:embed` placeholder strategy: how to embed the blob into the
  wrapper without polluting git with a binary that changes every
  build.
