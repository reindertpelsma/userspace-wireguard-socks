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

## Implementation order

1. **Freestanding refactor of `core/`** (this commit) — replace libc
   deps, verify still builds via `build_phase1.sh`.
2. **Blob build target** — new `preload/build_static.sh` produces
   `uwgpreload-static.{amd64,arm64}.bin`.
3. **Supervisor skeleton in `cmd/uwgwrapper/`** — fork+attach,
   PTRACE_EVENT_EXEC, read auxv, find a hole.
4. **Remote mmap** — PTRACE_SETREGS to invoke mmap from inside the
   tracee.
5. **Blob copy** — PTRACE_POKEDATA loop.
6. **Init entry handoff** — set RIP to blob entry, push saved_start
   on stack.
7. **Detach + verify** — small static-binary smoke test.
8. **Validate against `transport=preload-static`** in
   `tests/preload/phase2_static_test.go`.

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
