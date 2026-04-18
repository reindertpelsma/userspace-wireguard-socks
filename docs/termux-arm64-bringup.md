# Termux arm64 Bring-Up Plan

This document is written for a fresh Codex session running inside Termux on an
unrooted arm64 Android phone. The goal is ambitious but useful: make
`uwgsocks`, `uwgwrapper`, preload, ptrace, and the UI server work in a weird,
restrictive mobile Linux-like environment, then prove it with the same tests we
use on normal Linux.

Assume the Codex session has full filesystem access to this repository
directory, but has no chat history or prior context of any kind. Everything
important about the project and the Termux goal must be rediscovered from the
files in this checkout and from small local probes.

The short version: `uwgsocks` mostly behaves like a normal Go-on-Android port,
but Go/linker and Bionic details matter. `uwgwrapper --transport preload`,
`ptrace-seccomp`, and `preload-and-ptrace` are the important Termux proof paths.
Explicit `ptrace-only` is intentionally treated as unsupported on arm64 for now
because Android/arm64 does not provide the amd64-style syscall-entry marker and
the tested Android 4.14 kernel does not expose a reliable enough fallback.

## Project Background For Fresh Codex

This repository is `userspace-wireguard-socks`. It is a rootless WireGuard
gateway that avoids requiring `/dev/net/tun`, routing table changes, or
`CAP_NET_ADMIN` for its default operating mode. Instead of creating a normal
kernel VPN interface, it embeds WireGuard plus a userspace network stack and
exposes that stack through:

- HTTP and SOCKS5 proxies for proxy-aware applications.
- Local forwards and reverse forwards.
- A raw socket API over HTTP/WebSocket-like upgrades.
- `uwgfdproxy`, a local Unix-socket bridge to the raw socket API.
- `uwgwrapper`, a launcher that makes ordinary Linux programs use the gateway
  without native SOCKS support.
- A Go library API for tests and embedding.

The main binaries in this repo are:

- `cmd/uwgsocks`: the rootless WireGuard gateway, proxy, API server, ACL engine,
  relay/conntrack engine, traffic shaper, DNS helper, optional TUN bridge, and
  raw socket API provider.
- `cmd/uwgwrapper`: the application launcher. It can use `LD_PRELOAD`, ptrace,
  seccomp-assisted ptrace, or a combined preload+seccomp+ptrace mode.
- `cmd/uwgwrapper/assets/uwgpreload.so`: the embedded preload library built
  from `preload/uwgpreload.c`.
- `internal/fdproxy`: the fd bridge used by `uwgwrapper`.
- `internal/uwgtrace`: ptrace/seccomp syscall interception.
- `internal/uwgshared`: shared fd table and hot-path guard state used between
  preload and ptrace.
- `turn/`: a standalone TURN relay used by WireGuard transport modes.

There is also a second repository checked out inside this one:

- `uwgsocks-ui/`: a separate UI/server repo with its own `.git` directory. It
  manages users, peers, generated YAML, daemon restarts, runtime peer traffic
  shapers, 2FA/OIDC login, and optional kernel WireGuard through `uwgkm`.

For the Termux goal, the important architecture is:

- `uwgsocks` should run as a normal unrooted userspace WireGuard server/client
  on the phone.
- `uwgsocks-ui` should run on the phone and manage `uwgsocks`, not kernel
  WireGuard. On unrooted Android, `uwgkm`/kernel mode is not the proof.
- `uwgwrapper --transport preload` should route dynamically linked Termux
  applications through the phone's `uwgsocks`.
- `uwgwrapper --transport ptrace-seccomp` should catch static or direct
  syscalls that preload cannot intercept.
- `uwgwrapper --transport preload-and-ptrace` should keep common libc socket
  operations in preload's hot path while leaving ptrace available for cold-path
  syscalls.
- `uwgwrapper --transport ptrace-only` is not the Termux target unless a future
  Android/kernel combination exposes reliable syscall-entry/exit metadata.
- Host TUN mode is not expected to work on an unrooted phone unless a real
  accessible TUN device exists; this experiment is primarily about the rootless
  proxy/socket/wrapper paths.

The existing implementation has already grown beyond a toy proxy. It includes
IPv4, IPv6, TCP, UDP, ping-style ICMP/ICMPv6, DNS routing, forward ACLs with
conntrack, per-peer traffic shaping, runtime config APIs, socket binding and
listener support, SO_REUSEADDR/SO_REUSEPORT behavior inside fdproxy, and a UI
server that can change live peer settings. A fresh Codex should preserve those
features while porting; do not simplify the model to "just make curl work".

## Current Termux Result

The first real Termux run used an unrooted Android arm64 phone reachable through
a reverse SSH tunnel. The observed environment was:

- Kernel: Android 4.14 arm64.
- User: normal Termux app UID, not root despite the SSH username.
- Go: `go1.26.2 android/arm64`.
- Clang: Termux clang targeting `aarch64-unknown-linux-android24`.
- Same-UID `ptrace` works; `strace -f true` succeeds.
- `seccomp` trace stops work with `PTRACE_O_TRACESECCOMP`.
- `pidfd_open`/`pidfd_getfd` are not available on this kernel.

Practical status after the first bring-up:

- `uwgsocks` builds and runs on Termux with `GOFLAGS="-ldflags=-checklinkname=0"`.
  This is needed because `github.com/wlynxg/anet` uses `//go:linkname` against
  the Go `net` package and newer Go releases reject that by default.
- The preload library builds with Termux clang after Bionic compatibility fixes
  for `getnameinfo`, resolver types, `dup2`/`dup3`, `sendmmsg`/`recvmmsg`, and
  missing `fopencookie`.
- `uwgwrapper --transport preload` works with Termux `curl`.
- `uwgwrapper --transport ptrace-seccomp` works with a plain C HTTP client and
  Termux `curl` over a dummy userspace WireGuard client/server pair.
- `uwgwrapper --transport preload-and-ptrace` works with a plain C HTTP client
  and Termux `curl` after adding preload `poll`/`ppoll` wrappers. This is
  important on kernels without `pidfd_getfd`, because ptrace cannot duplicate a
  tracee-owned fdproxy socket for readiness polling.
- `uwgwrapper --transport ptrace-only` fails fast on arm64 instead of hanging.
  On this phone, pure ptrace syscall entry/exit detection is ambiguous enough
  to desynchronize during process startup.
- A deterministic reverse-forward smoke test passed: phone-local Python HTTP
  server on `127.0.0.1:18080`, `uwgsocks` server reverse-forwarding
  `100.64.90.99:18080`, `uwgsocks` client on `127.0.0.1:8082`, and wrapped
  clients fetching `http://100.64.90.99:18080/`.

The official Codex CLI did not install cleanly in raw Termux at first because
the optional native package was skipped for Android. This workaround made
`codex --version` work in the tested environment:

```bash
npm install -g @openai/codex@latest
npm install -g "@openai/codex-linux-arm64@npm:@openai/codex@0.121.0-linux-arm64" --force
codex --version
```

That only fixes the CLI binary. Authentication may still need an interactive
browser/login path, so doing the bring-up from a remote Codex session over SSH
is still the safer workflow.

## Fresh Codex Starting Point

Start by reading these files in order:

1. `README.md`
2. `docs/howto/README.md`
3. `docs/configuration.md`
4. `docs/socket-protocol.md`
5. `docs/testing.md`
6. `uwgsocks-ui/README.md`
7. `internal/uwgtrace/tracer_linux_amd64.go`
8. `internal/uwgtrace/seccomp_linux_amd64.go`
9. `preload/uwgpreload.c`
10. `cmd/uwgwrapper/main.go`

Then make an initial checkpoint:

```bash
git status --short
git rev-parse --is-inside-work-tree || git init
git add -A
git commit -m "chore: checkpoint before termux arm64 bring-up" || true
```

Do not start by changing everything. First collect facts from the phone and run
small probes. Android devices differ a lot, and this task is exactly where
assuming a normal distro will burn an afternoon.

## Termux Setup

Use a current Termux build from F-Droid or official Termux GitHub releases, not
an old package source. Keep the checkout under Termux-owned storage, such as
`$HOME/src/userspace-wireguard-socks`. Do not build or execute from Android
shared storage.

```bash
pkg update
pkg upgrade
pkg install git golang clang make pkg-config nodejs-lts npm curl jq openssl strace lsof procps
termux-wake-lock
```

Recommended environment snapshot:

```bash
uname -a
uname -m
getprop ro.product.cpu.abi
getprop ro.build.version.release
getprop ro.build.version.sdk
go version
go env GOOS GOARCH CGO_ENABLED CC
clang --version
echo "PREFIX=$PREFIX"
echo "LD_PRELOAD=$LD_PRELOAD"
```

Expected values:

- `GOOS=android`, not `linux`, when building natively in Termux with normal Go.
- `GOARCH=arm64`.
- The C library is Android Bionic libc, not glibc.
- Termux may use `LD_PRELOAD` for `termux-exec`; wrapper code must preserve an
  existing `LD_PRELOAD` instead of replacing it.

## Current Architecture Reality

Before porting, confirm the present state:

```bash
rg -n "linux && amd64|!linux || !amd64|PtraceRegs|Orig_rax|AUDIT_ARCH" internal/uwgtrace tests/preload
```

Current expected finding in this checkout:

- `internal/uwgtrace/tracer_linux_amd64.go` and
  `internal/uwgtrace/seccomp_linux_amd64.go` contain the mature amd64 tracer.
- `internal/uwgtrace/tracer_arm64.go` and
  `internal/uwgtrace/seccomp_arm64.go` contain the Termux/Linux arm64 port.
- `internal/uwgtrace/tracer_stub.go` covers unsupported OS/architecture pairs.
- Some historical tests still focus on `linux/amd64`; add Android/arm64 smoke
  coverage as the phone workflow stabilizes.

If working from an older checkout that only has the amd64 tracer, prove preload
and `uwgsocks` first, then port the tracer. Do not expect ptrace support to
appear just by building on Termux.

## Capability Probes

Create tiny one-file probes before touching the project. Keep them in
`/tmp/uwg-termux-probes` or `tests/termux/probes` if they become useful tests.

Probe `LD_PRELOAD`:

- Build a small `.so` that wraps `connect`, `socket`, `read`, and `write`.
- Run it against Termux `curl` or a tiny C client.
- Confirm the symbols are intercepted on dynamically linked Termux binaries.
- Confirm Go static binaries are not intercepted and therefore need ptrace.

Probe `ptrace`:

- Parent forks a child.
- Child does `PTRACE_TRACEME`, raises `SIGSTOP`, then performs `socket`,
  `connect`, `sendmsg`, `recvmsg`, `readv`, and `writev`.
- Parent sets `PTRACE_O_TRACESYSGOOD`, resumes with `PTRACE_SYSCALL`, and logs
  syscall entry/exit.
- If this fails with `EPERM`, document it and test preload-only first. On an
  unrooted phone we only need same-app/same-UID tracing, not cross-app tracing.

Probe seccomp:

- Install a minimal seccomp filter returning `SECCOMP_RET_TRACE` for `getpid`.
- Attach the ptracer with `PTRACE_O_TRACESECCOMP`.
- Confirm a `PTRACE_EVENT_SECCOMP` stop is received.
- If seccomp trace is blocked on arm64, prefer documenting that ptrace wrapper
  modes are unavailable in that environment. Do not silently fall back to
  `ptrace-only` unless syscall-entry/exit detection has been proven reliable on
  that exact kernel.

Probe memory copying:

- Confirm `process_vm_readv` and `process_vm_writev` work against the traced
  child. The current tracer uses them heavily for sockaddr, msghdr, iovec, and
  payload copying.
- If Android blocks them, add a fallback using `PTRACE_PEEKDATA` and
  `PTRACE_POKEDATA`.

Probe `PR_SET_NO_NEW_PRIVS`:

- Confirm `prctl(PR_SET_NO_NEW_PRIVS, 1)` succeeds.
- Keep wrapper default `--no-new-privileges=true`.

## Build Strategy

Do not use `compile.sh` blindly at first. It currently assumes a normal Linux
build, gcc, and a preload asset that is built before the Go wrapper.

Start with the pure Go parts:

```bash
go test ./internal/config ./internal/engine ./internal/fdproxy ./internal/uwgshared
go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
./uwgsocks --help
```

Build the preload library with Termux clang:

```bash
mkdir -p ./cmd/uwgwrapper/assets
clang -shared -fPIC -O2 -Wall -Wextra \
  -o ./cmd/uwgwrapper/assets/uwgpreload.so \
  preload/uwgpreload.c -ldl -pthread
```

Then build the wrapper:

```bash
go build -trimpath -ldflags='-s -w' -o uwgwrapper ./cmd/uwgwrapper
./uwgwrapper --help
```

If Go reports `GOOS=android` and build tags exclude Linux tracer files, decide
explicitly whether to support `android && arm64` build tags, `linux && arm64`
build tags under a proot/container, or both. Native Termux normally means
`android/arm64`, even though the kernel ABI is Linux-like.

## Porting Plan

### 1. Split tracer architecture code

The current tracer code directly references amd64 register names like
`Orig_rax`, `Rax`, `Rdi`, `Rsi`, `Rdx`, `R10`, `R8`, and `R9`. Refactor before
adding arm64.

Suggested shape:

```go
type syscallRegs struct {
	nr   int64
	args [6]uint64
	ret  uint64
}

type nativeRegs struct {
	// architecture-specific ptrace register payload
}
```

Add architecture helpers:

- `getSyscallRegs(tid int) (nativeRegs, syscallRegs, error)`
- `setSyscallRegs(tid int, nativeRegs, syscallRegs) error`
- `setSyscallReturnAndSkip(tid int, nativeRegs, result int64) error`
- `rewriteSyscall(tid int, nativeRegs, nr int64, args [6]uint64) error`

Keep socket emulation logic generic. Only register extraction, return setting,
syscall skipping, and seccomp arch constants should be architecture-specific.

### 2. Implement arm64 register mapping

On aarch64 Linux syscall arguments are in `x0` through `x5`, the syscall number
is in `x8`, and the return value is in `x0`. The preload/ptrace secret should
therefore be checked in argument 6, `x5`, for secret-bypass syscalls.

In Go's `x/sys/unix`, arm64 has `unix.PtraceRegs` with:

- `Regs[0]` through `Regs[5]`: syscall args
- `Regs[8]`: syscall number on syscall entry
- `Regs[0]`: return value on syscall exit

Do not trust this blindly. Verify it with the ptrace probe and a known syscall
like `getpid` before porting all handlers.

### 3. Implement arm64 seccomp

The BPF layout of `struct seccomp_data` is the same idea, but the arch check
must use `AUDIT_ARCH_AARCH64` instead of `AUDIT_ARCH_X86_64`.

Keep both filters:

- simple seccomp: trace only syscalls we care about
- secret seccomp: trace relevant syscalls unless argument 6 equals the shared
  preload secret

Use one syscall dispatch table and architecture-specific constants. The current
optimized pattern in `seccomp_linux_amd64.go` should be preserved: arch check,
load syscall number once, jump to one of the shared terminal blocks, otherwise
allow.

### 4. Audit preload for Bionic

`preload/uwgpreload.c` should be compiled and tested against Android Bionic.
Expect small incompatibilities:

- Some glibc-only aliases may not exist.
- `fopencookie` support must be verified.
- `sendmmsg` and `recvmmsg` declarations may need Android feature guards.
- `SYS_*` numbers are architecture-specific but should be provided by Termux
  headers when building natively.
- Existing Termux `LD_PRELOAD` entries must remain in the environment.

Do not remove glibc support while fixing Bionic. Use feature guards and small
compatibility wrappers.

### 5. Update test gating

After the port, change wrapper tests from `linux/amd64 only` to supported
platform checks, likely:

- `linux/amd64`
- `android/arm64` if native Termux works
- optionally `linux/arm64` if tested under a normal arm64 distro/container

The tests should skip individual transports when a probe says seccomp or ptrace
is unavailable, not skip the entire package.

## Test Ladder

Run tests in this order. Do not start with `go test ./...`; on a phone, it is
slow, noisy, and hides the first useful failure.

### Level 0: build and static checks

```bash
go test ./internal/config ./internal/uwgshared
go test ./internal/fdproxy
go test ./internal/engine -run 'Test.*Config|Test.*ACL|Test.*Conntrack'
go build ./cmd/uwgsocks
go build ./cmd/uwgwrapper
```

### Level 1: uwgsocks rootless server/client

Use two local `uwgsocks` processes with the example exit server/client configs.
Keep everything on loopback first.

```bash
./uwgsocks --config ./examples/exit-server.yaml
./uwgsocks --config ./examples/exit-client.yaml
curl -x socks5h://127.0.0.1:1080 http://example.com/
curl http://127.0.0.1:9090/v1/status
```

Expected result: HTTP/SOCKS proxying works without root and without `/dev/net/tun`.

### Level 2: preload only

```bash
./uwgwrapper --transport preload --api http://127.0.0.1:8080 -- curl -v http://example.com/
```

Then run focused tests:

```bash
go test ./tests/preload -run 'TestUWGWrapper.*Preload|TestUWGWrapperMessageSyscallsAcrossTransports' -count=1 -timeout 5m
```

If preload works but ptrace does not, keep going with the tracer port. That is
still progress.

### Level 3: ptrace only

```bash
./uwgwrapper --transport ptrace-only --api http://127.0.0.1:8080 -- curl -v http://example.com/
go test ./tests/preload -run 'TestUWGWrapper.*Ptrace|TestUWGWrapperMessageSyscallsAcrossTransports' -count=1 -timeout 5m
```

This proves static/inlined syscalls can be caught even without seccomp.

### Level 4: ptrace plus simple seccomp

```bash
./uwgwrapper --transport ptrace-seccomp --api http://127.0.0.1:8080 -- curl -v http://example.com/
go test ./internal/uwgtrace
go test ./tests/preload -run 'TestUWGWrapperPtraceSeccomp|TestUWGWrapperMessageSyscallsAcrossTransports' -count=1 -timeout 5m
```

This proves Android allows `SECCOMP_RET_TRACE` for the same-app tracee.

### Level 5: preload plus ptrace combo

```bash
./uwgwrapper --transport preload-and-ptrace --api http://127.0.0.1:8080 -- curl -v http://example.com/
```

Run stats tests and verify normal file I/O does not cold-path into ptrace:

```bash
go test ./tests/preload -run 'TestUWGWrapperPtraceSeccompSocketSyscallSurfaceStats|TestUWGWrapperStdioHeavy' -count=1 -timeout 5m
```

The important performance property is that libc socket hot paths use preload
and only static/inlined or not-yet-hot syscalls reach ptrace.

### Level 6: broader suite

Only after focused tests pass:

```bash
go test ./tests/preload -count=1 -timeout 15m
go test ./... -count=1 -timeout 30m
```

Avoid running multiple wrapper integration tests in parallel until fixed-port
tests are audited. Several tests intentionally start local WireGuard peers and
fdproxy listeners.

## UI Server On The Phone

The target proof is: the phone runs `uwgsocks-ui`, the UI manages a rootless
`uwgsocks` server process, and another WireGuard peer can connect to the phone.

Build `uwgsocks` first:

```bash
go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
```

Build the UI. On-device frontend builds may be slow; if npm is too heavy,
extract or copy a known-good `dist` and use `-frontend-dir`.

```bash
cd uwgsocks-ui
npm --prefix frontend install
npm --prefix frontend run build
rm -rf dist
mkdir -p dist
cp -r frontend/dist/* dist/
CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o uwgsocks-ui .
```

Run as a rootless userspace WireGuard server:

```bash
mkdir -p phone-data
./uwgsocks-ui \
  -listen 0.0.0.0:8080 \
  -data-dir ./phone-data \
  -daemon-path ../uwgsocks \
  -wg-url unix://uwgsocks.sock \
  -generate-config=true
```

Notes:

- Do not enable `-system` or `-auto-system` for the unrooted proof. `uwgkm`
  manages kernel WireGuard and is not the goal on Android.
- Listen ports above 1024 are safest on unrooted Android.
- For LAN testing, keep the phone awake with `termux-wake-lock` and disable
  aggressive battery optimization for Termux.
- If the phone is behind carrier NAT, inbound Internet peers need port
  forwarding, a LAN test, or TURN-assisted connectivity.

Acceptance checks:

```bash
curl -I http://127.0.0.1:8080/
curl http://127.0.0.1:8080/login.html
curl --unix-socket ./phone-data/uwgsocks.sock http://unix/v1/status
```

From another device on the same LAN:

```bash
curl -I http://PHONE_LAN_IP:8080/
```

Then import the generated WireGuard peer config on another client and verify:

- handshake appears in the UI
- status API shows bytes moving
- peer can reach a phone-hosted reverse forward or DNS/proxy service
- ACL and traffic-shaper changes apply at runtime

## What "All Tests Pass" Means Here

For this port, "all tests pass" should be staged:

- All non-wrapper Go tests pass on Android/arm64 or have a documented Android
  skip for a real OS limitation.
- Preload-only wrapper tests pass on dynamically linked Termux programs.
- Ptrace-only wrapper tests pass for direct/static syscalls.
- Ptrace+seccomp tests pass if Android allows `SECCOMP_RET_TRACE`; otherwise
  they skip with a probe-backed reason and `ptrace-only` remains supported.
- Combo mode passes when both preload and seccomp trace are available.
- UI server tests pass without kernel WireGuard mode.
- Any TUN tests skip on unrooted Android unless a real accessible TUN device is
  present.

Skips must be precise. A good skip says "Android arm64: seccomp trace probe
returned EPERM" rather than "unsupported platform".

## Debugging Checklist

Use these when something fails:

```bash
UWGS_WRAPPER_DEBUG=1 UWGS_PRELOAD_DEBUG=1 ./uwgwrapper ...
strace -f -o /tmp/uwg.strace ./uwgwrapper ...
logcat -d | grep -i 'avc\\|seccomp\\|ptrace\\|uwg'
readelf -h ./uwgwrapper
readelf -l ./cmd/uwgwrapper/assets/uwgpreload.so
ldd ./cmd/uwgwrapper/assets/uwgpreload.so || true
```

Common failure shapes:

- `LD_PRELOAD` ignored: target is static, setuid-like, or Android linker refused
  the library.
- `Permission denied` on exec: wrong storage location or Android app-data
  execution restriction.
- `No such file or directory` for a script: shebang points at `/bin` or
  `/usr/bin`; Termux path rewriting may require preserving `termux-exec`.
- `ptrace EPERM`: Android policy blocks tracing in this environment; document
  and continue with preload-only unless same-UID tracing can be made to work.
- `process_vm_readv EPERM`: implement ptrace peek/poke fallback.
- `seccomp ENOSYS` or no seccomp event: fall back to `ptrace-only`.
- IPv6 connect hangs: make sure uwgsocks rejects unavailable IPv6 immediately so
  applications try IPv4.

## References Checked

- Termux execution environment: app-data execute restrictions, Termux path
  behavior, dynamic linking, and `termux-exec` interaction:
  <https://github.com/termux/termux-packages/wiki/Termux-execution-environment>
- Termux package building notes, including aarch64 defaults and local package
  builds:
  <https://github.com/termux/termux-packages/wiki/Building-packages>
- Linux seccomp filter behavior for `SECCOMP_RET_TRACE` and ptrace:
  <https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.10-2023-07_r1/Documentation/userspace-api/seccomp_filter.rst>
- Termux install/source guidance discussion:
  <https://github.com/termux/termux-app/discussions/4000>
