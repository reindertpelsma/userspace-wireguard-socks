# Compatibility

This page answers the practical question: what can I expect to work on each
platform, and how hard has it actually been exercised?

Status terms used below:

- `CI`: exercised automatically in GitHub Actions
- `Manual`: tested on real hosts, but not on every push
- `Cross-build`: release/build coverage only
- `No`: not supported

## Feature Matrix

| Feature | Linux | macOS | Windows | FreeBSD | OpenBSD |
| --- | --- | --- | --- | --- | --- |
| Core `uwgsocks` client/server, proxies, forwards, ACLs, relay, mesh | CI | CI | CI | Manual | Manual, treat as experimental |
| Host TUN mode | CI | CI | CI | Manual | Manual, treat as experimental |
| Pluggable transports (`udp`, `https`, `quic`, `turn`, `tls`, `http`) | CI | CI | CI | Manual | Manual, treat QUIC as lightly tested |
| Standalone `turn` daemon | CI | CI | CI | Cross-build | Cross-build |
| `uwgsocks-lite` | CI | CI | CI | Cross-build | Cross-build |
| `uwgwrapper` / preload / ptrace interception | CI on glibc and musl | No | No | No | No |

## What Most Users Should Assume

- Linux is the reference platform for the full feature set.
- macOS and Windows are strong for the main `uwgsocks` data plane, proxies,
  forwards, mesh, transports, and host-TUN mode.
- FreeBSD and OpenBSD are real targets, not theoretical ports, but they still
  deserve a more conservative production posture than Linux or macOS.
- `uwgwrapper` is intentionally Linux-only.

## Platform Notes

### Linux

- Best-tested platform for `uwgsocks`.
- Best-tested platform for `uwgwrapper`.
- Release builds ship glibc and musl wrapper variants for `amd64` and `arm64`.
- Host-TUN, mesh, ACLs, reverse forwards, and transport modes are all part of
  the normal exercised surface.

#### `uwgwrapper` libc compatibility matrix

`uwgpreload.so` is the load-bearing piece for the wrapper — if it can't link
against the host's libc cleanly, the whole wrapper subsystem fails to start.
The matrix below was validated by building the `.so` inside each container
against its native libc, loading it via `LD_PRELOAD`, and running a
socket+close probe under the loaded library. The script lives in
[`scripts/docker-libc-matrix/`](../../scripts/docker-libc-matrix/) — re-run
it on any Linux Docker host with `bash scripts/docker-libc-matrix/run-matrix.sh`.

| Distribution | libc fingerprint | amd64 | arm64 |
| --- | --- | :---: | :---: |
| Ubuntu 18.04 (Bionic) | glibc 2.27 | PASS | PASS |
| Ubuntu 20.04 (Focal) | glibc 2.31 | PASS | PASS |
| Ubuntu 22.04 (Jammy) | glibc 2.35 | PASS | PASS |
| Ubuntu 24.04 (Noble) | glibc 2.39 | PASS | PASS |
| Ubuntu 25.10 | glibc 2.42 | PASS | PASS |
| Debian 11 (Bullseye) | glibc 2.31 | PASS | PASS |
| Debian 13 (Trixie) | glibc 2.41 | PASS | PASS |
| Alpine 3.10 | musl 1.1.22 | PASS | PASS |
| Alpine 3.16 | musl 1.2.3 | PASS | PASS |
| Alpine 3.20 | musl 1.2.5-r3 | PASS | PASS |
| Alpine 3.22 | musl 1.2.5-r12 | PASS | PASS |

Coverage spans every glibc release shipped by Ubuntu since 2018 (2.27 → 2.42)
and every musl in current Alpine releases (1.1.22 → 1.2.5). Both 32-bit-only
historical libc quirks (Alpine 3.10's musl 1.1) and the very latest glibc
quirks (e.g., the 2.43+ `select(2)` → `pselect6(2)` mapping) are exercised.

#### `uwgwrapper` full-suite + browser validation

Beyond the smoke test, the local validation matrix exercises the
**entire `go test ./...`** suite (race-clean, full integration tests)
under five glibc/musl versions on each arch:

| Distribution | libc | amd64 | arm64 |
| --- | --- | :---: | :---: |
| Ubuntu 18.04 | glibc 2.27 | full ✓ | full ✓ |
| Debian Bullseye | glibc 2.31 | full ✓ | full ✓ |
| Debian Bookworm | glibc 2.36 | full ✓ | full ✓ |
| Alpine current (golang:alpine) | musl 1.2.5+ | full ✓ | full ✓ |
| Alpine 3.16 | musl 1.2.3 | full ✓ | full ✓ |

A separate **headless-Chromium** matrix runs the wrapper end-to-end with
a real browser through both bare ptrace and preload+ptrace transports.
This catches the syscall-pattern complexity (TLS init, async DNS,
multi-process renderer fd sharing) that simpler stubs miss:

| Distribution | libc | amd64 ptrace | amd64 preload+ptrace | arm64 ptrace | arm64 preload+ptrace |
| --- | --- | :---: | :---: | :---: | :---: |
| Debian Bookworm | glibc 2.36 | ✓ | ✓ | ✓ | ✓ |
| Alpine 3.20 | musl 1.2.5 | ✓ | ✓ | ✓ | ✓ |

CI runs an equivalent smaller matrix on every release tag (see
`.github/workflows/release.yml` jobs `preload-libc-matrix` and
`preload-chromium-matrix`) so regressions surface before publish.

### macOS

- Core `uwgsocks` functionality is exercised in CI.
- Host-TUN uses the native `utun` interface.
- QUIC works, but Linux is still the safer baseline if QUIC is central to your
  deployment.
- No `uwgwrapper`.

### Windows

- Core `uwgsocks` functionality is exercised in CI.
- Host-TUN requires `wintun.dll`.
- SOCKS5, HTTP proxy, forwards, reverse forwards, mesh, and runtime API work
  without host-TUN.
- No `uwgwrapper`.

### FreeBSD

- Core `uwgsocks` functionality is manually validated on real hosts.
- Host-TUN uses the native `tun` interface.
- Treat it as supported, but still with less repeated coverage than Linux.
- No `uwgwrapper`.

### OpenBSD

- Core functionality has been exercised manually, but the project should still
  be treated as experimental here.
- Host-TUN support exists.
- No `uwgwrapper`.

## Additional Build Targets

Release artifacts also cover extra targets where runtime confidence is lower
than the primary platforms:

| Target | Current confidence |
| --- | --- |
| Linux `riscv64` | Cross-build and limited emulated validation |
| Linux `mips` / `mipsle` | Cross-build only |
| Windows `arm64` | Release artifact shipped; lighter runtime coverage than `amd64` |

If you need one sentence: use Linux for the full surface, use macOS and Windows
confidently for the main data plane, and treat BSD and exotic targets as
deliberate but less battle-tested deployments.
