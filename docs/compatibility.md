# Compatibility

## Feature support

- Rootless WireGuard client and server mode.
- IPv4, IPv6, TCP, UDP, DNS, and ping-style ICMP/ICMPv6.
- HTTP proxy, SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, and SOCKS5 BIND.
- Local forwards and tunnel-side reverse forwards with optional PROXY protocol.
- Transparent inbound termination from WireGuard peers to host sockets.
- Peer-to-peer relay forwarding with ACLs and stateful conntrack.
- Runtime API for status, ping, peer updates, ACL updates, forwards, and
  WireGuard config replacement.
- Raw socket API for connected TCP/UDP/ICMP, TCP listeners, UDP listener-style
  sockets, DNS frames, and local fd bridging.
- `uwgwrapper` transport modes: preload only, preload + seccomp + ptrace,
  ptrace + simple seccomp, and ptrace without seccomp. `NO_NEW_PRIVILEGES` is
  enabled by default for launched processes.
- Per-peer and global traffic shaping for upload, download, and buffering
  latency. Runtime peer API updates can change shapers without restarting.
- Optional TURN bind mode, including `turn.include_wg_public_key` for relays
  that want the WireGuard public key embedded in the TURN username.

## Platform support

`uwgsocks` is the same binary for glibc and musl libc. `uwgwrapper` ships
separate binaries per libc because it embeds an `LD_PRELOAD` shared library.

### Primary platforms

Full test suite passing, including `uwgwrapper` preload and ptrace paths.

| Platform | Notes |
|---|---|
| Linux amd64 glibc | CI on every push (GitHub Actions `ubuntu-latest`) |
| Linux arm64 glibc | CI on every push (GitHub Actions `ubuntu-24.04-arm`) |
| Linux amd64 musl | CI on every release (Docker Alpine in GitHub Actions) |
| Linux arm64 musl | Manually tested on Raspberry Pi 4 running Alpine Linux |
| Linux amd64 gVisor | Tested; gVisor has minor sandboxing restrictions on ptrace paths |

### Secondary platforms

`uwgsocks` passes its full test suite. `uwgwrapper` is not built on these
platforms (no `LD_PRELOAD` / ptrace support outside Linux).

| Platform | Notes |
|---|---|
| macOS arm64 | CI on every push (GitHub Actions `macos-latest`); soak and race-detector tests run on Mac Mini M1 |
| Windows amd64 | CI on every push (GitHub Actions `windows-latest`) |
| Windows arm64 | Manually tested (arm64 VM on Raspberry Pi) |
| Linux arm64 Termux (Android) | Manually tested |

### Standalone TURN server artifacts

The standalone `turn/` server is also published as a release artifact.

| Platform | Status |
|---|---|
| Linux amd64 | CI-tested in `turn/`; release binary shipped |
| Linux arm64 | CI-tested in `turn/`; release binary shipped |
| Linux riscv64 | Cross-compiled release binary shipped |
| Linux mips64 | Cross-compiled release binary shipped |
| macOS amd64 | Cross-compiled release binary shipped |
| macOS arm64 | CI-tested in `turn/`; release binary shipped |
| Windows amd64 | CI-tested in `turn/`; release binary shipped |
| Windows arm64 | Cross-compiled release binary shipped |

### Exotic architecture builds

`uwgsocks` cross-compiles cleanly (`CGO_ENABLED=0`) and binaries are shipped
in releases. Runtime test coverage is limited to QEMU emulation.

| Platform | Status |
|---|---|
| Linux riscv64 | QEMU-tested: all core tests pass; one IPv6 ICMP test skipped due to QEMU network limitation |
| Linux mips (big-endian) | Build-only; no container images available for QEMU runtime testing |
| Linux mipsle (little-endian) | Build-only; targeted at EdgeRouter X and similar devices |

`uwgwrapper` is not built for exotic architectures. The `LD_PRELOAD` shim and
ptrace/seccomp filter tables are architecture-specific and only maintained for
amd64 and arm64.

## Known limitations by platform

**All non-Linux platforms:**
- No `uwgwrapper`. Applications without proxy support must use a system-level
  VPN or configure SOCKS5/HTTP proxy manually.
- No `uwgtrace`, `uwgfdproxy`, or ptrace-based interception.

**Windows:**
- Host TUN support requires [wintun](https://www.wintun.net/). SOCKS5/HTTP
  proxy and socket API modes work without it.
- Releases that want host-TUN support should ship the official signed
  `wintun.dll` beside `uwgsocks.exe`. Installing the same DLL in
  `C:\Windows\System32` also works.
- Host-TUN DNS configuration is best-effort through `netsh`.

**macOS:**
- Host TUN support uses the native `utun` interface and can be configured by
  `uwgsocks` itself or by external tooling.
- Host-TUN DNS server changes are not currently automated for `utun`.
- UDP buffer size warnings from quic-go are cosmetic on macOS; QUIC transport
  functions correctly.

**gVisor:**
- ptrace-based `uwgwrapper` modes are restricted by the sandbox. Preload-only
  mode works if the gVisor policy permits `dlopen`.

**riscv64 / mips / mipsle:**
- No `uwgwrapper`.
- IPv6 ICMP (ping6 through the tunnel) is unverified on real hardware; all
  other tested paths pass.
