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
