<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Wrapper And fdproxy

`uwgwrapper` is the socksify-style path for applications that do not support
SOCKS or HTTP themselves.

Basic launch mode:

```bash
./uwgsocks --config ./examples/exit-client.yaml
./uwgwrapper --api http://127.0.0.1:8080 -- curl -v https://www.google.com
```

Throughput smoke test with a real WireGuard config:

```bash
./uwgsocks --wg-config ./my-provider.conf --http unix:/tmp/http.sock &
./uwgwrapper --api unix:/tmp/http.sock -- speedtest-cli
```

## Model

The wrapper combines:

- a preload fast path for common libc socket calls
- seccomp filtering so handled syscalls do not bounce through ptrace unnecessarily
- ptrace fallback for static or inlined syscalls that bypass libc
- `uwgfdproxy` as the local Unix-socket bridge to `uwgsocks`

Data path:

```text
application
  -> uwgpreload.so overriding libc socket functions
  -> local UNIX socket
  -> uwgfdproxy
  -> uwgsocks raw socket API
  -> WireGuard
```

## Transport Modes

- `auto`: choose the best available mode
- `preload-and-ptrace`: preload + seccomp + ptrace fallback
- `ptrace`: ptrace + simple seccomp filter
- `ptrace-only`: ptrace without seccomp
- `preload`: preload only

Prefer SOCKS or HTTP for applications that already support them. Use the
wrapper only when the application cannot be configured that way.

`uwgwrapper` is a compatibility layer, not an application sandbox. A process
running under the wrapper still has the normal privileges of its Unix user and
can intentionally choose direct networking or inspect its own address space.
The preload shared-state and passthrough secret are there to coordinate the hot
path with ptrace/seccomp, not to prevent a malicious local application from
escaping the tunnel.

## Current Capabilities

- TCP and UDP sockets
- outbound unprivileged ICMP ping sockets
- connected TCP and UDP preserve explicit `bind(2)` source IP and port when the destination is WireGuard-routed
- TCP listeners and unconnected UDP listeners in the tunnel when `proxy.bind` or `socket_api.bind` is enabled
- `SO_REUSEADDR` and `SO_REUSEPORT` within one fdproxy instance
- loopback bypass for explicit local loopback traffic
- IPv6 support when the tunnel configuration supports it, with immediate rejection when the app tries IPv6 but the tunnel cannot carry it
- multi-thread, multi-process, fork, and exec support

`NO_NEW_PRIVILEGES` is enabled by default for launched processes.

## Limitations

- preload-only mode cannot catch static binaries or libraries that never call libc
- the wrapper does not work across user boundaries
- loopback traffic is intentionally not tunneled
- `SO_REUSEPORT` is local to one fdproxy instance and is not coordinated across different wrapper processes
- support is still experimental compared with direct SOCKS or HTTP

## Explicit fdproxy Daemon Mode

If you want applications to start without a `uwgwrapper -- ...` launcher in
front of them:

```bash
./uwgwrapper --mode=fdproxy --listen /tmp/fdproxy.sock \
  --api unix:/tmp/http.sock --socket-path /uwg/socket

LD_PRELOAD=/tmp/uwgwrapper-$(id -u)/uwgpreload-*.so \
UWGS_FDPROXY=/tmp/fdproxy.sock \
  wget https://www.google.com

./uwgwrapper --spawn-fdproxy=false --listen /tmp/fdproxy.sock \
  --api unix:/tmp/http.sock --socket-path /uwg/socket -- \
  wget https://www.google.com
```

`fdproxy.sock` must be a Unix socket inside the same environment as the
application. Access is controlled with normal filesystem permissions.

## DNS Notes

The preload library overrides common libc DNS resolution calls so applications
do not silently use `/etc/hosts` or `/etc/resolv.conf` when the intent is to
route DNS through WireGuard. Some applications bypass libc and make raw DNS
connections themselves, so by default the wrapper also rewrites connected
TCP and UDP port-53 sockets toward the tunnel DNS when appropriate.

For the configuration that controls tunnel DNS and raw socket access, see
[Configuration and Routing](configuration-and-routing.md) and
[Raw socket API](../socket-protocol.md).
