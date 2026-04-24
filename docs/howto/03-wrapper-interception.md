<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 03 Wrapper Interception

Previous: [02 Server And Ingress](02-server-and-ingress.md)  
Next: [04 Firewall And ACLs](04-firewall-and-acls.md)

`uwgwrapper` forces unmodified Linux applications through the mesh, including
programs that do not speak SOCKS5 or HTTP and even statically linked binaries
that bypass libc fast paths.

It does that with:

- `LD_PRELOAD` for the cheap path
- `seccomp-bpf` to cut ptrace overhead
- `ptrace` fallback for static Go/Rust binaries and direct syscalls

## Start The Wrapper-Friendly Daemon

```bash
./uwgsocks --config ./examples/socksify.yaml
```

That example exposes:

- API socket: `unix:/tmp/uwgsocks-api.sock`
- HTTP upgrade socket: `unix:/tmp/uwgsocks-http.sock`

## Wrap An Unmodified App

```bash
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock -- curl https://ifconfig.me
```

That uses the Unix HTTP listener and upgrades to `/uwg/socket`.

## HTTP URL Instead Of Unix Socket

If `uwgsocks` exposes an HTTP API listener instead:

```bash
./uwgsocks --config ./examples/server.yaml
./uwgwrapper --api http://127.0.0.1:9090 --token demo-api-token-change-me -- curl https://ifconfig.me
```

Use:

- `unix:/path.sock` when the daemon is local and you want filesystem-scoped access
- `http://127.0.0.1:9090` when you want the wrapper to upgrade through the authenticated API listener

## SSH ProxyCommand / stdin Mode

If you do not need `LD_PRELOAD` at all and only want a clean TCP pipe over the
tunnel, `uwgwrapper` can bridge stdin/stdout directly to one tunnel TCP
destination:

```bash
./uwgwrapper \
  --api unix:/tmp/uwgsocks-http.sock \
  --stdio-connect 100.64.90.10:22
```

That is useful as an SSH `ProxyCommand`:

```sshconfig
Host mesh-host
  HostName 100.64.90.10
  ProxyCommand /usr/local/bin/uwgwrapper --api unix:/tmp/uwgsocks-http.sock --stdio-connect %h:%p
```

This path does not consume another WireGuard peer. It is just one more tunnel
TCP stream created through `/uwg/socket`, so multiple commands can be stacked
or run in parallel without editing the peer list.

## Which One Should You Prefer?

- Use native SOCKS5 or HTTP if the app already supports it.
- Use `--stdio-connect` when the caller already speaks stdin/stdout socket semantics, such as SSH `ProxyCommand`.
- Use `uwgwrapper` when the app cannot speak SOCKS5 or HTTP directly, whether it is hard-coded, static, or just not proxy-aware.

The wrapper is a compatibility layer, not a sandbox. It forces network syscalls
through `uwgsocks`; it does not change the process' Unix privileges.

## Explicit fdproxy Mode

If you want a persistent sidecar instead of `uwgwrapper -- app`:

```bash
./uwgwrapper --mode=fdproxy \
  --listen /tmp/fdproxy.sock \
  --api unix:/tmp/uwgsocks-http.sock
```

Then launch apps with:

```bash
LD_PRELOAD=/tmp/uwgwrapper-$(id -u)/uwgpreload-*.so \
UWGS_FDPROXY=/tmp/fdproxy.sock \
curl https://ifconfig.me
```
