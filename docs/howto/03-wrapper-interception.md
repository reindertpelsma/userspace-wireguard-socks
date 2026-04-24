<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 03 Wrapper Interception

Previous: [02 Server And Ingress](02-server-and-ingress.md)  
Next: [04 Firewall And ACLs](04-firewall-and-acls.md)

`uwgwrapper` forces unmodified Linux applications through the mesh, including
programs that do not speak SOCKS5 or HTTP and even statically linked binaries
that bypass libc fast paths.

## Start The Wrapper-Friendly Daemon

```bash
./uwgsocks --config ./examples/socksify.yaml
```

The example is [`examples/socksify.yaml`](../../examples/socksify.yaml):

```yaml
wireguard:
  config_file: ./examples/client.conf

api:
  listen: unix:/tmp/uwgsocks-api.sock
  allow_unauthenticated_unix: true

proxy:
  http_listeners:
    - unix:/tmp/uwgsocks-http.sock

socket_api:
  bind: true
  transparent_bind: false
  udp_inbound: false
```

That gives you two local control points:

- a management API socket at `unix:/tmp/uwgsocks-api.sock`
- an HTTP upgrade listener at `unix:/tmp/uwgsocks-http.sock`

`uwgwrapper` uses the HTTP upgrade listener, not a separate daemon protocol.
That listener can live on a Unix socket file or on a loopback HTTP address.

## Wrap An Unmodified Linux App

```bash
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock -- curl https://ifconfig.me
```

That is the common case: same host, Unix socket transport, and no extra TCP
listener.

## Unix Socket Or HTTP URL

Use a Unix socket when the daemon is local and you want filesystem-scoped
access:

```bash
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock -- curl https://ifconfig.me
```

Use an HTTP URL when the wrapper needs to reach the daemon over loopback or a
supervised local TCP listener:

```bash
./uwgsocks --config ./examples/server.yaml
./uwgwrapper --api http://127.0.0.1:9090 --token demo-api-token-change-me -- curl https://ifconfig.me
```

Both routes end up at the same `/uwg/socket` raw socket API.

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

## Which Path Should You Prefer?

- Use native SOCKS5 or HTTP if the app already supports it.
- Use `--stdio-connect` when the caller already speaks stdin/stdout socket semantics, such as SSH `ProxyCommand`.
- Use `uwgwrapper` when the app cannot speak SOCKS5 or HTTP directly, whether it is hard-coded, static, or just not proxy-aware.

The wrapper is a compatibility layer, not a sandbox. It forces network syscalls
through `uwgsocks`; it does not change the process' Unix privileges.

## Why It Still Works On Static Go Or Rust Binaries

- `LD_PRELOAD` catches the easy libc path.
- `seccomp-bpf` reduces ptrace overhead on supported Linux systems.
- `ptrace` remains as the fallback for static binaries and direct syscalls.

That combination is why `uwgwrapper` is closer to “socksify for any Linux
binary” than to a normal proxy helper.
