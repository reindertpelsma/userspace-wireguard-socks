<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 03 Wrapper Interception

Previous: [02 Server And Ingress](02-server-and-ingress.md)  
Next: [04 Firewall And ACLs](04-firewall-and-acls.md)

This is the stealth move.

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

## Which One Should You Prefer?

- Use native SOCKS5 or HTTP if the app already supports it.
- Use `uwgwrapper` when the app is hard-coded, legacy, or static.

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
