<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Host-TUN backend

Optional. When `tun.enabled: true`, `uwgsocks` creates a real TUN
device on the host and wires the WireGuard tunnel to it instead
of (or alongside) the gVisor netstack. The host's kernel does the
L3 routing.

When you DON'T need this:
- Most rootless deployments. SOCKS5 / HTTP / forwards / wrapper
  reach the tunnel without a kernel TUN.
- Containers without `--cap-add=NET_ADMIN`.

When you DO need this:
- Routing the host's default gateway through the tunnel.
- Supporting any application that won't speak SOCKS5 / HTTP.
- Bridging to other tunnels via the kernel routing table.

## Backend matrix

| OS | Backend | Notes |
|---|---|---|
| Linux | `/dev/net/tun` (kernel module) | Needs `cap_net_admin` or root. `setcap cap_net_admin+ep ./uwgsocks` is the recommended path. |
| macOS | `utun` device (kernel built-in) | Needs root or an entitlement. `sudo` works for development. |
| Windows | `wintun.dll` | Download from [wintun.net](https://www.wintun.net/), place in `C:\Windows\System32\` or alongside the binary. |
| FreeBSD | `tun(4)` device | Needs `if_tap` / `if_tun` kernel module. |
| OpenBSD | `tun(4)` device | Same. DNS automation is intentionally simple — `tun.dns_resolv_conf` is the safest cross-platform mechanism. |

## What the backend manages

| Operation | Implemented per-OS |
|---|---|
| Create / start / stop the device | Yes |
| Add / remove tunnel addresses | Yes |
| Add / remove routes | Linux + macOS + Windows; BSD uses ifconfig/route conventions |
| DNS resolver hooks | Linux (systemd-resolved + resolvconf), macOS (scutil), Windows (NRPT). BSD opts into `tun.dns_resolv_conf` (rewrites `/etc/resolv.conf`). |
| Bypass-route snapshots | Linux only — captures routes that should bypass the tunnel for outbound dialer use. |

## Linux specifics

- **fwmark**: documented as a future opt-in; not currently exposed.
  When implemented, will let kernel iptables/nftables route by
  packet mark, not just destination.
- **Policy routing**: same — future opt-in. Today, host routing
  changes are explicit + opinionated.

## BSD specifics

- DNS automation is deliberately minimal. `tun.dns_resolv_conf` is
  the most portable mechanism. Distribution-specific tools
  (`resolvconf`, etc.) aren't auto-detected.
- Real-host validation has been done manually on FreeBSD + OpenBSD;
  CI cross-builds these targets but doesn't run-test them (no
  GitHub-hosted BSD runners). See
  [reference/compatibility.md](../reference/compatibility.md) for the
  current status.

## Configuration

```yaml
tun:
  enabled: true
  name: "uwgsocks0"            # Linux only; ignored on macOS (auto-named utunN)
  route_allowed_ips: true      # add peer AllowedIPs as kernel routes
  default_route: false         # CAUTION: capture the default route
  dns_resolv_conf: false       # BSD-style /etc/resolv.conf rewrite
```

See [reference/config-reference.md](../reference/config-reference.md)
for every key under `tun:`.

## Cross-OS quirks

- **macOS utun number sparseness**: utun device numbers can be
  scattered. The backend picks the first free `utunN`. If you
  see "device or resource busy" raise `tun.utun_max_attempts`.
- **Windows path-required**: `wintun.dll` MUST be in a path
  Windows can locate before `uwgsocks` starts. Putting it
  alongside the binary is most reliable.
- **OpenBSD pf interaction**: OpenBSD's `pf` doesn't bind
  `/etc/pf.conf` rules to dynamically-created tun devices. Add
  `pass` rules for the tunnel interface manually.

See [operations/runbook.md](../operations/runbook.md) for "TUN
device can't be opened" troubleshooting.
