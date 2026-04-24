<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Configuration

`uwgsocks` merges configuration from three layers:

1. YAML runtime config (`--config`)
2. wg-quick style config (`wireguard.config_file`, `wireguard.config`, `--wg-config`, `--wg-inline`)
3. CLI flags

Use this page to understand what each block is for and how the pieces fit
together. Use [config-reference.md](config-reference.md) when you already know
what you want and need the exact field names.

## 1. WireGuard

This is the core identity, addressing, and peer routing layer.

```yaml
wireguard:
  private_key: ""
  listen_port: 51820
  listen_addresses: []
  addresses: []
  mtu: 1420
  config_file: ./wg0.conf
  peers:
    - public_key: ""
      endpoint: ""
      allowed_ips: []
      persistent_keepalive: 25
      transport: ""
```

Use this block for:

- the interface private key
- tunnel addresses
- the direct WireGuard UDP listen port when applicable
- peer identity, endpoints, and `AllowedIPs`
- per-peer transport selection

Important points:

- `AllowedIPs` still define the routed subnets, just like normal WireGuard.
- `wireguard.peers[].transport` selects a named outer transport from
  `transports:`.
- `control_url`, `mesh_enabled`, and related mesh flags are also peer settings,
  because mesh is built on top of real WireGuard peers, not beside them.
- wg-quick comment directives such as `#!URL=...`, `#!TURN=...`, and
  `#!Control=...` are understood by `uwgsocks` and ignored by standard
  WireGuard.

## 2. Forwards, Reverse Forwards, And Host Forwarding

This is how you turn tunnel connectivity into useful application entry points.

### `forwards`

Bind a host-local socket and dial a tunnel destination.

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:18081
    target: 100.64.90.1:8081
```

Use this when you want “local port forward over WireGuard.”

### `reverse_forwards`

Bind inside the userspace WireGuard network and send accepted traffic back to a
host service.

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8080
    target: 127.0.0.1:8080
```

Use this when you want “publish my local service into the WireGuard network.”

### Unix Sockets

Both directions support Unix sockets where that makes sense:

- `unix://`
- `unix+dgram://`
- `unix+seqpacket://`
- `unix+stream://`

That matters when a local service should not be exposed on loopback at all. See
[../howto/09-unix-socket-forwards.md](../howto/09-unix-socket-forwards.md).

### `host_forward`

Controls when proxy or inbound traffic may fall back to host-local services.

```yaml
host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1
  inbound:
    enabled: false
    redirect_ip: ""
```

Use this to decide whether tunnel traffic may reach host-local services when no
more specific tunnel listener owns the destination.

## 3. Proxies And Local Ingress

This is the host-facing application entry layer.

```yaml
proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
  mixed: ""
  outbound_proxies: []
  udp_associate: true
  bind: false
```

Use this block for:

- SOCKS5 proxy
- HTTP proxy
- mixed SOCKS5/HTTP listener
- upstream proxy chaining
- SOCKS5 UDP ASSOCIATE
- SOCKS5 BIND support

This is the normal choice when an app already knows how to use a proxy.

### `inbound`

Controls transparent inbound handling from WireGuard peers to host sockets.

```yaml
inbound:
  transparent: true
  consistent_port: loose
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30
```

Use this when the node should behave like a rootless WireGuard server or exit
node for inbound traffic.

### `socket_api`

The raw socket API behind `/v1/socket` and `/uwg/socket`.

Use this when you are building:

- sidecars
- custom SDK clients
- browser or tool integrations
- wrapper/fdproxy flows

### `api`

The runtime management API:

```yaml
api:
  listen: 127.0.0.1:9090
  token: replace-me
```

Use this for status, live peer updates, ACL replacement, and forward changes.

## 4. Mesh Control

Mesh control is the lightweight coordination plane for peer discovery and
distributed ACLs.

```yaml
mesh_control:
  listen: 100.64.80.1:8787
  challenge_rotate_seconds: 120
  active_peer_window_seconds: 120
```

And on peers:

```yaml
wireguard:
  peers:
    - public_key: HUB_PUBLIC_KEY
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      mesh_accept_acls: true
```

Use mesh control when you want:

- one private peer network instead of isolated client/server pairs
- direct peer discovery on top of a stable parent path
- more than one relay site sharing the same peer inventory
- projected ACLs enforced on clients as well as relays

Full details: [mesh-control.md](mesh-control.md)

## 5. Host TUN

Host TUN is optional. It exists for applications that need a kernel-visible
interface rather than a proxy or wrapper.

```yaml
tun:
  enabled: true
  name: uwgsocks0
  configure: true
  route_allowed_ips: true
  dns_servers: []
```

Use host TUN when:

- an app cannot use SOCKS5 or HTTP
- you are not on Linux and therefore cannot use `uwgwrapper`
- you explicitly want host routing changes

Use proxy or wrapper mode first if your goal is selective per-app routing
without touching the host network stack.

## 6. Firewall ACLs And Relay

Policy is split into `inbound`, `outbound`, and `relay` ACL planes:

```yaml
acl:
  inbound_default: deny
  outbound_default: allow
  relay_default: deny
  inbound: []
  outbound: []
  relay: []
```

And relay behavior is controlled separately:

```yaml
relay:
  enabled: true
  conntrack: true
  conntrack_max_flows: 65536
  conntrack_max_per_peer: 4096
```

Use this section when:

- peers should be allowed to reach only one service
- the node is relaying traffic between peers
- direct mesh paths and relay fallback should still obey the same projected policy

The detailed policy model is in [acls.md](acls.md).

## 7. Transports

Transports decide how WireGuard packets travel on the outside.

```yaml
transports:
  - name: udp
    base: udp
    listen: true
    listen_port: 51820

  - name: web
    base: https
    listen: true
    listen_port: 8443
    websocket:
      path: /wg

  - name: quic
    base: quic
    listen: true
    listen_port: 8443
    websocket:
      path: /wg
```

Use transports when:

- plain UDP is blocked or fingerprinted
- you want WireGuard to look like HTTPS or HTTP/3 traffic
- the server is hidden behind a TURN relay
- one deployment should expose more than one carrier mode at once

Common bases:

- `udp`
- `tcp`
- `tls`
- `dtls`
- `http`
- `https`
- `quic`
- `turn`

For tradeoffs and recommended usage, read [transport-modes.md](transport-modes.md).

## 8. Traffic Shaping And Supporting Services

### `traffic_shaper`

Applies upload/download ceilings and buffering latency:

```yaml
traffic_shaper:
  upload_bps: 0
  download_bps: 0
  latency_ms: 0
```

Use this when one peer or deployment should be bandwidth-capped or buffered
more gently.

### `dns_server`

Hosts a DNS server inside the tunnel:

```yaml
dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024
```

Use this when WireGuard peers should resolve names through the `uwgsocks` side
of the network.

### `routing` And `filtering`

Safety controls such as:

- reserve local tunnel subnets so misses do not leak to the host network
- drop obviously invalid IPv4 traffic early
- drop noisy IPv6 link-local multicast

### `scripts` And `log`

Operational controls:

- opt in to script hooks explicitly with `scripts.allow`
- enable verbose logging with `log.verbose`

## Preferred Reading Order

- Want exact fields: [config-reference.md](config-reference.md)
- Want policy details: [acls.md](acls.md)
- Want mesh behavior: [mesh-control.md](mesh-control.md)
- Want transport tradeoffs: [transport-modes.md](transport-modes.md)
- Want TURN behavior: [turn.md](turn.md)
