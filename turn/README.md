# Open TURN Relay

This TURN server is tuned for UDP relay use cases where relay ports, WireGuard filtering, and policy control matter more than classic WebRTC media relay defaults.

It is built on Pion TURN and adds:
- fixed relay ports per user
- username-as-port range mode
<<<<<<< HEAD
- per-user dynamic port ranges, for outbound clients and for clients not needing a fixed port.
=======
- per-user dynamic port ranges
- multiple TURN listeners: UDP, TCP, TLS, and DTLS
- auto-generated TLS/DTLS certs when no files are configured, plus hot reload for certificate files
>>>>>>> droplet/master
- optional mapped/public relay addresses
- internal relay-to-relay routing optimization
- `outbound_only` users that may only receive replies after they send first
- `internal_only` users that may only talk to other TURN allocations on the same server
- optional WireGuard packet filtering on each relay port

## Quick Start

```bash
go build -o turn .
./turn -config turn-open-relay.example.yaml
```

Docker:

```bash
docker compose up --build
```

## Relay Model

The server supports three allocation styles:

1. Fixed user port:
   one username always gets one relay port.
2. Username-as-port range:
   the TURN username itself is the requested relay port inside a configured range.
3. Per-user dynamic port range:
   one username gets any free port inside its configured range, this user can then also connect multiple times.
   Unlike fixed user ports and the username-as-ports, this user can have multiple sessions.
   This is useful for users that are Wireguard clients, or Wireguard servers that only need a temporary ephermal port.

When one TURN client sends to the public `XOR-RELAYED-ADDRESS` of another live TURN client on the same server, the packet is routed internally inside the Go process instead of going out to the network. WireGuard guards still apply on both sides.

## Config Overview

Top-level fields:
- `realm`
- `software`
- `allocation_ttl`
- `nonce_ttl`
- `preopen_single_ports`
- `listen.relay_ip`
- `listeners`
- `max_sessions`

### Listeners

At least one listener is required. Each listener declares:
- `type`: `udp`, `tcp`, `tls`, or `dtls`
- `listen`: bind address, for example `0.0.0.0:3478`
- `cert_file` and `key_file` for `tls` or `dtls` listeners
- `reload_interval` to periodically reload renewed certificate files

If a `tls` or `dtls` listener is configured without certificate files, the server generates a self-signed certificate automatically at startup.

```yaml
listen:
  relay_ip: "203.0.113.10"

listeners:
  - type: "udp"
    listen: "0.0.0.0:3478"
  - type: "tcp"
    listen: "0.0.0.0:3478"
  - type: "tls"
    listen: "0.0.0.0:5349"
    cert_file: "/etc/letsencrypt/live/example/fullchain.pem"
    key_file: "/etc/letsencrypt/live/example/privkey.pem"
    reload_interval: "1m"
  - type: "dtls"
    listen: "0.0.0.0:5349"
```

### Fixed User

```yaml
users:
  - username: "alice"
    password: "alice-pass"
    port: 40000
    permission_behavior: "allow"
    source_networks:
      - "0.0.0.0/0"
    mapped_address: "203.0.113.10:40000"
```

Key fields:
- `port`: fixed relay port
- `mapped_address`: public relay address returned to clients
- `source_networks`: client IP allowlist
- `permission_behavior`: parsed and stored for policy compatibility

### Per-User Dynamic Port Range

```yaml
users:
  - username: "batch-worker"
    password: "batch-pass"
    port_range_start: 45000
    port_range_end: 45031
    mapped_range:
      ip: "203.0.113.10"
      start_port: 55000
```

The server will bind any free local port in `45000-45031`. If `mapped_range` is set, the returned public relay port is translated by offset.

### Username-As-Port Range

```yaml
port_ranges:
  - start: 41000
    end: 41099
    password: "shared-range-secret"
    permission_behavior: "allow-if-no-permissions"
    source_networks:
      - "0.0.0.0/0"
    mapped_range:
      ip: "203.0.113.10"
      start_port: 51000
```

Example:
- username `41005`
- password `shared-range-secret`
- internal relay port `41005`
- public relay address `203.0.113.10:51005`

## Traffic Policies

### `outbound_only`

```yaml
users:
  - username: "egress-only"
    password: "secret"
    port: 40100
    outbound_only: true
```

Behavior:
- the allocation may send to external peers
- a peer may only send traffic back after the allocation has already sent to that exact peer
- simply creating a TURN permission is not enough to open unsolicited inbound traffic

### `internal_only`

```yaml
users:
  - username: "mesh-node"
    password: "secret"
    port: 40101
    internal_only: true
```

Behavior:
- packets to external UDP endpoints are suppressed
- packets from external UDP endpoints are suppressed
- traffic to other live TURN relay addresses on the same server still works
- the advertised relay port is reserved logically inside the TURN server, but no host UDP socket is bound for that public relay port

`internal_only` can be combined with `outbound_only`.

## WireGuard Guarding

Each user or range may optionally enable WireGuard filtering:

```yaml
users:
  - username: "wg-server"
    password: "secret"
    port: 40000
    wireguard_mode: server-only
    wireguard_public_key: BASE64_PUBLIC_KEY_HERE
```

Supported `wireguard_mode` values:
- `disabled`
- `server-only`
- `default-with-overwrite`
- `required-in-username`

The TURN server does not decrypt WireGuard traffic. It only validates and filters packet flow.

## Mapped Addresses

Use these when the server is behind NAT or port forwarding:
- `mapped_address` for fixed users
- `mapped_range` for username ranges or per-user dynamic port ranges

Clients receive the mapped/public address in `XOR-RELAYED-ADDRESS`, while the server still binds the local relay socket on the internal interface.

## Example Config

See [turn-open-relay.example.yaml](./turn-open-relay.example.yaml).

## Tests

Default test suite:

```bash
go test ./...
```

The repository also contains a heavier WireGuard integration test behind the `integration` build tag because it depends on a real environment:

```bash
go test -tags=integration ./...
```
