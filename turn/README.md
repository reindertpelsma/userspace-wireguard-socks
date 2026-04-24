# Open TURN Relay

This TURN server is built to make private services reachable when direct port
forwarding is not an option.

The main use case is WireGuard:

- put a small public TURN relay on a VPS
- keep the real `uwgsocks` or WireGuard node behind NAT, CGNAT, or a corporate firewall
- let clients reach that hidden node through TURN without exposing the private host directly

That same pattern also works for other UDP applications, but the project is
tuned first for WireGuard-style traffic, relay-port control, and policy
enforcement rather than generic WebRTC media relay defaults.

It is built on Pion TURN and adds:
- fixed relay ports per user
- username-as-port range mode
- per-user dynamic port ranges
- multiple TURN listeners: UDP, TCP, TLS, DTLS, HTTP, HTTPS, and QUIC
- auto-generated TLS/DTLS certs when no files are configured, plus hot reload for certificate files
- optional mapped/public relay addresses
- internal relay-to-relay routing optimization
- `outbound_only` users that may only receive replies after they send first
- `internal_only` users that may only talk to other TURN allocations on the same server
- optional WireGuard-aware filtering on each relay port, including server-public-key checks for hidden WireGuard backends
- relay-side filtering that drops obvious garbage before it reaches the private WireGuard node
- handshake abuse controls so a public relay can absorb floods instead of blindly feeding them to the hidden WireGuard server
- optional local management API for status, user updates, and username-as-port range updates

## Quick Start

```bash
go build -o turn .
./turn -config turn-open-relay.example.yaml
```

For a public ingress relay, the typical deployment is:

1. Run `turn` on the public edge host.
2. Point the private `uwgsocks` or WireGuard server at that TURN endpoint.
3. Give clients a `turn://`, `turns://`, or TURN-over-HTTP/HTTPS/QUIC carrier
   so they can reach the hidden server through the relay.

Convenience build scripts are also included:

```bash
bash compile.sh
```

On Windows:

```powershell
compile.bat
```

Docker:

```bash
docker compose up --build
```

Release tags also publish a Linux container image:

- `ghcr.io/reindertpelsma/uwgsocks-turn:<tag>`

```bash
docker run --rm \
  -p 3478:3478/tcp \
  -p 3478:3478/udp \
  -v "$PWD/turn-open-relay.example.yaml:/config/turn.yaml:ro" \
  ghcr.io/reindertpelsma/uwgsocks-turn:v0.1.0-beta.1
```

The image accepts either a mounted config file or inline/base64 config through
`TURN_CONFIG_INLINE` / `TURN_CONFIG_B64`.

## Relay Model

The server supports three allocation styles:

1. Fixed user port:
   one username always gets one relay port.
2. Username-as-port range:
   the TURN username itself is the requested relay port inside a configured range.
3. Per-user dynamic port range:
   one username gets any free port inside its configured range, this user can then also connect multiple times.
   Unlike fixed user ports and the username-as-ports, this user can have multiple sessions.
   This is useful for users that are WireGuard clients, or WireGuard servers that only need a temporary ephemeral port.

When one TURN client sends to the public `XOR-RELAYED-ADDRESS` of another live TURN client on the same server, the packet is routed internally inside the Go process instead of going out to the network. WireGuard guards still apply on both sides.

## Config Overview

Top-level fields:
- `realm`
- `software`
- `allocation_ttl`
- `nonce_ttl`
- `preopen_single_ports`
- `api.listen`
- `api.token`
- `listen.relay_ip`
- `listeners`
- `max_sessions`

### Listeners

At least one listener is required. Each listener declares:
- `type`: `udp`, `tcp`, `tls`, `dtls`, `http`, `https`, or `quic`
- `listen`: bind address, for example `0.0.0.0:3478`
- `path` for `http`, `https`, or `quic` listeners, default `/turn`
- `cert_file` and `key_file` for `tls`, `dtls`, `https`, or `quic` listeners
- `reload_interval` to periodically reload renewed certificate files

If a `tls`, `dtls`, `https`, or `quic` listener is configured without certificate files, the server generates a self-signed certificate automatically at startup.

HTTP-carried listeners accept both:
- WebSocket framing with `Sec-WebSocket-Protocol: turn`, one TURN message per frame
- raw upgraded streams with `Upgrade: TURN`, carrying ordinary TURN-over-TCP framing

QUIC listeners accept WebTransport datagrams for TURN messages and also RFC 9220 WebSocket over HTTP/3 on the same path.

### Local Management API

The standalone binary can expose a small authenticated local API:

```yaml
api:
  listen: "unix:///var/run/turn.sock"
  token: "replace-me"
```

Supported endpoints:
- `GET /v1/status`
- `GET /v1/users`
- `PUT /v1/users`
- `POST /v1/users`
- `DELETE /v1/users?username=...`
- `GET /v1/port-ranges`
- `PUT /v1/port-ranges`
- `POST /v1/port-ranges`
- `DELETE /v1/port-ranges?start=...&end=...`

This API is intended for local control planes such as `uwgsocks-ui`. Listener changes still require restart; user and port-range updates can be pushed live.

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
- `permission_behavior`: relay policy mode for how peer traffic is handled

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

The TURN server does not decrypt WireGuard traffic. It validates and filters
packet flow before relaying it.

That matters when this binary is the public edge in front of a private
WireGuard server:

- the relay can pin traffic to the expected hidden server identity
- unrelated Internet noise does not have to reach the private backend
- random UDP spray and obvious junk packets are dropped at the relay instead of
  being forwarded blindly

In practice, that gives you a small public ingress box that is better behaved
than a generic open TURN relay when the real service behind it is WireGuard.

The practical outcome is what matters:

- the relay can act like a public firewall in front of the hidden server
- unrelated Internet noise gets filtered at the edge
- abusive handshake bursts are dampened before they become the private
  backend's problem

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

GitHub Actions runs `go test ./...` in `turn/` on every push. Tagged releases
also publish standalone TURN binaries for Linux (`amd64`, `arm64`, `riscv64`,
`mips64`), macOS (`amd64`, `arm64`), and Windows (`amd64`, `arm64`).
