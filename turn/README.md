# Open TURN Relay

This project is mainly for running a TURN server as a **UDP relay proxy with stable, predictable ports**.

The main point is not typical WebRTC TURN usage.
The main point is to **open UDP ports to the internet through a TURN server**, while keeping relay ports consistent and easy to map.

In other words:
- most WebRTC TURN servers allocate random-looking relay ports for media sessions, behind a restrictive permission firewall
- this server is meant for **UDP relay/proxy use**, where **fixed or predictable relay ports matter**
- that makes it useful when you want to expose UDP endpoints to the internet in a controlled way

It is built on Pion TURN and adds:
- username/password auth
- fixed relay port per user
- port-range mode where the username is the relay port number
- optional public mapped address override for NAT/port-forwarded setups
- source network filtering
- selectable permission behavior

## Start in 20 seconds

Build and run:

```bash
go build -o turn .
./turn -config turn-open-relay.example.yaml
```

Docker:

```bash
docker compose up --build
```

## What it is for

Use this when you want a TURN server to behave more like a **UDP relay appliance** than a classic WebRTC media relay.

Typical goal:
- bind UDP relay ports
- expose them to the internet
- keep them consistent across users or ranges
- optionally report a public IP/port different from the local bind IP/port

This is especially useful when:
- the server sits behind NAT
- you use router port forwarding
- you want simple firewall rules
- you want `username -> UDP port` mapping

## Config file

Main fields:

- `realm`: TURN realm used for auth
- `software`: label shown by the server
- `allocation_ttl`: allocation lifetime, for example `10m`
- `nonce_ttl`: auth nonce lifetime, for example `10m`
- `preopen_single_ports`: reserved for future deterministic prebind behavior
- `listen.turn_listen`: UDP address for the TURN server, for example `0.0.0.0:3478`
- `listen.relay_ip`: IP used for relay addresses

### Users

A user gets one fixed relay port.

Example:

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

Meaning:
- username = `alice`
- password = `alice-pass`
- relay port = `40000`
- client source must match `source_networks`
- reported public relay address = `203.0.113.10:40000`

### Port ranges

For a port range, the **username is the port number**.

Example:

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

Meaning:
- valid usernames are `41000` through `41099`
- all use the same password
- username `41005` maps to relay port `41005`
- reported public relay address becomes `203.0.113.10:51005`

## Permission behavior

Three modes exist:

### `allow`
Allow peer traffic broadly. This is the most open mode and required when you want to use the TURN server as a UDP port forwarder.

### `allow-if-no-permissions`
Allow traffic when no explicit permissions exist yet. If permissions are created later, they can narrow behavior.

### `reject-unless-permitted`
Only allow traffic that is explicitly permitted. This is the most strict mode.

## Source networks

`source_networks` is a CIDR allowlist.

Examples:

```yaml
source_networks:
  - "127.0.0.0/8"
  - "10.0.0.0/8"
```

If set, client source IPs must match one of those ranges.

## Mapped address and mapped range

Use these when the server is behind NAT or port forwarding.

### Single user

```yaml
mapped_address: "203.0.113.10:50001"
```

The server can listen internally on one address, but tell clients to use another public endpoint.

### Port range

```yaml
mapped_range:
  ip: "203.0.113.10"
  start_port: 51000
```

This translates the internal range to a public range with the same size.

Example:
- internal `41000-41099`
- external `51000-51099`

## Example credentials

Fixed user:
- username: `alice`
- password: `alice-pass`

Range user:
- username: `41005`
- password: `shared-range-secret`

## Files

- `open_turn_pion.go`: server
- `turn-open-relay.example.yaml`: sample config
- `Dockerfile`: two-stage scratch image build
- `docker-compose.yml`: example container run
