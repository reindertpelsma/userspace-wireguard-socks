# Open TURN Relay

This project hosts a TURN server for Wireguard servers/clients and can also be used as a general UDP relay proxy.

Unlike normal WebRTC TURN, this TURN server allocates a static port and allows abritary connections from the internet to reach the proxyy

Features:
- TURN server allowing both inbound and outbound UDP connections
- Open UDP relay support allowing applications behind firewalls to use a TURN server to open a UDP port to the internet
- Wireguard support allowing the TURN server to filter Wireguard packets before arriving the target wireguard server/client, be able to validate on the server's public key
- Full DoS firewall for Wireguard servers, with automatic mitigation if an attack is detected.
- Supporting username and password authentication and source network filtering, plus port range method
- optional public mapped address override for NAT/port-forwarded setups
- selectable permission behavior

When used with Wireguard, the TURN server will not be able to decrypt or MITM the connection, allowing the TURN server be able to hosted on a untrusted provider for cheap bandwidth, while keeping your personal traffic secure.

Even if you have the ability to expose a port, when you want to protect your IP or your Wireguard server you can still run the TURN server as a firewall and let your wireguard server connect through TURN.

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
    wireguard_mode: server-only # Options: disabled (no UDP), server-only (force server public key), default-with-overwrite (public key can be chosen by client by embedding in username), required-in-username
    wireguard_public_key: QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
```

Meaning:
- username = `alice`
- password = `alice-pass`
- relay port = `40000`
- client source must match `source_networks`
- reported public relay address = `203.0.113.10:40000`
- the UDP port may only be used for inbound/outbound Wireguard traffic
- Only wireguard connections to the server's public key are allowed

The wireguard public key is not sent over the wire, therefore its like a password the TURN server can use to verify inbound connections before even forwarding them to your server. its therefore crucial to keep your wireguard server public key secret outside of legitemate clients that need to connect to your server.

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
    wireguard_mode: required-in-username
```

Meaning:
- valid usernames are `41000` through `41099`
- all use the same password
- username `41005` maps to relay port `41005`
- reported public relay address becomes `203.0.113.10:51005`
- all these ports are Wireguard ports, the public key is provided by the TURN client inside the TURN username.

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
