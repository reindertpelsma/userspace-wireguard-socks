<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# API, Library, And Testing

## Management API

Enable the API:

```yaml
api:
  listen: 127.0.0.1:9090
  token: replace-with-a-long-random-token
```

If the API binds anywhere other than loopback, a token is required. For a Unix
socket, omit the token only when explicitly enabled:

```yaml
api:
  listen: unix:/tmp/api.sock
  allow_unauthenticated_unix: true
```

Main endpoints:

- `GET /v1/status`
- `GET /v1/ping`
- `GET /v1/interface_ips`
- `GET /v1/socket`
- peer CRUD under `/v1/peers`
- ACL CRUD under `/v1/acls`
- forward CRUD under `/v1/forwards`
- `PUT /v1/wireguard/config`

Example:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:9090/v1/peers
```

The repository also ships a small API client through the main binary:

```bash
export UWGS_API=http://127.0.0.1:9090
export UWGS_API_TOKEN=replace-with-a-long-random-token

./uwgsocks status
./uwgsocks ping 100.64.90.1 --count 3
./uwgsocks peers
./uwgsocks add-peer --public-key PEER_PUBLIC_KEY --allowed-ip 100.64.90.3/32
./uwgsocks remove-peer PEER_PUBLIC_KEY
./uwgsocks acl-list outbound
./uwgsocks add-forward --proto tcp --listen 127.0.0.1:18080 --target 100.64.90.1:80
```

The raw socket API is for local clients that need connected TCP or UDP,
tunnel-side bind or listen behavior, or DNS transactions without SOCKS5
limitations. It uses HTTP upgrade on `/v1/socket`; the HTTP proxy listener also
exposes `/uwg/socket`.

For the wire format, see [Raw socket API](../socket-protocol.md).

## Library Use

Other Go programs can embed the engine directly:

```go
package main

import (
	"io"
	"log"
	"net/netip"
	"os"

	uwg "github.com/reindertpelsma/userspace-wireguard-socks"
)

func main() {
	cfg, err := uwg.LoadConfig("server.yaml")
	if err != nil {
		log.Fatal(err)
	}
	eng, err := uwg.New(cfg, log.New(os.Stderr, "uwg: ", log.LstdFlags))
	if err != nil {
		log.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		log.Fatal(err)
	}
	defer eng.Close()

	ln, err := eng.ListenTCP(netip.MustParseAddrPort("100.64.90.1:8080"))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			_, _ = io.WriteString(conn, "Hello World\n")
		}()
	}
}
```

Use `DialContext` when you want the same AllowedIPs and fallback behavior as
the SOCKS or HTTP proxy. Use `DialTunnelContext` when the connection must stay
inside WireGuard.

## Testing

The test suite is rootless. Most tests do not need `/dev/net/tun`; host TUN
logic is exercised with an in-memory fake TUN device.

```bash
go test ./...
go vet ./...
```

The repository also includes:

- a loopback throughput benchmark in `internal/engine`
- `./scripts/iperf_loopback.sh`
- wrapper tests that exercise preload, ptrace, seccomp, fork, exec, message syscalls, IPv6, ICMP, and bind behavior

See [Testing plan](../testing.md) for the current detailed coverage and
release-candidate soak guidance.

## Feature Summary

- SOCKS5, HTTP, or mixed listeners
- local forwards and reverse forwards
- IPv4, IPv6, TCP, UDP, DNS, and ping-style ICMP
- transparent inbound TCP and UDP termination for WireGuard peers
- socksify-style wrapper for existing applications
- optional tunnel-hosted DNS service
- ACLs for inbound, outbound, and relay flows
- optional peer-to-peer relay forwarding
- runtime management API
- Go library APIs

## Notes

- TCP keepalive frames are not visible through Go `net.Conn` reads, so idle timers reset on userspace-visible reads and writes
- UDP empty datagrams are visible and do reset the UDP idle timer
- full RFC 6040 ECN tunneling is not currently implemented because the wireguard-go bind interface does not expose per-packet outer TOS or TrafficClass metadata at this layer
