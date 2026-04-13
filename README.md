# Userspace WireGuard SOCKS Gateway

Run **a full WireGuard network stack entirely in userspace**, with **no
root privileges**, **no `/dev/net/tun`**, and **no system routing
changes**.

This project makes it possible to **run both WireGuard clients and
servers inside a normal application process**, while exposing multiple
ways for applications to use the tunnel.

The result is a fully functional WireGuard environment that works even
in extremely restricted environments such as:

-   rootless containers
-   CI/CD runners
-   HPC clusters
-   gVisor sandboxes
-   locked‑down servers
-   SaaS applications embedding secure networking

Instead of creating a system VPN interface, applications interact with a
**userspace WireGuard TCP/IP stack**.

------------------------------------------------------------------------

# What Makes This Project Different

This project aims to provide **complete userspace WireGuard
functionality**, not just a proxy or client wrapper.

Key capabilities include:

-   Running **WireGuard servers** completely rootless
-   Allowing **arbitrary internet traffic to exit through a WireGuard
    peer**
-   Supporting **multi‑peer relay routing**
-   Providing **TCP, UDP, and IPv6 networking through the tunnel**
-   Allowing **applications without proxy support to use WireGuard
    transparently**
-   Offering **fine‑grained ACL firewall rules**
-   Exposing a **runtime API for managing peers and configuration**
-   Supporting **embedding WireGuard networking inside applications**

All of this runs in **pure userspace** without special privileges.

------------------------------------------------------------------------

# Core Capabilities

### Rootless WireGuard server

Run a full WireGuard endpoint without root privileges.

The server can:

-   accept peers
-   route internet traffic
-   forward connections
-   relay traffic between peers

This allows machines in restricted environments to still act as **secure
networking gateways**.

------------------------------------------------------------------------

### Userspace TCP/IP stack

A full networking stack runs inside the process, enabling:

-   TCP connections
-   UDP datagrams
-   IPv6 support
-   DNS resolution through the tunnel

Applications interact with it through proxies, forwards, or a library
interface.

------------------------------------------------------------------------

### Transparent application routing (LD_PRELOAD wrapper)

Applications that do not support proxies can still use the tunnel.

The included wrapper intercepts libc socket calls and routes them
through the userspace stack.

    ./uwgwrapper --api http://127.0.0.1:8080 -- curl https://example.com

This allows almost any dynamically linked program to use WireGuard
without modification.

------------------------------------------------------------------------

### UDP support

The system supports UDP routing through the userspace stack, allowing
applications relying on UDP protocols to function correctly.

------------------------------------------------------------------------

### Reverse forwards and service exposure

Applications running in restricted environments can expose services to
WireGuard peers.

Example uses:

-   exposing internal services
-   running ingress proxies behind a tunnel
-   forwarding ports from restricted environments

------------------------------------------------------------------------

### PROXY protocol support

When forwarding traffic, the original client address can be preserved
using PROXY protocol.

This is useful when routing traffic to:

-   ingress HTTP proxies
-   reverse proxies
-   service gateways

so that backend services can still see the original source IP.

------------------------------------------------------------------------

### Firewall ACLs

The system includes a built‑in firewall capable of filtering:

-   inbound connections
-   outbound connections
-   relay traffic between peers

Rules can match:

-   IP ranges
-   ports
-   direction

This allows safe deployment of relay nodes and gateway peers.

------------------------------------------------------------------------

### Runtime management API

The daemon exposes an API that allows modifying configuration while
running.

The API supports operations such as:

-   adding or removing peers
-   updating ACL rules
-   configuring forwards
-   retrieving runtime status
-   inspecting active connections

This makes the project suitable for **dynamic environments and
applications**.

------------------------------------------------------------------------

### Embeddable Go library

Applications can embed the WireGuard networking engine directly.

This allows software to create private networking capabilities without
relying on external daemons or system VPN configuration.

------------------------------------------------------------------------

# Quick Example

Run a local WireGuard exit server:

``` bash
./uwgsocks --config ./examples/server.yaml --listen-port 51820 --inbound-transparent=true
```

Run a client exposing a SOCKS proxy:

``` bash
./uwgsocks --config ./examples/client.yaml --socks5 127.0.0.1:1080
```

Send traffic through the tunnel:

``` bash
curl -x socks5h://127.0.0.1:1080 https://www.google.com
```

------------------------------------------------------------------------

# Typical Use Cases

### Rootless VPN nodes

Run secure network peers on machines without administrative privileges.

------------------------------------------------------------------------

### Secure networking inside containers

Run WireGuard inside containers without `CAP_NET_ADMIN`.

------------------------------------------------------------------------

### CI/CD infrastructure access

Allow build jobs to access private infrastructure through WireGuard.

------------------------------------------------------------------------

### Application‑embedded networking

Embed secure peer‑to‑peer networking inside applications.

------------------------------------------------------------------------

### Per‑application VPN routing

Route only selected applications through WireGuard without affecting the
entire system.

------------------------------------------------------------------------

### Gateway or relay nodes

Run peers that relay traffic between other peers or provide internet
egress.

------------------------------------------------------------------------

# Architecture Overview

    Application
          │
          │  (optional)
          ▼
    LD_PRELOAD wrapper
          │
          ▼
    fdproxy
          │
          ▼
    uwgsocks
          │
    Userspace TCP/IP stack
          │
          ▼
    WireGuard
          │
          ▼
    UDP network

The application sees normal sockets while traffic flows through the
userspace networking engine.

------------------------------------------------------------------------

# Installation

Download a release:

https://github.com/reindertpelsma/userspace-wireguard-socks/releases

Or build from source:

    bash compile.sh

This produces two binaries:

    uwgsocks
    uwgwrapper

Both are static executables.

------------------------------------------------------------------------

# Supported Environments

The project is designed to run in extremely restricted environments,
including:

-   rootless Docker containers
-   Kubernetes workloads without network privileges
-   CI environments
-   HPC clusters
-   gVisor sandboxes
-   locked‑down shared systems

------------------------------------------------------------------------

# Advanced Capabilities

Additional functionality includes:

-   local and reverse port forwards
-   DNS forwarding through the tunnel
-   multi‑peer relay routing
-   ACL firewall configuration
-   runtime API management
-   embedding inside Go applications

Detailed configuration and examples are documented in the sections
below.

------------------------------------------------------------------------

# Contributing

Contributions, bug reports, and feature suggestions are welcome.

If this project is useful for you, consider starring the repository.

# More information

See the [Full-Technical-How-To.md](Full-Technical-How-To.md) for all details you want to know about

------------------------------------------------------------------------

# License

ISC License
