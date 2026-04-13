# Userspace WireGuard Gateway

Run WireGuard networking **without root**, **without `/dev/net/tun`**,
and **without touching system routing**.

``` bash
# See building below to build your own executables
wget https://github.com/reindertpelsma/userspace-wireguard-socks/releases/download/0.1/uwgsocks
wget https://github.com/reindertpelsma/userspace-wireguard-socks/releases/download/0.1/uwgwrapper

./uwgsocks --wg-config ./my-wireguard-vpn.conf --http 127.0.0.1:8080 --socks5 127.0.0.1:1080 &
curl -x http://127.0.0.1:8080 https://example.com
./uwgwrapper --api http://127.0.0.1:8080 -- curl https://example.com
```

One executable. One WireGuard config. No system VPN setup required.

------------------------------------------------------------------------

# Building

Ensure `golang` is installing alongside `gcc`

```bash
bash compile.sh
```

# What This Project Is

`uwgsocks` runs a **complete WireGuard + TCP/IP stack in userspace**.

Instead of creating a system VPN interface, applications connect
through:

-   HTTP proxy
-   SOCKS proxy
-   port forwards
-   a transparent wrapper
-   or an embedded library

This makes WireGuard easy to use when you:

-   cannot run as root
-   do not want to modify system routing
-   only want to route **specific applications**
-   need networking inside restricted environments

------------------------------------------------------------------------

# Why you maybe want this

### No system networking changes

No:

-   routing tables
-   iptables rules
-   TUN interfaces
-   privileged containers

Just run the binary.

Works in environments such as:

-   Docker containers
-   CI/CD runners
-   HPC clusters
-   restricted servers
-   gVisor sandboxes

------------------------------------------------------------------------

### Proxy only the applications you want

Instead of routing an entire machine through a VPN, you can route only a
few tools:

``` bash
curl -x http://127.0.0.1:8080 https://example.com
```

or run one program through the tunnel:

``` bash
./uwgwrapper --api http://127.0.0.1:8080 -- git clone https://example.com/repo
```

------------------------------------------------------------------------

### Run a full WireGuard server without root

`uwgsocks` can host a complete WireGuard peer that can:

-   accept other peers
-   route internet traffic
-   forward ports
-   relay traffic between peers

All without requiring root privileges.

------------------------------------------------------------------------

# Core Capabilities

-   rootless WireGuard **client and server**
-   userspace TCP, UDP and IPv6 networking
-   HTTP and SOCKS proxy interfaces
-   reverse port forwards from the tunnel
-   multi-peer relay support
-   transparent wrapper for applications without proxy support
-   PROXY protocol support to preserve source IP
-   firewall ACL rules
-   runtime API to manage peers and configuration
-   embeddable Go networking library

Everything runs **100% in userspace**.

------------------------------------------------------------------------

# Quick Example

Run a WireGuard client exposing proxies:

``` bash
./uwgsocks \
  --wg-config ./provider.conf \
  --http 127.0.0.1:8080 \
  --socks5 127.0.0.1:1080
```

Use the proxy:

``` bash
curl -x http://127.0.0.1:8080 https://www.google.com
```

Run a program transparently through the tunnel:

``` bash
./uwgwrapper --api http://127.0.0.1:8080 -- wget https://example.com
```

------------------------------------------------------------------------

# Typical Use Cases

### Simple VPN proxy

Quickly route traffic through WireGuard without touching system
networking.

### Docker networking

Avoid privileged containers and complex routing setups.

### CI/CD pipelines

Access private infrastructure securely during builds.

### Application‑embedded networking

Embed WireGuard connectivity directly inside applications.

### Secure service exposure

Expose or forward services through WireGuard peers.

------------------------------------------------------------------------

# Architecture

    Application
         │
         │ (optional)
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

------------------------------------------------------------------------

# One Binary. One Config.

Most setups only require:

``` bash
./uwgsocks --wg-config ./vpn.conf --http 127.0.0.1:8080
```

No system setup required.

------------------------------------------------------------------------

# Documentation

Detailed configuration and technical documentation are available in:

    Technical-How-To.md

------------------------------------------------------------------------

# License

ISC License
