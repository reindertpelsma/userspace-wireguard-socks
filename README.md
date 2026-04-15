# Userspace WireGuard Gateway

Run WireGuard networking **without root**, **without `/dev/net/tun`**,\
**without routing changes**, and **without system VPN setup**.

``` bash
# download binaries
wget https://github.com/reindertpelsma/userspace-wireguard-socks/releases/download/0.1/uwgsocks
wget https://github.com/reindertpelsma/userspace-wireguard-socks/releases/download/0.1/uwgwrapper
chmod +x uwgsocks uwgwrapper

# start a WireGuard tunnel with HTTP and SOCKS proxy
./uwgsocks --wg-config ./vpn.conf --http 127.0.0.1:8080 --socks5 127.0.0.1:1080

# use it
curl -x http://127.0.0.1:8080 https://example.com

# run any application through it
./uwgwrapper --api http://127.0.0.1:8080 -- curl https://example.com
```

One executable. One WireGuard config. No system networking setup
required.

------------------------------------------------------------------------

# What This Project Is

`uwgsocks` runs a **complete WireGuard + TCP/IP stack entirely in
userspace**.

Instead of creating a system VPN interface, applications connect
through:

-   HTTP proxy
-   SOCKS proxy
-   port forwards
-   a transparent wrapper
-   or an embedded Go library

This makes WireGuard simple to use when you:

-   cannot run as root
-   do not want to modify system routing
-   only want to route **specific applications**
-   need networking inside restricted environments

------------------------------------------------------------------------

# Why you might want to use this

### No system networking changes

No:

-   routing tables
-   iptables rules
-   TUN interfaces
-   privileged containers

Just run the binary.

Works in environments such as:

-   locked‑down Docker or Kubernetes containers
-   CI/CD runners
-   HPC clusters
-   restricted servers
-   gVisor sandboxes

------------------------------------------------------------------------

### Proxy only the applications you want

Instead of routing an entire machine through a VPN, you can route only
specific tools.

Example:

``` bash
curl -x http://127.0.0.1:8080 https://example.com
```

Or transparently run an application through the tunnel:

``` bash
./uwgwrapper --api http://127.0.0.1:8080 -- git clone https://example.com/repo
```

------------------------------------------------------------------------

### Run a full WireGuard server without root

`uwgsocks` can host a complete WireGuard peer that can:

-   accept peers
-   route internet traffic inbound and outbound
-   forward ports
-   relay traffic between peers

All **without requiring root privileges**.

------------------------------------------------------------------------

# Core Capabilities

-   rootless WireGuard **client and server**
-   userspace TCP, UDP, and IPv6 networking
-   HTTP and SOCKS proxy interfaces
-   reverse port forwards from the tunnel
-   multi‑peer relay support
-   transparent wrapper for applications without proxy support
-   PROXY protocol support to preserve source IP
-   built‑in firewall ACL rules
-   runtime API to manage peers and configuration
-   embeddable Go networking library
-   ability to route traffic through existing SOCKS/HTTP proxies

Everything runs **100% in userspace**.

------------------------------------------------------------------------

# Quick Example

Start a demo WireGuard server (Terminal 1):

``` bash
./uwgsocks --config examples/exit-server.yaml
```

Connect with a client exposing proxies (Terminal 2):

``` bash
./uwgsocks \
  --config examples/exit-client.yaml \
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
         │
         ▼
    uwgwrapper (optional)
         │
         ▼
    uwgsocks
         │
    Userspace TCP/IP stack
         │
         ▼
    WireGuard

------------------------------------------------------------------------

# Building

If you prefer to build the binaries yourself:

Requirements:

-   Go
-   gcc

``` bash
bash compile.sh
```

This produces:

    uwgsocks
    uwgwrapper

Both are static executables.

------------------------------------------------------------------------

# Documentation

Detailed configuration and technical documentation are available in:

    Technical-How-To.md

------------------------------------------------------------------------

# License

ISC License
