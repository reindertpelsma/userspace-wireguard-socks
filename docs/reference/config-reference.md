<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Configuration reference

> **Generated**. Do not edit by hand. Regenerate with:
> ```
> go run ./tools/genconfigref
> ```
> The source of truth is the struct definitions in `internal/config/` and
> `internal/transport/`. Add a `// comment` above the field; it shows up here.

Use [configuration.md](configuration.md) for behavior context behind these fields.

## `wireguard`

WireGuard interface + peer settings: keys, addresses, peers,
keepalives, hook scripts. See the wg-quick man page for the
underlying field semantics.

  ```yaml
  wireguard:
    config_file: string
    config: string
    private_key: string
    listen_port: int?
    listen_addresses: [string]
    addresses: [string]
    mtu: int
    dns: [string]
    roam_fallback_seconds: int
    pre_up: [string]
    post_up: [string]
    pre_down: [string]
    post_down: [string]
    peers: [Peer]
    default_transport: string
    turn_directives: [string]
    tcp_listen: bool
  ```

  - **`config_file`** (string)  
    Path to wg-quick style config.

  - **`config`** (string)  
    Inline wg-quick text.

  - **`private_key`** (string)  
    These fields mirror the wg-quick [Interface] and [Peer] values that make
    sense for a userspace, no-TUN runtime. Table/SaveConfig are accepted but
    ignored because the process never mutates the host routing table.

  - **`listen_port`** (int?)  
    UDP listen port when listening directly.

  - **`listen_addresses`** ([string])  
    ListenAddresses restrict server-mode WireGuard UDP sockets to specific
    local IP addresses. Empty means wireguard-go's normal all-IPv4/all-IPv6
    listeners.

  - **`addresses`** ([string])  
    Local tunnel IPs/CIDRs.

  - **`mtu`** (int) — default: `1420`  
    Userspace tunnel MTU.

  - **`dns`** ([string])  
    DNS servers learned from wg-quick.

  - **`roam_fallback_seconds`** (int) — default: `120`  
    RoamFallbackSeconds reapplies a peer's configured static Endpoint after
    roaming if the live endpoint stops handshaking for this long. Peers
    without Endpoint= remain dynamic and are not affected.

  - **`pre_up`** ([string])  
    Script hooks; only run when scripts.allow=true.

  - **`post_up`** ([string])  
    Script hooks after startup; require scripts.allow=true.

  - **`pre_down`** ([string])  
    Script hooks before shutdown; require scripts.allow=true.

  - **`post_down`** ([string])  
    Script hooks after shutdown; require scripts.allow=true.

  - **`peers`** ([Peer])  
    Peers is the list of WireGuard peers known at startup.
    Each entry holds public-key, AllowedIPs, optional endpoint
    + transport, plus the mesh-control flags. Mirrors the
    [Peer] sections of a wg-quick config.

  - **`default_transport`** (string)  
    DefaultTransport is the name of the transport used for peers that do not
    specify an explicit Transport field.  When empty the first NCO transport
    in the Transports list is used; if none exist the first transport is used.

  - **`turn_directives`** ([string])  
    Fields synthesized from #! directives in wg-quick config files.
    TURNDirectives holds raw TURN URLs from #!TURN= lines, e.g. "turn+tls://user:pass@host:port".

  - **`tcp_listen`** (bool)  
    TCPListen enables a TCP listener synthesized from a #!TCP directive in [Interface].

  ### `wireguard.peers[]`

    ```yaml
    peers[]:
      public_key: string
      preshared_key: string
      endpoint: string
      allowed_ips: [string]
      persistent_keepalive: int
      traffic_shaper: TrafficShaper
      control_url: string
      mesh_enabled: bool
      mesh_advertise: bool?
      mesh_disable_acls: bool
      mesh_accept_acls: bool
      mesh_trust: string
      transport: string
      tcp_mode: string
      skip_verify_tls: bool?
      connect_url: string
    ```

    - **`public_key`** (string)  
      PublicKey is the peer's base64 WireGuard public key. Required.

    - **`preshared_key`** (string)  
      Optional base64 WireGuard preshared key.

    - **`endpoint`** (string)  
      host:port or tagged scheme URL.

    - **`allowed_ips`** ([string])  
      Routed subnets/IPs for this peer.

    - **`persistent_keepalive`** (int)  
      Keepalive interval in seconds; 0 disables it.

    - **`traffic_shaper`** (TrafficShaper)  
      TrafficShaper applies a per-peer rate limit / latency
      budget. Overrides the top-level traffic_shaper for this
      peer's flows. Zero values inherit from the global shaper.

    - **`control_url`** (string)  
      Mesh control URL for this parent peer.

    - **`mesh_enabled`** (bool)  
      Allow dynamic mesh peers to be learned from this peer.

    - **`mesh_advertise`** (bool?)  
      null means default behavior.

    - **`mesh_disable_acls`** (bool)  
      Opt out of distributed mesh ACL enforcement locally.

    - **`mesh_accept_acls`** (bool)  
      Usually enabled when this peer participates in mesh ACLs.

    - **`mesh_trust`** (string)  
      untrusted | trusted_always | trusted_if_dynamic_acls

    - **`transport`** (string)  
      Transport is the name of a transport from the top-level transports list.
      Empty means use the default transport (first entry, or legacy UDP).

    - **`tcp_mode`** (string)  
      Fields synthesized from #! directives in wg-quick config files.
      TCPMode is set by #!TCP=: "no" (default), "supported", "required".

    - **`skip_verify_tls`** (bool?)  
      SkipVerifyTLS is set by #!SkipVerifyTLS=: nil=default, true=skip, false=verify.

    - **`connect_url`** (string)  
      ConnectURL is set by #!URL=: full URL for auto-negotiation transport.

    ### `wireguard.peers[].traffic_shaper`

      ```yaml
      traffic_shaper:
        upload_bps: int
        download_bps: int
        latency_ms: int
      ```

      - **`upload_bps`** (int)  
        Upload ceiling in bytes per second.

      - **`download_bps`** (int)  
        Download ceiling in bytes per second.

      - **`latency_ms`** (int)  
        Extra artificial latency in milliseconds.


## `proxy`

Proxy configures an optional proxy layer beneath the base transport.

  ```yaml
  proxy:
    socks5: string
    http: string
    http_listeners: [string]
    mixed: string
    username: string
    password: string
    fallback_direct: bool?
    fallback_socks5: string
    ipv6: bool?
    udp_associate: bool?
    udp_associate_ports: string
    https_proxying: bool?
    https_proxy_verify: string
    https_proxy_ca_file: string
    bind: bool?
    lowbind: bool?
    prefer_ipv6_for_udp_over_socks: bool?
    honor_environment: bool?
    outbound_proxies: [OutboundProxy]
  ```

  - **`socks5`** (string)  
    SOCKS5 is the host SOCKS5 listen address (host:port or
    "unix:/path"). Empty disables the SOCKS5 listener.

  - **`http`** (string)  
    Host HTTP proxy listen address.

  - **`http_listeners`** ([string])  
    Extra HTTP listeners, including unix: paths.

  - **`mixed`** (string)  
    Combined SOCKS5+HTTP listener.

  - **`username`** (string)  
    Proxy auth username.

  - **`password`** (string)  
    Proxy auth password.

  - **`fallback_direct`** (bool?) — default: `true`  
    Allow direct host dials after routing misses.

  - **`fallback_socks5`** (string)  
    FallbackSOCKS5 is an upstream SOCKS5 address used when no
    tunnel route matches (and FallbackDirect is off). Empty
    means no SOCKS5 fallback.

  - **`ipv6`** (bool?)  
    IPv6 controls whether proxy listeners accept IPv6 client
    connections and whether outbound dials may use IPv6. Nil
    means default (true on dual-stack hosts).

  - **`udp_associate`** (bool?) — default: `true`  
    Enable SOCKS5 UDP ASSOCIATE.

  - **`udp_associate_ports`** (string)  
    Optional port or range for UDP ASSOCIATE.

  - **`https_proxying`** (bool?) — default: `true`  
    Accept absolute-form HTTPS proxy requests.

  - **`https_proxy_verify`** (string) — default: `"pki"`  
    none | pki | ca | both

  - **`https_proxy_ca_file`** (string)  
    CA bundle for https_proxy_verify ca/both.

  - **`bind`** (bool?)  
    Enable SOCKS5 BIND and listener-style raw sockets.

  - **`lowbind`** (bool?)  
    Allow ports below 1024 where supported.

  - **`prefer_ipv6_for_udp_over_socks`** (bool?)  
    PreferIPv6ForUDPOverSOCKS routes SOCKS5-UDP through IPv6
    when both stacks are available. Off by default; turn on
    for environments where IPv4 UDP is heavily filtered.

  - **`honor_environment`** (bool?) — default: `true`  
    Import ALL_PROXY/HTTP(S)_PROXY fallbacks.

  - **`outbound_proxies`** ([OutboundProxy])  
    OutboundProxies is the list of upstream proxies the engine
    can chain to for matched destinations. Per-entry roles +
    subnets select where each proxy applies. See the
    OutboundProxy fields for the shape.

  ### `proxy.outbound_proxies[]`

    ```yaml
    outbound_proxies[]:
      type: string
      address: string
      username: string
      password: string
      roles: [string]
      subnets: [string]
    ```

    - **`type`** (string)  
      Type is "socks5" or "http". If Address is a URL, the scheme fills this.

    - **`address`** (string)  
      Address is host:port or a URL such as socks5://127.0.0.1:1080.

    - **`username`** (string)  
      Proxy auth username.

    - **`password`** (string)  
      Proxy auth password.

    - **`roles`** ([string])  
      Roles controls whether the proxy can be used for SOCKS/HTTP proxy clients,
      transparent inbound WireGuard forwarding, or both. Empty means both.

    - **`subnets`** ([string])  
      Subnets limits destinations that use this proxy. Empty means all
      destinations. When several proxies match, the most-specific prefix wins.


## `inbound`

Inbound (a.k.a. "transparent inbound") accepts WireGuard peer
traffic destined for host services. Off by default; turning
on means tunnel-side peers can reach host loopback and the
host network through redirected connections.

  ```yaml
  inbound:
    transparent: bool?
    consistent_port: string
    disable_low_ports: bool?
    forward_icmp_errors: bool?
    tcp_mss_clamp: bool?
    reply_icmp: bool?
    icmp_rate_limit_per_sec: int
    max_connections: int
    max_connections_per_peer: int
    connection_table_grace_seconds: int
    tcp_receive_window_bytes: int
    tcp_max_buffered_bytes: int
    host_dial_proxy_socks5: string
    host_dial_bind_address: string
    tcp_idle_timeout_seconds: int
    udp_idle_timeout_seconds: int
  ```

  - **`transparent`** (bool?)  
    Accept tunnel TCP/UDP directly to host sockets.

  - **`consistent_port`** (string) — default: `"loose"`  
    strict | loose | disabled

  - **`disable_low_ports`** (bool?) — default: `true`  
    Reject host ports below 1024 unless explicitly allowed.

  - **`forward_icmp_errors`** (bool?) — default: `true`  
    Forward ICMP errors back into the tunnel when possible.

  - **`tcp_mss_clamp`** (bool?) — default: `true`  
    Clamp MSS on inbound TCP to avoid PMTU issues.

  - **`reply_icmp`** (bool?) — default: `true`  
    Generate local ICMP echo replies where supported.

  - **`icmp_rate_limit_per_sec`** (int) — default: `10`  
    Per-peer ICMP reply rate limit.

  - **`max_connections`** (int)  
    Global inbound connection cap; 0 means unlimited.

  - **`max_connections_per_peer`** (int)  
    Per-peer inbound connection cap; 0 means unlimited.

  - **`connection_table_grace_seconds`** (int) — default: `30`  
    Keep closed-flow state briefly for late packets.

  - **`tcp_receive_window_bytes`** (int) — default: `1048576`  
    Netstack TCP receive window for inbound flows.

  - **`tcp_max_buffered_bytes`** (int) — default: `268435456`  
    Global buffered TCP cap for inbound flows.

  - **`host_dial_proxy_socks5`** (string)  
    HostDialProxySOCKS5 is an optional upstream SOCKS5 to use
    when transparent inbound flows need to dial host services
    through a proxy rather than directly. Empty means dial
    directly.

  - **`host_dial_bind_address`** (string)  
    Optional host source IP for transparent outbound dials.

  - **`tcp_idle_timeout_seconds`** (int) — default: `900`  
    Idle timeout for transparent inbound TCP flows.

  - **`udp_idle_timeout_seconds`** (int) — default: `30`  
    Idle timeout for transparent inbound UDP flows.


## `host_forward`

HostForward controls whether proxy clients (and inbound
tunnel peers) can reach host-local services. The two sub-
blocks are independent and OFF by default for inbound.

  ```yaml
  host_forward:
    proxy: HostForwardEndpoint
    inbound: HostForwardEndpoint
  ```

  - **`proxy`** (HostForwardEndpoint)  
    Proxy controls SOCKS5/HTTP requests to local tunnel addresses,
    localhost, and 127.0.0.0/8. It defaults on so a proxy client can reach
    services on the same host through the familiar local names.

  - **`inbound`** (HostForwardEndpoint)  
    Inbound controls WireGuard packets addressed to this peer's tunnel IPs
    when no userspace listener owns the port. It defaults off because it can
    expose loopback-only host services to remote peers.

  ### `host_forward.proxy`

    ```yaml
    proxy:
      enabled: bool?
      redirect_ip: string
      redirect_tun: bool
    ```

    - **`enabled`** (bool?) — default: `true`  
      Allow proxy clients to reach host-local services.

    - **`redirect_ip`** (string)  
      Optional host IP to use instead of loopback.

    - **`redirect_tun`** (bool)  
      Re-enter through the host TUN path.

  ### `host_forward.inbound`

    ```yaml
    inbound:
      enabled: bool?
      redirect_ip: string
      redirect_tun: bool
    ```

    - **`enabled`** (bool?)  
      Allow proxy clients to reach host-local services.

    - **`redirect_ip`** (string)  
      Optional host IP to use instead of loopback.

    - **`redirect_tun`** (bool)  
      Re-enter through the host TUN path.


## `mesh_control`

MeshControl is the optional tunnel-only peer-discovery and
dynamic-ACL synchronisation plane. See docs/howto/05-mesh-
coordination.md for the full protocol.

  ```yaml
  mesh_control:
    listen: string
    challenge_rotate_seconds: int
    active_peer_window_seconds: int
    notify_window_seconds: int
    notify_min_interval_seconds: int
    subscribe_max_lifetime_seconds: int
    advertise_self: bool
  ```

  - **`listen`** (string)  
    Host listen address or unix:// socket path.

  - **`challenge_rotate_seconds`** (int) — default: `120`  
    Rotate auth challenges on this interval.

  - **`active_peer_window_seconds`** (int) — default: `120`  
    Only advertise recently active peers.

  - **`notify_window_seconds`** (int) — default: `120`  
    NotifyWindowSeconds is how far in the future a mesh
    notification's deadline can extend. Caps long-poll
    subscriptions; clients reconnect after the window. Zero
    uses the default (300s).

  - **`notify_min_interval_seconds`** (int) — default: `60`  
    NotifyMinIntervalSeconds is the minimum gap between two
    mesh notifications to the same client. Rate-limits
    chatty peer-event firehoses. Zero uses the default (45s).

  - **`subscribe_max_lifetime_seconds`** (int) — default: `300`  
    Maximum lifetime for mesh event streams.

  - **`advertise_self`** (bool)  
    Include the current node itself in mesh responses.


## `routing`

Routing chooses the order in which the engine resolves a
destination IP across the available tunnel/peer/proxy paths
(see docs/reference/proxy-routing.md).

  ```yaml
  routing:
    enforce_address_subnets: bool?
  ```

  - **`enforce_address_subnets`** (bool?) — default: `true`  
    EnforceAddressSubnets makes Address=10.10.10.2/24 behave like a real
    interface route: other addresses in 10.10.10.0/24 must be routed by
    AllowedIPs or they are rejected instead of falling back to the Internet.


## `tun`

TUN is the optional host-TUN backend. When `enabled: true`
the engine creates a real TUN device and adds routes for
the tunnel addresses; when off, traffic is reachable only
through the proxy/socket-API/wrapper paths.

  ```yaml
  tun:
    enabled: bool
    name: string
    mtu: int
    configure: bool
    route_allowed_ips: bool?
    routes: [string]
    dns_servers: [string]
    dns_resolv_conf: string
    fallback_system_dns: [string]
    up: [string]
    down: [string]
  ```

  - **`enabled`** (bool)  
    Enabled creates a host OS TUN interface and terminates traffic from that
    interface in a second userspace netstack. The main no-/dev/net/tun mode
    remains the default.

  - **`name`** (string) — default: `"uwgsocks0"`  
    Name is the requested host interface name. The kernel may still return a
    concrete name when patterns such as "uwgsocks%d" are used.

  - **`mtu`** (int)  
    MTU defaults to wireguard.mtu.

  - **`configure`** (bool)  
    Configure asks uwgsocks to configure addresses/routes with netlink. When
    false, external scripts or an operator may configure the interface.

  - **`route_allowed_ips`** (bool?) — default: `true`  
    RouteAllowedIPs installs peer AllowedIPs as kernel routes when Configure
    is true. Extra Routes are always added when Configure is true.

  - **`routes`** ([string])  
    Routes are additional CIDRs routed to the TUN interface.

  - **`dns_servers`** ([string])  
    DNSServers are optional host DNS servers configured on the TUN interface
    when the platform backend supports it.

  - **`dns_resolv_conf`** (string)  
    DNSResolvConf, when set, writes tun.dns_servers as plain "nameserver"
    lines into this file instead of using platform DNS manager APIs.

  - **`fallback_system_dns`** ([string])  
    FallbackSystemDNS is used only for resolving outer WireGuard transport
    hostnames outside the tunnel when host-TUN routes are active.

  - **`up`** ([string])  
    Up and Down are optional shell snippets run after interface creation and
    before teardown when scripts.allow is true.

  - **`down`** ([string])  
    Teardown hooks; require scripts.allow=true.


## `filtering`

Filtering applies blanket ingress drops to the userspace
netstack (e.g. drop IPv6 link-local multicast). Off-by-
default safety nets, not a substitute for ACLs.

  ```yaml
  filtering:
    drop_ipv6_link_local_multicast: bool?
    drop_ipv4_invalid: bool?
  ```

  - **`drop_ipv6_link_local_multicast`** (bool?) — default: `true`  
    DropIPv6LinkLocalMulticast drops IPv6 multicast packets in
    the fe80::/10 link-local range at netstack ingress. Off by
    default; turn on for environments where MLD/router-advert
    chatter pollutes the tunnel.

  - **`drop_ipv4_invalid`** (bool?) — default: `true`  
    DropIPv4Invalid drops malformed IPv4 packets (invalid IHL,
    total-length mismatch, etc.) at netstack ingress. Default
    on — turning off is rarely needed.


## `traffic_shaper`

TrafficShaper applies a global token-bucket rate limit to
the tunnel. Per-peer shapers under wireguard.peers[]
override the global value.

  ```yaml
  traffic_shaper:
    upload_bps: int
    download_bps: int
    latency_ms: int
  ```

  - **`upload_bps`** (int)  
    Upload ceiling in bytes per second.

  - **`download_bps`** (int)  
    Download ceiling in bytes per second.

  - **`latency_ms`** (int)  
    Extra artificial latency in milliseconds.


## `relay`

Relay enables hub-mode peer-to-peer forwarding (one peer's
traffic destined for another peer's AllowedIPs is forwarded
rather than dropped). See the acl.relay rules for the
matching policy.

  ```yaml
  relay:
    enabled: bool?
    conntrack: bool?
    conntrack_max_flows: int
    conntrack_max_per_peer: int
  ```

  - **`enabled`** (bool?)  
    Allow proxy clients to reach host-local services.

  - **`conntrack`** (bool?) — default: `true`  
    Keep stateful relay conntrack enabled.

  - **`conntrack_max_flows`** (int) — default: `65536`  
    Global relay flow table cap.

  - **`conntrack_max_per_peer`** (int) — default: `4096`  
    Per-peer relay flow table cap.


## `api`

API configures the management HTTP listener (status, peer
add/remove, ACL replace). See docs/reference/api-reference.md
for the full endpoint surface.

  ```yaml
  api:
    listen: string
    token: string
    allow_unauthenticated_unix: bool
  ```

  - **`listen`** (string)  
    Host listen address or unix:// socket path.

  - **`token`** (string)  
    Bearer token for HTTP listeners.

  - **`allow_unauthenticated_unix`** (bool) — default: `true`  
    Allow trusted local Unix-socket callers without a token.


## `socket_api`

SocketAPI configures the raw socket protocol exposed at
`/v1/socket` and `/uwg/socket`. Used by the wrapper, by
language SDKs, and by direct integrators. See
docs/reference/socket-protocol.md.

  ```yaml
  socket_api:
    bind: bool
    transparent_bind: bool
    udp_inbound: bool
  ```

  - **`bind`** (bool)  
    Bind enables TCP listener sockets over /v1/socket. UDP bind-style sockets
    are allowed without this flag, but stay established-only unless UDPInbound
    is also set.

  - **`transparent_bind`** (bool)  
    TransparentBind permits clients to bind source addresses outside the
    configured WireGuard interface addresses. This is intentionally separate
    from Bind because it can intercept traffic meant for other tunnel IPs.

  - **`udp_inbound`** (bool)  
    UDPInbound lets UDP listener sockets receive datagrams before the local
    application has sent to that remote address.


## `acl`

ACL holds the three policy planes — inbound, outbound, and
relay — each with a default action plus an ordered rule
list. First-match-wins.

  ```yaml
  acl:
    inbound_default: string
    outbound_default: string
    relay_default: string
    inbound: [Rule]
    outbound: [Rule]
    relay: [Rule]
  ```

  - **`inbound_default`** (string) — default: `"allow"`  
    allow | deny

  - **`outbound_default`** (string) — default: `"allow"`  
    allow | deny

  - **`relay_default`** (string) — default: `"deny"`  
    allow | deny

  - **`inbound`** ([Rule])  
    Ordered inbound ACL rule list.

  - **`outbound`** ([Rule])  
    Ordered outbound ACL rule list.

  - **`relay`** ([Rule])  
    Ordered relay ACL rule list.

  ### `acl.inbound[]`

    ```yaml
    inbound[]:
      action: string
      source: string
      destination: string
      sources: [string]
      destinations: [string]
      source_port: string
      destination_port: string
      protocol: string
    ```

    - **`action`** (string)  
      Action is what to do when a connection matches this rule.
      One of `allow` or `deny`. First-match-wins ordering applies
      across the rule list.

    - **`source`** (string)  
      Source is a single CIDR (or IP) the connection's source must
      match for this rule to fire. Empty means "any source".
      Singular form kept for back-compat with single-rule configs;
      for multiple sources use Sources instead.

    - **`destination`** (string)  
      Destination is a single CIDR (or IP) the connection's
      destination must match. Empty means "any destination".
      Singular form; for multiple destinations use Destinations.

    - **`sources`** ([string])  
      Sources is the list variant of Source. When non-empty it is
      used in addition to Source (the two are merged). Lets one
      rule cover many CIDRs rather than duplicating the rule.

    - **`destinations`** ([string])  
      Destinations is the list variant of Destination. Same merge
      semantics as Sources.

    - **`source_port`** (string)  
      SourcePort is the source-port match: a single port "53" or
      a range "1024-65535". Empty means "any port".

    - **`destination_port`** (string)  
      DestPort is the destination-port match: single port or
      range. Empty means "any port".

    - **`protocol`** (string)  
      udp | tcp | tls | dtls | http | https | quic

  ### `acl.outbound[]`

    ```yaml
    outbound[]:
      action: string
      source: string
      destination: string
      sources: [string]
      destinations: [string]
      source_port: string
      destination_port: string
      protocol: string
    ```

    - **`action`** (string)  
      Action is what to do when a connection matches this rule.
      One of `allow` or `deny`. First-match-wins ordering applies
      across the rule list.

    - **`source`** (string)  
      Source is a single CIDR (or IP) the connection's source must
      match for this rule to fire. Empty means "any source".
      Singular form kept for back-compat with single-rule configs;
      for multiple sources use Sources instead.

    - **`destination`** (string)  
      Destination is a single CIDR (or IP) the connection's
      destination must match. Empty means "any destination".
      Singular form; for multiple destinations use Destinations.

    - **`sources`** ([string])  
      Sources is the list variant of Source. When non-empty it is
      used in addition to Source (the two are merged). Lets one
      rule cover many CIDRs rather than duplicating the rule.

    - **`destinations`** ([string])  
      Destinations is the list variant of Destination. Same merge
      semantics as Sources.

    - **`source_port`** (string)  
      SourcePort is the source-port match: a single port "53" or
      a range "1024-65535". Empty means "any port".

    - **`destination_port`** (string)  
      DestPort is the destination-port match: single port or
      range. Empty means "any port".

    - **`protocol`** (string)  
      udp | tcp | tls | dtls | http | https | quic

  ### `acl.relay[]`

    ```yaml
    relay[]:
      action: string
      source: string
      destination: string
      sources: [string]
      destinations: [string]
      source_port: string
      destination_port: string
      protocol: string
    ```

    - **`action`** (string)  
      Action is what to do when a connection matches this rule.
      One of `allow` or `deny`. First-match-wins ordering applies
      across the rule list.

    - **`source`** (string)  
      Source is a single CIDR (or IP) the connection's source must
      match for this rule to fire. Empty means "any source".
      Singular form kept for back-compat with single-rule configs;
      for multiple sources use Sources instead.

    - **`destination`** (string)  
      Destination is a single CIDR (or IP) the connection's
      destination must match. Empty means "any destination".
      Singular form; for multiple destinations use Destinations.

    - **`sources`** ([string])  
      Sources is the list variant of Source. When non-empty it is
      used in addition to Source (the two are merged). Lets one
      rule cover many CIDRs rather than duplicating the rule.

    - **`destinations`** ([string])  
      Destinations is the list variant of Destination. Same merge
      semantics as Sources.

    - **`source_port`** (string)  
      SourcePort is the source-port match: a single port "53" or
      a range "1024-65535". Empty means "any port".

    - **`destination_port`** (string)  
      DestPort is the destination-port match: single port or
      range. Empty means "any port".

    - **`protocol`** (string)  
      udp | tcp | tls | dtls | http | https | quic


## `forwards`

Forwards are host listeners that forward host-side traffic
into the tunnel. Per-listener proto + listen + target +
optional PROXY-protocol framing.

  _type:_ list of objects, each with these keys:

  ```yaml
  forwards:
    proto: string
    listen: string
    target: string
    proxy_protocol: string
    allow_unnamed_dgram: bool
    frame_bytes: int
  ```

  - **`proto`** (string)  
    Proto is the wire protocol of the forward: `tcp` or `udp`.
    For unix-socket listens, accept any of `tcp`, `udp`,
    `unix`, `unix+dgram`, `unix+seqpacket`.

  - **`listen`** (string)  
    Listen is the address to accept on. For forwards this is a host socket;
    for reverse_forwards it is a userspace WireGuard/netstack socket and may
    be an arbitrary tunnel-routed IP, not necessarily one assigned by Address=.

  - **`target`** (string)  
    Target is the address dialed for accepted traffic. For forwards this must
    be routed by WireGuard AllowedIPs. For reverse_forwards it is a normal
    host-network destination.

  - **`proxy_protocol`** (string)  
    ProxyProtocol enables HAProxy PROXY protocol metadata on this mapping.
    On forwards the incoming host-side header is parsed and stripped before
    dialing over WireGuard; on reverse_forwards a header is emitted to the
    host-side target. Valid values are "", "v1", and "v2".

  - **`allow_unnamed_dgram`** (bool)  
    AllowUnnamedDGRAM permits unnamed unixgram senders when Listen uses a
    unix+dgram socket for a forward. Unnamed senders cannot receive replies,
    so the default is false.

  - **`frame_bytes`** (int)  
    FrameBytes selects the big-endian length prefix used when a forward maps
    a stream protocol onto a message-oriented Unix socket, or a datagram
    protocol onto a Unix stream socket. Valid values are 0 (default to 4), 2,
    and 4.


## `turn`

TURN configures TURN as the base transport. Set base: turn alongside
this block.

  ```yaml
  turn:
    server: string
    protocol: string
    username: string
    password: string
    realm: string
    permissions: [string]
    no_create_permission: bool
    include_wg_public_key: bool
    tls: TLSConfig
  ```

  - **`server`** (string)  
    Server is the TURN server address (host:port).

  - **`protocol`** (string)  
    Protocol is how to reach the TURN server: udp | tcp | tls | dtls | http | https | quic.

  - **`username`** (string)  
    Username for TURN authentication.

  - **`password`** (string)  
    Password for TURN authentication.

  - **`realm`** (string)  
    Realm for TURN authentication (optional).

  - **`permissions`** ([string])  
    Permissions determines which peer endpoints are allowed to send traffic
    through the TURN relay.
    It can be a list of specific CIDRs.

  - **`no_create_permission`** (bool)  
    NoCreatePermission skips TURN CreatePermission and relies on relay policy.

  - **`include_wg_public_key`** (bool)  
    IncludeWGPublicKey appends an encrypted copy of this instance's
    WireGuard public key to the TURN username. The companion open TURN relay
    can use that metadata to bind allocations to a WireGuard identity.

  - **`tls`** (TLSConfig)  
    TLS configures TURNS and TURN-over-DTLS.

  ### `turn.tls`

    ```yaml
    tls:
      cert_file: string
      key_file: string
      verify_peer: bool
      reload_interval: string
      ca_file: string
      server_sni: OptionalString
    ```

    - **`cert_file`** (string)  
      CertFile path to PEM certificate. Empty → auto-generate self-signed.

    - **`key_file`** (string)  
      KeyFile path to PEM private key. Required when CertFile is set.

    - **`verify_peer`** (bool)  
      VerifyPeer enables remote certificate verification. Default false
      because WireGuard already provides mutual authentication.

    - **`reload_interval`** (string)  
      ReloadInterval is how often the cert file is checked for renewal,
      e.g. "60s". Empty or zero means no hot-reload.

    - **`ca_file`** (string)  
      CAFile path to PEM CA bundle used to validate the peer certificate.
      For clients, empty means use the system roots. For servers that require
      client certificates, a CAFile is mandatory.

    - **`server_sni`** (OptionalString)  
      ServerSNI controls the client-side TLS Server Name Indication.
      Unset means infer from the target hostname.
      Explicit null means send no SNI at all.
      A string value forces that SNI.

    ### `turn.tls.server_sni`

      ```yaml
      server_sni:
      ```


## `transports`

Transports defines the pluggable transport layer for WireGuard packets.
Each entry names a transport (base protocol + optional proxy) that can
be used in listen mode, client mode, or both.  Peers reference transports
by name; the first entry is the default.

If empty the legacy TURN config and UDP-listen logic apply unchanged.

  _type:_ list of objects, each with these keys:

  ```yaml
  transports:
    name: string
    base: string
    listen: bool
    listen_port: int?
    listen_addresses: [string]
    tls: TLSConfig
    turn: TURNConfig
    url: string
    websocket: WebSocketConfig
    proxy: ProxyConfig
    ipv6_translate: bool
    ipv6_prefix: string
  ```

  - **`name`** (string)  
    Name is a unique identifier referenced by peers.

  - **`base`** (string)  
    Base is the framing protocol: udp | turn | tcp | tls | dtls | http |
    https | quic | quic-ws | url

  - **`listen`** (bool)  
    Listen enables server-mode: the transport binds a fixed port and
    accepts incoming WireGuard connections.

  - **`listen_port`** (int?)  
    ListenPort overrides the wireguard.listen_port for this transport.
    Zero means inherit from wireguard.listen_port.

  - **`listen_addresses`** ([string])  
    ListenAddresses restricts the listen socket to specific IPs.
    Empty means all interfaces.

  - **`tls`** (TLSConfig)  
    TLS holds TLS / DTLS / HTTPS / QUIC certificate and validation options.

  - **`turn`** (TURNConfig)  
    TURN configures TURN as the base transport. Set base: turn alongside
    this block.

  - **`url`** (string)  
    URL is the full base URL for the "url" auto-negotiation transport,
    e.g. "https://example.com/wg". Only used when Base = "url".

  - **`websocket`** (WebSocketConfig)  
    WebSocket configures HTTP path / Host header details for HTTP-based transports.

  - **`proxy`** (ProxyConfig)  
    Proxy configures an optional proxy layer beneath the base transport.

  - **`ipv6_translate`** (bool)  
    IPv6Translate maps IPv4 addresses to IPv6 using NAT64/DNS64 prefix.

  - **`ipv6_prefix`** (string)  
    IPv6Prefix is the NAT64 /96 prefix. Defaults to "64:ff9b::/96".

  ### `transports[].tls`

    ```yaml
    tls:
      cert_file: string
      key_file: string
      verify_peer: bool
      reload_interval: string
      ca_file: string
      server_sni: OptionalString
    ```

    - **`cert_file`** (string)  
      CertFile path to PEM certificate. Empty → auto-generate self-signed.

    - **`key_file`** (string)  
      KeyFile path to PEM private key. Required when CertFile is set.

    - **`verify_peer`** (bool)  
      VerifyPeer enables remote certificate verification. Default false
      because WireGuard already provides mutual authentication.

    - **`reload_interval`** (string)  
      ReloadInterval is how often the cert file is checked for renewal,
      e.g. "60s". Empty or zero means no hot-reload.

    - **`ca_file`** (string)  
      CAFile path to PEM CA bundle used to validate the peer certificate.
      For clients, empty means use the system roots. For servers that require
      client certificates, a CAFile is mandatory.

    - **`server_sni`** (OptionalString)  
      ServerSNI controls the client-side TLS Server Name Indication.
      Unset means infer from the target hostname.
      Explicit null means send no SNI at all.
      A string value forces that SNI.

    ### `transports[].tls.server_sni`

      ```yaml
      server_sni:
      ```

  ### `transports[].turn`

    ```yaml
    turn:
      server: string
      username: string
      password: string
      realm: string
      protocol: string
      no_create_permission: bool
      include_wg_public_key: bool
      tls: TLSConfig
      permissions: [string]
    ```

    - **`server`** (string)  
      Server is the TURN server URL or host:port.

    - **`username`** (string)  
      Username is the long-term TURN credential username.

    - **`password`** (string)  
      Password is the long-term TURN credential password.

    - **`realm`** (string)  
      Realm is the TURN realm for long-term credentials.

    - **`protocol`** (string)  
      Protocol is how to reach the TURN server: udp | tcp | tls | dtls | http | https | quic
      Note: TURN does not need encryption for security, its only to bypass firewalls or hide the VPN as web traffic

    - **`no_create_permission`** (bool)  
      NoCreatePermission skips CreatePermission calls (open relays).

    - **`include_wg_public_key`** (bool)  
      IncludeWGPublicKey appends the encrypted WireGuard public key to the
      TURN username so the relay can associate allocations. The Wireguard public key is encrypted with the TURN password

    - **`tls`** (TLSConfig)  
      TLS configures TURN over TLS / DTLS. For TURN this is primarily useful
      for obfuscation and optional client/server certificate filtering.

    - **`permissions`** ([string])  
      Permissions is a list of IP/CIDR allowed to send relay traffic.

    ### `transports[].turn.tls`

      ```yaml
      tls:
        cert_file: string
        key_file: string
        verify_peer: bool
        reload_interval: string
        ca_file: string
        server_sni: OptionalString
      ```

      - **`cert_file`** (string)  
        CertFile path to PEM certificate. Empty → auto-generate self-signed.

      - **`key_file`** (string)  
        KeyFile path to PEM private key. Required when CertFile is set.

      - **`verify_peer`** (bool)  
        VerifyPeer enables remote certificate verification. Default false
        because WireGuard already provides mutual authentication.

      - **`reload_interval`** (string)  
        ReloadInterval is how often the cert file is checked for renewal,
        e.g. "60s". Empty or zero means no hot-reload.

      - **`ca_file`** (string)  
        CAFile path to PEM CA bundle used to validate the peer certificate.
        For clients, empty means use the system roots. For servers that require
        client certificates, a CAFile is mandatory.

      - **`server_sni`** (OptionalString)  
        ServerSNI controls the client-side TLS Server Name Indication.
        Unset means infer from the target hostname.
        Explicit null means send no SNI at all.
        A string value forces that SNI.

      ### `transports[].turn.tls.server_sni`

        ```yaml
        server_sni:
        ```

  ### `transports[].websocket`

    ```yaml
    websocket:
      path: string
      upgrade_mode: string
      connect_host: string
      host_header: string
      advertise_http3: bool
    ```

    - **`path`** (string)  
      Path is the HTTP path used for the WebSocket upgrade. Defaults to "/".

    - **`upgrade_mode`** (string)  
      UpgradeMode selects the HTTP upgrade protocol used by client-mode
      HTTP/HTTPS transports:
        "" | "websocket" → RFC 6455 WebSocket upgrade (default)
        "proxyguard"     → ProxyGuard UoTLV/1 native HTTP upgrade
      
      Listen mode always accepts both WebSocket and UoTLV/1 on the same path.

    - **`connect_host`** (string)  
      ConnectHost overrides the host used for DNS lookup and TCP/QUIC
      connection. When empty the peer endpoint host is used. This is the
      first of three independently configurable host values for domain
      fronting:
        ConnectHost  → DNS + actual TCP/QUIC connect
        TLS.ServerSNI → TLS ClientHello SNI
        HostHeader   → HTTP Host / :authority header (inner, often encrypted)

    - **`host_header`** (string)  
      HostHeader overrides the HTTP Host / :authority header sent in the
      upgrade request. Used for domain fronting where the HTTP layer is
      encrypted and the CDN routes on the inner host. Empty means use the
      target host.

    - **`advertise_http3`** (bool)  
      AdvertiseHTTP3 adds Alt-Svc: h3 on HTTPS listener responses so clients
      can discover a matching HTTP/3 endpoint on the same port. This does not
      enable QUIC by itself; configure a real QUIC listener separately.

  ### `transports[].proxy`

    ```yaml
    proxy:
      type: string
      socks5: SOCKS5ProxyConfig
      http: HTTPProxyConfig
    ```

    - **`type`** (string)  
      Type is: none | socks5 | http | https. Use base: turn for TURN.

    - **`socks5`** (SOCKS5ProxyConfig)  
      SOCKS5 settings, used when Type is "socks5".

    - **`http`** (HTTPProxyConfig)  
      HTTP CONNECT proxy settings, used when Type is "http" or "https".

    ### `transports[].proxy.socks5`

      ```yaml
      socks5:
        server: string
        username: string
        password: string
      ```

      - **`server`** (string)  
        Server is the SOCKS5 proxy host:port.

      - **`username`** (string)  
        Username for SOCKS5 user/password auth (RFC 1929). Empty means none.

      - **`password`** (string)  
        Password for SOCKS5 user/password auth.

    ### `transports[].proxy.http`

      ```yaml
      http:
        server: string
        username: string
        password: string
        tls: TLSConfig
      ```

      - **`server`** (string)  
        Server is the HTTP CONNECT proxy host:port.

      - **`username`** (string)  
        Username for HTTP Basic auth on the proxy. Empty means none.

      - **`password`** (string)  
        Password for HTTP Basic auth on the proxy.

      - **`tls`** (TLSConfig)  
        TLS configures HTTPS proxy transport.
        When verify_peer is omitted, HTTPS proxies default to:
        false for anonymous proxies, true when credentials are configured.

      ### `transports[].proxy.http.tls`

        ```yaml
        tls:
          cert_file: string
          key_file: string
          verify_peer: bool
          reload_interval: string
          ca_file: string
          server_sni: OptionalString
        ```

        - **`cert_file`** (string)  
          CertFile path to PEM certificate. Empty → auto-generate self-signed.

        - **`key_file`** (string)  
          KeyFile path to PEM private key. Required when CertFile is set.

        - **`verify_peer`** (bool)  
          VerifyPeer enables remote certificate verification. Default false
          because WireGuard already provides mutual authentication.

        - **`reload_interval`** (string)  
          ReloadInterval is how often the cert file is checked for renewal,
          e.g. "60s". Empty or zero means no hot-reload.

        - **`ca_file`** (string)  
          CAFile path to PEM CA bundle used to validate the peer certificate.
          For clients, empty means use the system roots. For servers that require
          client certificates, a CAFile is mandatory.

        - **`server_sni`** (OptionalString)  
          ServerSNI controls the client-side TLS Server Name Indication.
          Unset means infer from the target hostname.
          Explicit null means send no SNI at all.
          A string value forces that SNI.

        ### `transports[].proxy.http.tls.server_sni`

          ```yaml
          server_sni:
          ```


## `reverse_forwards`

ReverseForwards listen inside the userspace WireGuard netstack and dial
out to the host network. They are narrower than transparent inbound
forwarding because only explicitly configured tunnel IP:port pairs are
exposed.

  _type:_ list of objects, each with these keys:

  ```yaml
  reverse_forwards:
    proto: string
    listen: string
    target: string
    proxy_protocol: string
    allow_unnamed_dgram: bool
    frame_bytes: int
  ```

  - **`proto`** (string)  
    Proto is the wire protocol of the forward: `tcp` or `udp`.
    For unix-socket listens, accept any of `tcp`, `udp`,
    `unix`, `unix+dgram`, `unix+seqpacket`.

  - **`listen`** (string)  
    Listen is the address to accept on. For forwards this is a host socket;
    for reverse_forwards it is a userspace WireGuard/netstack socket and may
    be an arbitrary tunnel-routed IP, not necessarily one assigned by Address=.

  - **`target`** (string)  
    Target is the address dialed for accepted traffic. For forwards this must
    be routed by WireGuard AllowedIPs. For reverse_forwards it is a normal
    host-network destination.

  - **`proxy_protocol`** (string)  
    ProxyProtocol enables HAProxy PROXY protocol metadata on this mapping.
    On forwards the incoming host-side header is parsed and stripped before
    dialing over WireGuard; on reverse_forwards a header is emitted to the
    host-side target. Valid values are "", "v1", and "v2".

  - **`allow_unnamed_dgram`** (bool)  
    AllowUnnamedDGRAM permits unnamed unixgram senders when Listen uses a
    unix+dgram socket for a forward. Unnamed senders cannot receive replies,
    so the default is false.

  - **`frame_bytes`** (int)  
    FrameBytes selects the big-endian length prefix used when a forward maps
    a stream protocol onto a message-oriented Unix socket, or a datagram
    protocol onto a Unix stream socket. Valid values are 0 (default to 4), 2,
    and 4.


## `dns_server`

DNSServer is the optional DNS server hosted INSIDE the
tunnel for peers/clients to query. Distinct from the
runtime resolve API at /v1/resolve.

  ```yaml
  dns_server:
    listen: string
    max_inflight: int
  ```

  - **`listen`** (string)  
    Host listen address or unix:// socket path.

  - **`max_inflight`** (int) — default: `1024`  
    Maximum concurrent DNS requests handled at once.


## `scripts`

Scripts gates the wg-quick PreUp/PostUp/PreDown/PostDown
hook execution. Off by default; turning on lets WG-quick
configs run shell commands, so only enable for trusted
local input.

  ```yaml
  scripts:
    allow: bool
  ```

  - **`allow`** (bool)  
    Allow is opt-in because this userspace runtime does not need shell hooks
    for ordinary routing or firewall setup.


## `log`

Log selects log verbosity and the destination format.

  ```yaml
  log:
    verbose: bool
  ```

  - **`verbose`** (bool)  
    Enable verbose/debug-style logging.


## `metrics`

Metrics configures the optional Prometheus-compatible
/metrics endpoint. Bound on a separate listener from API
so the scrape secret can differ.

  ```yaml
  metrics:
    listen: string
    token: string
    per_peer_detail: bool
    max_per_peer: int
  ```

  - **`listen`** (string)  
    Listen is the TCP host:port (or "unix:/path") for the metrics
    endpoint. Empty disables the metrics subsystem entirely.

  - **`token`** (string)  
    Token, if non-empty, is required as a Bearer token on /metrics.
    Empty means the endpoint is unauthenticated — fine for loopback /
    firewalled bind addresses, dangerous otherwise. The operator picks.

  - **`per_peer_detail`** (bool)  
    PerPeerDetail emits per-peer time series (bytes, last_handshake).
    Off by default because hub deployments can have thousands of peers
    and Prometheus cardinality scales linearly. Capped at MaxPerPeer
    regardless of how many peers exist.

  - **`max_per_peer`** (int)  
    MaxPerPeer caps the number of per-peer series emitted when
    PerPeerDetail is true. Beyond this, an "_overflow" peer label
    catches the rest in aggregate. Zero or negative means use default.


