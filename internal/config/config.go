// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package config owns the three configuration inputs: YAML runtime config,
// wg-quick style WireGuard config, and the normalized structures consumed by
// the engine. CLI flags are applied in cmd/uwgsocks before Normalize.
package config

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// WireGuard interface + peer settings: keys, addresses, peers,
	// keepalives, hook scripts. See the wg-quick man page for the
	// underlying field semantics.
	WireGuard WireGuard `yaml:"wireguard"`
	// Proxy configures host-side SOCKS5 / HTTP proxy listeners that
	// route client traffic into the tunnel. See the proxy.* fields
	// for listener bind addrs, auth, fallback behaviour, and
	// per-route outbound proxy chains.
	Proxy Proxy `yaml:"proxy"`
	// Inbound (a.k.a. "transparent inbound") accepts WireGuard peer
	// traffic destined for host services. Off by default; turning
	// on means tunnel-side peers can reach host loopback and the
	// host network through redirected connections.
	Inbound Inbound `yaml:"inbound"`
	// HostForward controls whether proxy clients (and inbound
	// tunnel peers) can reach host-local services. The two sub-
	// blocks are independent and OFF by default for inbound.
	HostForward HostForward `yaml:"host_forward"`
	// MeshControl is the optional tunnel-only peer-discovery and
	// dynamic-ACL synchronisation plane. See docs/howto/05-mesh-
	// coordination.md for the full protocol.
	MeshControl MeshControl `yaml:"mesh_control"`
	// Routing chooses the order in which the engine resolves a
	// destination IP across the available tunnel/peer/proxy paths
	// (see docs/reference/proxy-routing.md).
	Routing Routing `yaml:"routing"`
	// TUN is the optional host-TUN backend. When `enabled: true`
	// the engine creates a real TUN device and adds routes for
	// the tunnel addresses; when off, traffic is reachable only
	// through the proxy/socket-API/wrapper paths.
	TUN TUN `yaml:"tun"`
	// Filtering applies blanket ingress drops to the userspace
	// netstack (e.g. drop IPv6 link-local multicast). Off-by-
	// default safety nets, not a substitute for ACLs.
	Filtering Filtering `yaml:"filtering"`
	// TrafficShaper applies a global token-bucket rate limit to
	// the tunnel. Per-peer shapers under wireguard.peers[]
	// override the global value.
	TrafficShaper TrafficShaper `yaml:"traffic_shaper"`
	// Relay enables hub-mode peer-to-peer forwarding (one peer's
	// traffic destined for another peer's AllowedIPs is forwarded
	// rather than dropped). See the acl.relay rules for the
	// matching policy.
	Relay Relay `yaml:"relay"`
	// API configures the management HTTP listener (status, peer
	// add/remove, ACL replace). See docs/reference/api-reference.md
	// for the full endpoint surface.
	API API `yaml:"api"`
	// SocketAPI configures the raw socket protocol exposed at
	// `/v1/socket` and `/uwg/socket`. Used by the wrapper, by
	// language SDKs, and by direct integrators. See
	// docs/reference/socket-protocol.md.
	SocketAPI SocketAPI `yaml:"socket_api"`
	// ACL holds the three policy planes — inbound, outbound, and
	// relay — each with a default action plus an ordered rule
	// list. First-match-wins.
	ACL ACL `yaml:"acl"`
	// Forwards are host listeners that forward host-side traffic
	// into the tunnel. Per-listener proto + listen + target +
	// optional PROXY-protocol framing.
	Forwards []Forward `yaml:"forwards"`
	// TURN is the legacy single-TURN-server config block, kept for
	// wg-quick compatibility. New configs should use a transports[]
	// entry with `base: turn` instead.
	TURN TURN `yaml:"turn"`
	// Transports defines the pluggable transport layer for WireGuard packets.
	// Each entry names a transport (base protocol + optional proxy) that can
	// be used in listen mode, client mode, or both.  Peers reference transports
	// by name; the first entry is the default.
	//
	// If empty the legacy TURN config and UDP-listen logic apply unchanged.
	Transports []transport.Config `yaml:"transports"`
	// ReverseForwards listen inside the userspace WireGuard netstack and dial
	// out to the host network. They are narrower than transparent inbound
	// forwarding because only explicitly configured tunnel IP:port pairs are
	// exposed.
	ReverseForwards []Forward `yaml:"reverse_forwards"`
	// DNSServer is the optional DNS server hosted INSIDE the
	// tunnel for peers/clients to query. Distinct from the
	// runtime resolve API at /v1/resolve.
	DNSServer DNSServer `yaml:"dns_server"`
	// Scripts gates the wg-quick PreUp/PostUp/PreDown/PostDown
	// hook execution. Off by default; turning on lets WG-quick
	// configs run shell commands, so only enable for trusted
	// local input.
	Scripts Scripts `yaml:"scripts"`
	// Log selects log verbosity and the destination format.
	Log Log `yaml:"log"`
	// Metrics configures the optional Prometheus-compatible
	// /metrics endpoint. Bound on a separate listener from API
	// so the scrape secret can differ.
	Metrics Metrics `yaml:"metrics"`
}

// Metrics configures the optional Prometheus-compatible /metrics endpoint.
// It is hosted on a separate listener from the admin API so the scrape
// secret can be a different one (or none) — Prometheus scrape configs are
// commonly committed to git or shared across teams, and we don't want that
// secret to imply admin access. See docs/reference/metrics.md.
type Metrics struct {
	// Listen is the TCP host:port (or "unix:/path") for the metrics
	// endpoint. Empty disables the metrics subsystem entirely.
	Listen string `yaml:"listen"`
	// Token, if non-empty, is required as a Bearer token on /metrics.
	// Empty means the endpoint is unauthenticated — fine for loopback /
	// firewalled bind addresses, dangerous otherwise. The operator picks.
	Token string `yaml:"token"`
	// PerPeerDetail emits per-peer time series (bytes, last_handshake).
	// Off by default because hub deployments can have thousands of peers
	// and Prometheus cardinality scales linearly. Capped at MaxPerPeer
	// regardless of how many peers exist.
	PerPeerDetail bool `yaml:"per_peer_detail"`
	// MaxPerPeer caps the number of per-peer series emitted when
	// PerPeerDetail is true. Beyond this, an "_overflow" peer label
	// catches the rest in aggregate. Zero or negative means use default.
	MaxPerPeer int `yaml:"max_per_peer"`
}

type WireGuard struct {
	// Path to wg-quick style config.
	ConfigFile string `yaml:"config_file"`
	// Inline wg-quick text.
	Config string `yaml:"config"`

	// These fields mirror the wg-quick [Interface] and [Peer] values that make
	// sense for a userspace, no-TUN runtime. Table/SaveConfig are accepted but
	// ignored because the process never mutates the host routing table.
	PrivateKey string `yaml:"private_key"`
	// UDP listen port when listening directly.
	ListenPort *int `yaml:"listen_port"`
	// ListenAddresses restrict server-mode WireGuard UDP sockets to specific
	// local IP addresses. Empty means wireguard-go's normal all-IPv4/all-IPv6
	// listeners.
	ListenAddresses []string `yaml:"listen_addresses"`
	// Local tunnel IPs/CIDRs.
	Addresses []string `yaml:"addresses"`
	// Userspace tunnel MTU.
	MTU int `yaml:"mtu"`
	// DNS servers learned from wg-quick.
	DNS []string `yaml:"dns"`
	// RoamFallbackSeconds reapplies a peer's configured static Endpoint after
	// roaming if the live endpoint stops handshaking for this long. Peers
	// without Endpoint= remain dynamic and are not affected.
	RoamFallbackSeconds int `yaml:"roam_fallback_seconds"`
	// Script hooks; only run when scripts.allow=true.
	PreUp []string `yaml:"pre_up"`
	// Script hooks after startup; require scripts.allow=true.
	PostUp []string `yaml:"post_up"`
	// Script hooks before shutdown; require scripts.allow=true.
	PreDown []string `yaml:"pre_down"`
	// Script hooks after shutdown; require scripts.allow=true.
	PostDown []string `yaml:"post_down"`
	// Peers is the list of WireGuard peers known at startup.
	// Each entry holds public-key, AllowedIPs, optional endpoint
	// + transport, plus the mesh-control flags. Mirrors the
	// [Peer] sections of a wg-quick config.
	Peers []Peer `yaml:"peers"`

	// DefaultTransport is the name of the transport used for peers that do not
	// specify an explicit Transport field.  When empty the first NCO transport
	// in the Transports list is used; if none exist the first transport is used.
	DefaultTransport string `yaml:"default_transport,omitempty"`

	// Fields synthesized from #! directives in wg-quick config files.
	// TURNDirectives holds raw TURN URLs from #!TURN= lines, e.g. "turn+tls://user:pass@host:port".
	TURNDirectives []string `yaml:"turn_directives,omitempty"`
	// TCPListen enables a TCP listener synthesized from a #!TCP directive in [Interface].
	TCPListen bool `yaml:"tcp_listen,omitempty"`
}

type TURN struct {
	// Server is the TURN server address (host:port).
	Server string `yaml:"server"`
	// Protocol is how to reach the TURN server: udp | tcp | tls | dtls | http | https | quic.
	Protocol string `yaml:"protocol"`
	// Username for TURN authentication.
	Username string `yaml:"username"`
	// Password for TURN authentication.
	Password string `yaml:"password"`
	// Realm for TURN authentication (optional).
	Realm string `yaml:"realm"`
	// Permissions determines which peer endpoints are allowed to send traffic
	// through the TURN relay.
	// It can be a list of specific CIDRs.
	Permissions []string `yaml:"permissions"`
	// NoCreatePermission skips TURN CreatePermission and relies on relay policy.
	NoCreatePermission bool `yaml:"no_create_permission"`
	// IncludeWGPublicKey appends an encrypted copy of this instance's
	// WireGuard public key to the TURN username. The companion open TURN relay
	// can use that metadata to bind allocations to a WireGuard identity.
	IncludeWGPublicKey bool `yaml:"include_wg_public_key"`
	// TLS configures TURNS and TURN-over-DTLS.
	TLS transport.TLSConfig `yaml:"tls"`
}

type Peer struct {
	// PublicKey is the peer's base64 WireGuard public key. Required.
	PublicKey string `yaml:"public_key"`
	// Optional base64 WireGuard preshared key.
	PresharedKey string `yaml:"preshared_key"`
	// host:port or tagged scheme URL.
	Endpoint string `yaml:"endpoint"`
	// Routed subnets/IPs for this peer.
	AllowedIPs []string `yaml:"allowed_ips"`
	// Keepalive interval in seconds; 0 disables it.
	PersistentKeepalive int `yaml:"persistent_keepalive"`
	// TrafficShaper applies a per-peer rate limit / latency
	// budget. Overrides the top-level traffic_shaper for this
	// peer's flows. Zero values inherit from the global shaper.
	TrafficShaper TrafficShaper `yaml:"traffic_shaper"`
	// Mesh control URL for this parent peer.
	ControlURL string `yaml:"control_url,omitempty"`
	// Allow dynamic mesh peers to be learned from this peer.
	MeshEnabled bool `yaml:"mesh_enabled,omitempty"`
	// null means default behavior.
	MeshAdvertise *bool `yaml:"mesh_advertise,omitempty"`
	// Opt out of distributed mesh ACL enforcement locally.
	MeshDisableACLs bool `yaml:"mesh_disable_acls,omitempty"`
	// Usually enabled when this peer participates in mesh ACLs.
	MeshAcceptACLs bool `yaml:"mesh_accept_acls,omitempty"`
	// untrusted | trusted_always | trusted_if_dynamic_acls
	MeshTrust MeshTrust `yaml:"mesh_trust,omitempty"`
	// Transport is the name of a transport from the top-level transports list.
	// Empty means use the default transport (first entry, or legacy UDP).
	Transport string `yaml:"transport,omitempty"`

	// Fields synthesized from #! directives in wg-quick config files.
	// TCPMode is set by #!TCP=: "no" (default), "supported", "required".
	TCPMode string `yaml:"tcp_mode,omitempty"`
	// SkipVerifyTLS is set by #!SkipVerifyTLS=: nil=default, true=skip, false=verify.
	SkipVerifyTLS *bool `yaml:"skip_verify_tls,omitempty"`
	// ConnectURL is set by #!URL=: full URL for auto-negotiation transport.
	ConnectURL string `yaml:"connect_url,omitempty"`
}

type MeshTrust string

const (
	MeshTrustUntrusted            MeshTrust = "untrusted"
	MeshTrustTrustedAlways        MeshTrust = "trusted_always"
	MeshTrustTrustedIfDynamicACLs MeshTrust = "trusted_if_dynamic_acls"
)

type Proxy struct {
	// SOCKS5 is the host SOCKS5 listen address (host:port or
	// "unix:/path"). Empty disables the SOCKS5 listener.
	SOCKS5 string `yaml:"socks5"`
	// Host HTTP proxy listen address.
	HTTP string `yaml:"http"`
	// Extra HTTP listeners, including unix: paths.
	HTTPListeners []string `yaml:"http_listeners"`
	// Combined SOCKS5+HTTP listener.
	Mixed string `yaml:"mixed"`
	// Proxy auth username.
	Username string `yaml:"username"`
	// Proxy auth password.
	Password string `yaml:"password"`
	// Allow direct host dials after routing misses.
	FallbackDirect *bool `yaml:"fallback_direct"`
	// FallbackSOCKS5 is an upstream SOCKS5 address used when no
	// tunnel route matches (and FallbackDirect is off). Empty
	// means no SOCKS5 fallback.
	FallbackSOCKS5 string `yaml:"fallback_socks5"`
	// IPv6 controls whether proxy listeners accept IPv6 client
	// connections and whether outbound dials may use IPv6. Nil
	// means default (true on dual-stack hosts).
	IPv6 *bool `yaml:"ipv6"`
	// Enable SOCKS5 UDP ASSOCIATE.
	UDPAssociate *bool `yaml:"udp_associate"`
	// Optional port or range for UDP ASSOCIATE.
	UDPAssociatePorts string `yaml:"udp_associate_ports"`
	// Accept absolute-form HTTPS proxy requests.
	HTTPSProxying *bool `yaml:"https_proxying"`
	// none | pki | ca | both
	HTTPSProxyVerify string `yaml:"https_proxy_verify"`
	// CA bundle for https_proxy_verify ca/both.
	HTTPSProxyCAFile string `yaml:"https_proxy_ca_file"`
	// Enable SOCKS5 BIND and listener-style raw sockets.
	Bind *bool `yaml:"bind"`
	// Allow ports below 1024 where supported.
	LowBind *bool `yaml:"lowbind"`
	// PreferIPv6ForUDPOverSOCKS routes SOCKS5-UDP through IPv6
	// when both stacks are available. Off by default; turn on
	// for environments where IPv4 UDP is heavily filtered.
	PreferIPv6ForUDPOverSOCKS *bool `yaml:"prefer_ipv6_for_udp_over_socks"`
	// Import ALL_PROXY/HTTP(S)_PROXY fallbacks.
	HonorEnvironment *bool `yaml:"honor_environment"`
	// OutboundProxies is the list of upstream proxies the engine
	// can chain to for matched destinations. Per-entry roles +
	// subnets select where each proxy applies. See the
	// OutboundProxy fields for the shape.
	OutboundProxies []OutboundProxy `yaml:"outbound_proxies"`
}

type OutboundProxy struct {
	// Type is "socks5" or "http". If Address is a URL, the scheme fills this.
	Type string `yaml:"type" json:"type"`
	// Address is host:port or a URL such as socks5://127.0.0.1:1080.
	Address string `yaml:"address" json:"address"`
	// Proxy auth username.
	Username string `yaml:"username" json:"username,omitempty"`
	// Proxy auth password.
	Password string `yaml:"password" json:"password,omitempty"`
	// Roles controls whether the proxy can be used for SOCKS/HTTP proxy clients,
	// transparent inbound WireGuard forwarding, or both. Empty means both.
	Roles []string `yaml:"roles" json:"roles,omitempty"`
	// Subnets limits destinations that use this proxy. Empty means all
	// destinations. When several proxies match, the most-specific prefix wins.
	Subnets []string `yaml:"subnets" json:"subnets,omitempty"`
}

type Inbound struct {
	// Accept tunnel TCP/UDP directly to host sockets.
	Transparent *bool `yaml:"transparent"`
	// strict | loose | disabled
	ConsistentPort string `yaml:"consistent_port"`
	// Reject host ports below 1024 unless explicitly allowed.
	DisableLowPorts *bool `yaml:"disable_low_ports"`
	// Forward ICMP errors back into the tunnel when possible.
	ForwardICMPErrors *bool `yaml:"forward_icmp_errors"`
	// Clamp MSS on inbound TCP to avoid PMTU issues.
	TCPMSSClamp *bool `yaml:"tcp_mss_clamp"`
	// Generate local ICMP echo replies where supported.
	ReplyICMP *bool `yaml:"reply_icmp"`
	// Per-peer ICMP reply rate limit.
	ICMPRateLimitPerSec int `yaml:"icmp_rate_limit_per_sec"`
	// Global inbound connection cap; 0 means unlimited.
	MaxConnections int `yaml:"max_connections"`
	// Per-peer inbound connection cap; 0 means unlimited.
	MaxConnectionsPerPeer int `yaml:"max_connections_per_peer"`
	// Keep closed-flow state briefly for late packets.
	ConnectionTableGraceSeconds int `yaml:"connection_table_grace_seconds"`
	// Netstack TCP receive window for inbound flows.
	TCPReceiveWindowBytes int `yaml:"tcp_receive_window_bytes"`
	// Global buffered TCP cap for inbound flows.
	TCPMaxBufferedBytes int `yaml:"tcp_max_buffered_bytes"`
	// HostDialProxySOCKS5 is an optional upstream SOCKS5 to use
	// when transparent inbound flows need to dial host services
	// through a proxy rather than directly. Empty means dial
	// directly.
	HostDialProxySOCKS5 string `yaml:"host_dial_proxy_socks5"`
	// Optional host source IP for transparent outbound dials.
	HostDialBindAddress string `yaml:"host_dial_bind_address"`
	// Idle timeout for transparent inbound TCP flows.
	TCPIdleTimeoutSeconds int `yaml:"tcp_idle_timeout_seconds"`
	// Idle timeout for transparent inbound UDP flows.
	UDPIdleTimeoutSeconds int `yaml:"udp_idle_timeout_seconds"`
}

type HostForward struct {
	// Proxy controls SOCKS5/HTTP requests to local tunnel addresses,
	// localhost, and 127.0.0.0/8. It defaults on so a proxy client can reach
	// services on the same host through the familiar local names.
	Proxy HostForwardEndpoint `yaml:"proxy"`
	// Inbound controls WireGuard packets addressed to this peer's tunnel IPs
	// when no userspace listener owns the port. It defaults off because it can
	// expose loopback-only host services to remote peers.
	Inbound HostForwardEndpoint `yaml:"inbound"`
}

type HostForwardEndpoint struct {
	// Allow proxy clients to reach host-local services.
	Enabled *bool `yaml:"enabled"`
	// Optional host IP to use instead of loopback.
	RedirectIP string `yaml:"redirect_ip"`
	// Re-enter through the host TUN path.
	RedirectTUN bool `yaml:"redirect_tun"`
}

type Routing struct {
	// EnforceAddressSubnets makes Address=10.10.10.2/24 behave like a real
	// interface route: other addresses in 10.10.10.0/24 must be routed by
	// AllowedIPs or they are rejected instead of falling back to the Internet.
	EnforceAddressSubnets *bool `yaml:"enforce_address_subnets"`
}

type TUN struct {
	// Enabled creates a host OS TUN interface and terminates traffic from that
	// interface in a second userspace netstack. The main no-/dev/net/tun mode
	// remains the default.
	Enabled bool `yaml:"enabled"`
	// Name is the requested host interface name. The kernel may still return a
	// concrete name when patterns such as "uwgsocks%d" are used.
	Name string `yaml:"name"`
	// MTU defaults to wireguard.mtu.
	MTU int `yaml:"mtu"`
	// Configure asks uwgsocks to configure addresses/routes with netlink. When
	// false, external scripts or an operator may configure the interface.
	Configure bool `yaml:"configure"`
	// RouteAllowedIPs installs peer AllowedIPs as kernel routes when Configure
	// is true. Extra Routes are always added when Configure is true.
	RouteAllowedIPs *bool `yaml:"route_allowed_ips"`
	// Routes are additional CIDRs routed to the TUN interface.
	Routes []string `yaml:"routes"`
	// DNSServers are optional host DNS servers configured on the TUN interface
	// when the platform backend supports it.
	DNSServers []string `yaml:"dns_servers"`
	// DNSResolvConf, when set, writes tun.dns_servers as plain "nameserver"
	// lines into this file instead of using platform DNS manager APIs.
	DNSResolvConf string `yaml:"dns_resolv_conf"`
	// FallbackSystemDNS is used only for resolving outer WireGuard transport
	// hostnames outside the tunnel when host-TUN routes are active.
	FallbackSystemDNS []string `yaml:"fallback_system_dns"`
	// Up and Down are optional shell snippets run after interface creation and
	// before teardown when scripts.allow is true.
	Up []string `yaml:"up"`
	// Teardown hooks; require scripts.allow=true.
	Down []string `yaml:"down"`
}

type Filtering struct {
	// DropIPv6LinkLocalMulticast drops IPv6 multicast packets in
	// the fe80::/10 link-local range at netstack ingress. Off by
	// default; turn on for environments where MLD/router-advert
	// chatter pollutes the tunnel.
	DropIPv6LinkLocalMulticast *bool `yaml:"drop_ipv6_link_local_multicast"`
	// DropIPv4Invalid drops malformed IPv4 packets (invalid IHL,
	// total-length mismatch, etc.) at netstack ingress. Default
	// on — turning off is rarely needed.
	DropIPv4Invalid *bool `yaml:"drop_ipv4_invalid"`
}

type TrafficShaper struct {
	// Upload ceiling in bytes per second.
	UploadBps int64 `yaml:"upload_bps" json:"upload_bps"`
	// Download ceiling in bytes per second.
	DownloadBps int64 `yaml:"download_bps" json:"download_bps"`
	// Extra artificial latency in milliseconds.
	LatencyMillis int `yaml:"latency_ms" json:"latency_ms"`
}

func (t TrafficShaper) IsZero() bool {
	return t.UploadBps == 0 && t.DownloadBps == 0 && t.LatencyMillis == 0
}

type Relay struct {
	// Allow proxy clients to reach host-local services.
	Enabled *bool `yaml:"enabled"`
	// Keep stateful relay conntrack enabled.
	Conntrack *bool `yaml:"conntrack"`
	// Global relay flow table cap.
	ConntrackMaxFlows int `yaml:"conntrack_max_flows"`
	// Per-peer relay flow table cap.
	ConntrackMaxPerPeer int `yaml:"conntrack_max_per_peer"`
}

type API struct {
	// Host listen address or unix:// socket path.
	Listen string `yaml:"listen"`
	// Bearer token for HTTP listeners.
	Token string `yaml:"token"`
	// Allow trusted local Unix-socket callers without a token.
	AllowUnauthenticatedUnix bool `yaml:"allow_unauthenticated_unix"`
}

type SocketAPI struct {
	// Bind enables TCP listener sockets over /v1/socket. UDP bind-style sockets
	// are allowed without this flag, but stay established-only unless UDPInbound
	// is also set.
	Bind bool `yaml:"bind"`
	// TransparentBind permits clients to bind source addresses outside the
	// configured WireGuard interface addresses. This is intentionally separate
	// from Bind because it can intercept traffic meant for other tunnel IPs.
	TransparentBind bool `yaml:"transparent_bind"`
	// UDPInbound lets UDP listener sockets receive datagrams before the local
	// application has sent to that remote address.
	UDPInbound bool `yaml:"udp_inbound"`
}

type ACL struct {
	// allow | deny
	InboundDefault acl.Action `yaml:"inbound_default"`
	// allow | deny
	OutboundDefault acl.Action `yaml:"outbound_default"`
	// allow | deny
	RelayDefault acl.Action `yaml:"relay_default"`
	// Ordered inbound ACL rule list.
	Inbound []acl.Rule `yaml:"inbound"`
	// Ordered outbound ACL rule list.
	Outbound []acl.Rule `yaml:"outbound"`
	// Ordered relay ACL rule list.
	Relay []acl.Rule `yaml:"relay"`
}

type Forward struct {
	// Proto is the wire protocol of the forward: `tcp` or `udp`.
	// For unix-socket listens, accept any of `tcp`, `udp`,
	// `unix`, `unix+dgram`, `unix+seqpacket`.
	Proto string `yaml:"proto"`
	// Listen is the address to accept on. For forwards this is a host socket;
	// for reverse_forwards it is a userspace WireGuard/netstack socket and may
	// be an arbitrary tunnel-routed IP, not necessarily one assigned by Address=.
	Listen string `yaml:"listen"`
	// Target is the address dialed for accepted traffic. For forwards this must
	// be routed by WireGuard AllowedIPs. For reverse_forwards it is a normal
	// host-network destination.
	Target string `yaml:"target"`
	// ProxyProtocol enables HAProxy PROXY protocol metadata on this mapping.
	// On forwards the incoming host-side header is parsed and stripped before
	// dialing over WireGuard; on reverse_forwards a header is emitted to the
	// host-side target. Valid values are "", "v1", and "v2".
	ProxyProtocol string `yaml:"proxy_protocol"`
	// AllowUnnamedDGRAM permits unnamed unixgram senders when Listen uses a
	// unix+dgram socket for a forward. Unnamed senders cannot receive replies,
	// so the default is false.
	AllowUnnamedDGRAM bool `yaml:"allow_unnamed_dgram,omitempty"`
	// FrameBytes selects the big-endian length prefix used when a forward maps
	// a stream protocol onto a message-oriented Unix socket, or a datagram
	// protocol onto a Unix stream socket. Valid values are 0 (default to 4), 2,
	// and 4.
	FrameBytes int `yaml:"frame_bytes,omitempty"`
}

type DNSServer struct {
	// Host listen address or unix:// socket path.
	Listen string `yaml:"listen"`
	// Maximum concurrent DNS requests handled at once.
	MaxInflight int `yaml:"max_inflight"`
}

type MeshControl struct {
	// Host listen address or unix:// socket path.
	Listen string `yaml:"listen"`
	// Rotate auth challenges on this interval.
	ChallengeRotateSeconds int `yaml:"challenge_rotate_seconds"`
	// Only advertise recently active peers.
	ActivePeerWindowSeconds int `yaml:"active_peer_window_seconds"`
	// NotifyWindowSeconds is how far in the future a mesh
	// notification's deadline can extend. Caps long-poll
	// subscriptions; clients reconnect after the window. Zero
	// uses the default (300s).
	NotifyWindowSeconds int `yaml:"notify_window_seconds"`
	// NotifyMinIntervalSeconds is the minimum gap between two
	// mesh notifications to the same client. Rate-limits
	// chatty peer-event firehoses. Zero uses the default (45s).
	NotifyMinIntervalSeconds int `yaml:"notify_min_interval_seconds"`
	// Maximum lifetime for mesh event streams.
	SubscribeMaxLifetimeSeconds int `yaml:"subscribe_max_lifetime_seconds"`
	// Include the current node itself in mesh responses.
	AdvertiseSelf bool `yaml:"advertise_self"`
}

type Scripts struct {
	// Allow is opt-in because this userspace runtime does not need shell hooks
	// for ordinary routing or firewall setup.
	Allow bool `yaml:"allow"`
}

type Log struct {
	// Enable verbose/debug-style logging.
	Verbose bool `yaml:"verbose"`
}

func Default() Config {
	return Config{
		WireGuard: WireGuard{MTU: 1420, RoamFallbackSeconds: 120},
		Proxy: Proxy{
			FallbackDirect:            boolPtr(true),
			UDPAssociate:              boolPtr(true),
			HTTPSProxying:             boolPtr(true),
			HTTPSProxyVerify:          "pki",
			Bind:                      boolPtr(false),
			LowBind:                   boolPtr(false),
			PreferIPv6ForUDPOverSOCKS: boolPtr(false),
			HonorEnvironment:          boolPtr(true),
		},
		Inbound: Inbound{
			Transparent:                 boolPtr(false),
			ConsistentPort:              "loose",
			DisableLowPorts:             boolPtr(true),
			ForwardICMPErrors:           boolPtr(true),
			TCPMSSClamp:                 boolPtr(true),
			ReplyICMP:                   boolPtr(true),
			ICMPRateLimitPerSec:         10,
			ConnectionTableGraceSeconds: 30,
			TCPReceiveWindowBytes:       1 << 20,
			TCPMaxBufferedBytes:         256 << 20,
			TCPIdleTimeoutSeconds:       15 * 60,
			UDPIdleTimeoutSeconds:       30,
		},
		HostForward: HostForward{
			Proxy:   HostForwardEndpoint{Enabled: boolPtr(true)},
			Inbound: HostForwardEndpoint{Enabled: boolPtr(false)},
		},
		TUN:       TUN{Name: "uwgsocks0", RouteAllowedIPs: boolPtr(true)},
		Routing:   Routing{EnforceAddressSubnets: boolPtr(true)},
		Filtering: Filtering{DropIPv6LinkLocalMulticast: boolPtr(true), DropIPv4Invalid: boolPtr(true)},
		Relay: Relay{
			Enabled:             boolPtr(false),
			Conntrack:           boolPtr(true),
			ConntrackMaxFlows:   65536,
			ConntrackMaxPerPeer: 4096,
		},
		ACL: ACL{
			InboundDefault:  acl.Allow,
			OutboundDefault: acl.Allow,
			RelayDefault:    acl.Deny,
		},
		API: API{
			AllowUnauthenticatedUnix: true,
		},
		Scripts: Scripts{Allow: false},
		DNSServer: DNSServer{
			MaxInflight: 1024,
		},
		MeshControl: MeshControl{
			ChallengeRotateSeconds:      120,
			ActivePeerWindowSeconds:     120,
			NotifyWindowSeconds:         120,
			NotifyMinIntervalSeconds:    60,
			SubscribeMaxLifetimeSeconds: 300,
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return Config{}, err
		}
	}
	// When scripts are disabled (the default for hostile/network-supplied
	// configs), refuse PreUp/PostUp/PreDown/PostDown at parse time so a
	// hostile .conf can never stage a hook even if scripts.allow is later
	// flipped on by mistake or by a separate config layer.
	if cfg.WireGuard.ConfigFile != "" {
		if err := mergeWGQuickFile(&cfg.WireGuard, cfg.WireGuard.ConfigFile, !cfg.Scripts.Allow); err != nil {
			return Config{}, err
		}
	}
	if cfg.WireGuard.Config != "" {
		if err := mergeWGQuick(&cfg.WireGuard, cfg.WireGuard.Config, !cfg.Scripts.Allow); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.Normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Normalize fills defaults and pre-validates values that would otherwise fail
// later, after sockets and WireGuard devices have already been created.
func (c *Config) Normalize() error {
	if c.WireGuard.MTU == 0 {
		c.WireGuard.MTU = 1420
	}
	if c.WireGuard.RoamFallbackSeconds == 0 {
		c.WireGuard.RoamFallbackSeconds = 120
	}
	if c.WireGuard.RoamFallbackSeconds < 0 {
		return fmt.Errorf("wireguard.roam_fallback_seconds must be >= 0")
	}
	if err := normalizeTrafficShaper("traffic_shaper", &c.TrafficShaper); err != nil {
		return err
	}
	for i := range c.WireGuard.Peers {
		if err := normalizeTrafficShaper(fmt.Sprintf("wireguard.peers[%d].traffic_shaper", i), &c.WireGuard.Peers[i].TrafficShaper); err != nil {
			return err
		}
	}
	if c.Proxy.FallbackDirect == nil {
		t := true
		c.Proxy.FallbackDirect = &t
	}
	for _, addr := range c.WireGuard.ListenAddresses {
		if _, err := netip.ParseAddr(addr); err != nil {
			return fmt.Errorf("wireguard.listen_addresses %q: %w", addr, err)
		}
	}
	if c.Proxy.UDPAssociate == nil {
		t := true
		c.Proxy.UDPAssociate = &t
	}
	if c.Proxy.UDPAssociatePorts != "" {
		if _, _, err := ParsePortRange(c.Proxy.UDPAssociatePorts); err != nil {
			return fmt.Errorf("proxy.udp_associate_ports %q: %w", c.Proxy.UDPAssociatePorts, err)
		}
	}
	if c.Proxy.HTTPSProxying == nil {
		t := true
		c.Proxy.HTTPSProxying = &t
	}
	if c.Proxy.HTTPSProxyVerify == "" {
		if c.Proxy.HTTPSProxyCAFile != "" {
			c.Proxy.HTTPSProxyVerify = "both"
		} else {
			c.Proxy.HTTPSProxyVerify = "pki"
		}
	}
	switch c.Proxy.HTTPSProxyVerify {
	case "none", "pki":
	case "ca", "both":
		if c.Proxy.HTTPSProxyCAFile == "" {
			return fmt.Errorf("proxy.https_proxy_ca_file is required when proxy.https_proxy_verify is %q", c.Proxy.HTTPSProxyVerify)
		}
	default:
		return fmt.Errorf("invalid proxy.https_proxy_verify %q", c.Proxy.HTTPSProxyVerify)
	}
	if c.Proxy.HTTPSProxyCAFile != "" {
		if _, err := os.Stat(c.Proxy.HTTPSProxyCAFile); err != nil {
			return fmt.Errorf("proxy.https_proxy_ca_file %q: %w", c.Proxy.HTTPSProxyCAFile, err)
		}
	}
	if c.Proxy.Bind == nil {
		f := false
		c.Proxy.Bind = &f
	}
	if c.Proxy.LowBind == nil {
		f := false
		c.Proxy.LowBind = &f
	}
	if c.Proxy.PreferIPv6ForUDPOverSOCKS == nil {
		f := false
		c.Proxy.PreferIPv6ForUDPOverSOCKS = &f
	}
	if c.Proxy.HonorEnvironment == nil {
		t := true
		c.Proxy.HonorEnvironment = &t
	}
	c.addCompatibilityOutboundProxies()
	if *c.Proxy.HonorEnvironment {
		c.addEnvironmentOutboundProxies()
	}
	if err := normalizeOutboundProxies(c.Proxy.OutboundProxies); err != nil {
		return err
	}
	if strings.Contains(c.Proxy.Username, ":") {
		return fmt.Errorf("proxy.username must not contain ':'")
	}
	if len(c.Proxy.Username) > 255 {
		return fmt.Errorf("proxy.username must be at most 255 bytes for SOCKS5 username/password auth")
	}
	if len(c.Proxy.Password) > 255 {
		return fmt.Errorf("proxy.password must be at most 255 bytes for SOCKS5 username/password auth")
	}
	if c.HostForward.Proxy.Enabled == nil {
		t := true
		c.HostForward.Proxy.Enabled = &t
	}
	if c.HostForward.Inbound.Enabled == nil {
		f := false
		c.HostForward.Inbound.Enabled = &f
	}
	for name, ep := range map[string]HostForwardEndpoint{
		"host_forward.proxy":   c.HostForward.Proxy,
		"host_forward.inbound": c.HostForward.Inbound,
	} {
		if ep.RedirectIP != "" && ep.RedirectTUN {
			return fmt.Errorf("%s cannot set both redirect_ip and redirect_tun", name)
		}
		if ep.RedirectIP != "" {
			if _, err := netip.ParseAddr(ep.RedirectIP); err != nil {
				return fmt.Errorf("%s.redirect_ip %q: %w", name, ep.RedirectIP, err)
			}
		}
	}
	if c.TUN.Name == "" {
		c.TUN.Name = "uwgsocks0"
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = c.WireGuard.MTU
	}
	if c.TUN.MTU < 0 {
		return fmt.Errorf("tun.mtu must be >= 0")
	}
	if c.TUN.RouteAllowedIPs == nil {
		t := true
		c.TUN.RouteAllowedIPs = &t
	}
	for _, route := range c.TUN.Routes {
		if _, err := netip.ParsePrefix(route); err != nil {
			return fmt.Errorf("tun.routes %q: %w", route, err)
		}
	}
	for _, server := range c.TUN.DNSServers {
		if _, err := netip.ParseAddr(server); err != nil {
			return fmt.Errorf("tun.dns_servers %q: %w", server, err)
		}
	}
	if c.TUN.DNSResolvConf != "" && !filepath.IsAbs(c.TUN.DNSResolvConf) {
		return fmt.Errorf("tun.dns_resolv_conf must be an absolute path")
	}
	for _, server := range c.TUN.FallbackSystemDNS {
		if _, err := netip.ParseAddr(server); err != nil {
			return fmt.Errorf("tun.fallback_system_dns %q: %w", server, err)
		}
	}
	if c.Inbound.HostDialBindAddress != "" {
		if _, err := netip.ParseAddr(c.Inbound.HostDialBindAddress); err != nil {
			return fmt.Errorf("inbound.host_dial_bind_address %q: %w", c.Inbound.HostDialBindAddress, err)
		}
	}
	if c.Routing.EnforceAddressSubnets == nil {
		t := true
		c.Routing.EnforceAddressSubnets = &t
	}
	if c.Filtering.DropIPv6LinkLocalMulticast == nil {
		t := true
		c.Filtering.DropIPv6LinkLocalMulticast = &t
	}
	if c.Filtering.DropIPv4Invalid == nil {
		t := true
		c.Filtering.DropIPv4Invalid = &t
	}
	if c.Inbound.Transparent == nil {
		f := false
		c.Inbound.Transparent = &f
	}
	if c.Inbound.ConsistentPort == "" {
		c.Inbound.ConsistentPort = "loose"
	}
	switch c.Inbound.ConsistentPort {
	case "strict", "loose", "disabled":
	default:
		return fmt.Errorf("invalid inbound.consistent_port %q", c.Inbound.ConsistentPort)
	}
	if c.Inbound.DisableLowPorts == nil {
		t := true
		c.Inbound.DisableLowPorts = &t
	}
	if c.Inbound.ForwardICMPErrors == nil {
		t := true
		c.Inbound.ForwardICMPErrors = &t
	}
	if c.Inbound.TCPMSSClamp == nil {
		t := true
		c.Inbound.TCPMSSClamp = &t
	}
	if c.Inbound.ReplyICMP == nil {
		t := true
		c.Inbound.ReplyICMP = &t
	}
	if c.Inbound.ICMPRateLimitPerSec == 0 {
		c.Inbound.ICMPRateLimitPerSec = 10
	}
	if c.Inbound.ConnectionTableGraceSeconds == 0 {
		c.Inbound.ConnectionTableGraceSeconds = 30
	}
	if c.Inbound.ConnectionTableGraceSeconds < 0 {
		return fmt.Errorf("inbound.connection_table_grace_seconds must be >= 0")
	}
	if c.Inbound.MaxConnectionsPerPeer < 0 {
		return fmt.Errorf("inbound.max_connections_per_peer must be >= 0")
	}
	if c.Inbound.TCPReceiveWindowBytes == 0 {
		c.Inbound.TCPReceiveWindowBytes = 1 << 20
	}
	if c.Inbound.TCPReceiveWindowBytes < 0 {
		return fmt.Errorf("inbound.tcp_receive_window_bytes must be >= 0")
	}
	if c.Inbound.TCPMaxBufferedBytes == 0 {
		c.Inbound.TCPMaxBufferedBytes = 256 << 20
	}
	if c.Inbound.TCPMaxBufferedBytes < 0 {
		return fmt.Errorf("inbound.tcp_max_buffered_bytes must be >= 0")
	}
	if c.Inbound.TCPIdleTimeoutSeconds == 0 {
		c.Inbound.TCPIdleTimeoutSeconds = 15 * 60
	}
	if c.Inbound.TCPIdleTimeoutSeconds < 0 {
		return fmt.Errorf("inbound.tcp_idle_timeout_seconds must be >= 0")
	}
	if c.Inbound.UDPIdleTimeoutSeconds == 0 {
		c.Inbound.UDPIdleTimeoutSeconds = 30
	}
	if c.Inbound.UDPIdleTimeoutSeconds < 0 {
		return fmt.Errorf("inbound.udp_idle_timeout_seconds must be >= 0")
	}
	if c.DNSServer.MaxInflight == 0 {
		c.DNSServer.MaxInflight = 1024
	}
	if c.DNSServer.MaxInflight < 0 {
		return fmt.Errorf("dns_server.max_inflight must be >= 0")
	}
	if c.Metrics.MaxPerPeer <= 0 {
		c.Metrics.MaxPerPeer = 1024
	}
	if c.MeshControl.ChallengeRotateSeconds == 0 {
		c.MeshControl.ChallengeRotateSeconds = 120
	}
	if c.MeshControl.ChallengeRotateSeconds < 0 {
		return fmt.Errorf("mesh_control.challenge_rotate_seconds must be >= 0")
	}
	if c.MeshControl.ActivePeerWindowSeconds == 0 {
		c.MeshControl.ActivePeerWindowSeconds = 120
	}
	if c.MeshControl.ActivePeerWindowSeconds < 0 {
		return fmt.Errorf("mesh_control.active_peer_window_seconds must be >= 0")
	}
	if c.MeshControl.NotifyWindowSeconds == 0 {
		c.MeshControl.NotifyWindowSeconds = 120
	}
	if c.MeshControl.NotifyWindowSeconds < 0 {
		return fmt.Errorf("mesh_control.notify_window_seconds must be >= 0")
	}
	if c.MeshControl.NotifyMinIntervalSeconds == 0 {
		c.MeshControl.NotifyMinIntervalSeconds = 60
	}
	if c.MeshControl.NotifyMinIntervalSeconds < 0 {
		return fmt.Errorf("mesh_control.notify_min_interval_seconds must be >= 0")
	}
	if c.MeshControl.SubscribeMaxLifetimeSeconds == 0 {
		c.MeshControl.SubscribeMaxLifetimeSeconds = 300
	}
	if c.MeshControl.SubscribeMaxLifetimeSeconds < 0 {
		return fmt.Errorf("mesh_control.subscribe_max_lifetime_seconds must be >= 0")
	}
	for i := range c.WireGuard.Peers {
		switch c.WireGuard.Peers[i].MeshTrust {
		case "":
			c.WireGuard.Peers[i].MeshTrust = MeshTrustUntrusted
		case MeshTrustUntrusted, MeshTrustTrustedAlways, MeshTrustTrustedIfDynamicACLs:
		default:
			return fmt.Errorf("wireguard.peers[%d].mesh_trust must be one of %q, %q or %q", i, MeshTrustUntrusted, MeshTrustTrustedAlways, MeshTrustTrustedIfDynamicACLs)
		}
		if c.WireGuard.Peers[i].ControlURL != "" {
			u, err := url.Parse(c.WireGuard.Peers[i].ControlURL)
			if err != nil {
				return fmt.Errorf("wireguard.peers[%d].control_url: %w", i, err)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return fmt.Errorf("wireguard.peers[%d].control_url must use http or https", i)
			}
			if u.Host == "" {
				return fmt.Errorf("wireguard.peers[%d].control_url host is required", i)
			}
		}
		if c.WireGuard.Peers[i].ControlURL != "" && c.WireGuard.Peers[i].MeshEnabled && !c.WireGuard.Peers[i].MeshDisableACLs {
			c.WireGuard.Peers[i].MeshAcceptACLs = true
		}
		if c.WireGuard.Peers[i].MeshDisableACLs {
			c.WireGuard.Peers[i].MeshAcceptACLs = false
		}
	}
	if c.Relay.Enabled == nil {
		f := false
		c.Relay.Enabled = &f
	}
	if c.Relay.Conntrack == nil {
		t := true
		c.Relay.Conntrack = &t
	}
	if c.Relay.ConntrackMaxFlows == 0 {
		c.Relay.ConntrackMaxFlows = 65536
	}
	if c.Relay.ConntrackMaxFlows < 0 {
		return fmt.Errorf("relay.conntrack_max_flows must be >= 0")
	}
	if c.Relay.ConntrackMaxPerPeer == 0 {
		c.Relay.ConntrackMaxPerPeer = 4096
	}
	if c.Relay.ConntrackMaxPerPeer < 0 {
		return fmt.Errorf("relay.conntrack_max_per_peer must be >= 0")
	}
	in := acl.List{Default: c.ACL.InboundDefault, Rules: c.ACL.Inbound}
	if err := in.Normalize(); err != nil {
		return fmt.Errorf("inbound ACL: %w", err)
	}
	out := acl.List{Default: c.ACL.OutboundDefault, Rules: c.ACL.Outbound}
	if err := out.Normalize(); err != nil {
		return fmt.Errorf("outbound ACL: %w", err)
	}
	rel := acl.List{Default: c.ACL.RelayDefault, Rules: c.ACL.Relay}
	if err := rel.Normalize(); err != nil {
		return fmt.Errorf("relay ACL: %w", err)
	}
	c.ACL.InboundDefault, c.ACL.Inbound = in.Default, in.Rules
	c.ACL.OutboundDefault, c.ACL.Outbound = out.Default, out.Rules
	c.ACL.RelayDefault, c.ACL.Relay = rel.Default, rel.Rules
	if err := normalizeForwards("forward", c.Forwards); err != nil {
		return err
	}
	if err := normalizeForwards("reverse_forward", c.ReverseForwards); err != nil {
		return err
	}
	if err := c.synthesizeDirectiveTransports(); err != nil {
		return err
	}
	if err := c.normalizeTransports(); err != nil {
		return err
	}
	return validateBuildConfig(c)
}

// synthesizeDirectiveTransports converts #! directive fields on WireGuard and
// Peer into proper transport.Config entries appended to c.Transports, and
// updates peer.Transport references accordingly.
func (c *Config) synthesizeDirectiveTransports() error {
	// TURN directives → one transport.Config per entry (TURN base transport).
	for i, rawURL := range c.WireGuard.TURNDirectives {
		tc, err := parseTURNDirectiveURL(fmt.Sprintf("_wg-turn-%d", i), rawURL)
		if err != nil {
			return fmt.Errorf("#!TURN directive %d: %w", i, err)
		}
		c.Transports = append(c.Transports, tc)
	}

	// #!TCP in [Interface] → TCP listener transport.
	if c.WireGuard.TCPListen {
		c.Transports = append(c.Transports, transport.Config{
			Name:   "_wg-tcp-listen",
			Base:   "tcp",
			Listen: true,
		})
	}

	// Per-peer directives.
	for i := range c.WireGuard.Peers {
		peer := &c.WireGuard.Peers[i]
		if parsed, ok, err := parsePeerEndpointTransport(fmt.Sprintf("_wg-endpoint-%d", i), peer.Endpoint); err != nil {
			return fmt.Errorf("wireguard.peers[%d].endpoint: %w", i, err)
		} else if ok {
			if peer.Transport != "" {
				return fmt.Errorf("wireguard.peers[%d].endpoint transport scheme cannot be combined with explicit transport", i)
			}
			if peer.ConnectURL != "" {
				return fmt.Errorf("wireguard.peers[%d].endpoint transport scheme cannot be combined with #!URL", i)
			}
			c.Transports = append(c.Transports, parsed.Transport)
			peer.Endpoint = parsed.Endpoint
			peer.Transport = parsed.Transport.Name
			continue
		}
		if peer.Transport != "" {
			continue // explicit transport already set; directives are informational only
		}
		tlsCfg := transport.TLSConfig{}
		if peer.SkipVerifyTLS != nil {
			tlsCfg.VerifyPeer = !*peer.SkipVerifyTLS
		}
		if peer.ConnectURL != "" {
			name := fmt.Sprintf("_wg-url-%d", i)
			c.Transports = append(c.Transports, transport.Config{
				Name: name,
				Base: "url",
				URL:  peer.ConnectURL,
				TLS:  tlsCfg,
			})
			peer.Transport = name
		} else if peer.TCPMode == "required" || peer.TCPMode == "supported" {
			name := fmt.Sprintf("_wg-tcp-%d", i)
			c.Transports = append(c.Transports, transport.Config{
				Name: name,
				Base: "tcp",
				TLS:  tlsCfg,
			})
			peer.Transport = name
		}
	}
	return nil
}

// normalizeTransports validates transport configs and checks per-peer
// transport references.
func (c *Config) normalizeTransports() error {
	for i := range c.Transports {
		c.Transports[i] = transport.NormalizeConfig(c.Transports[i])
		cfg := &c.Transports[i]
		if cfg.Name == "" {
			return fmt.Errorf("transports[%d]: name is required", i)
		}
		if err := transport.ValidateBase(cfg.Base); err != nil {
			return fmt.Errorf("transports[%d] %q: %w", i, cfg.Name, err)
		}
		if err := transport.ValidateProxyType(cfg.Proxy.Type); err != nil {
			return fmt.Errorf("transports[%d] %q: %w", i, cfg.Name, err)
		}
	}
	// Build a name set for peer validation.
	names := make(map[string]bool, len(c.Transports))
	for _, t := range c.Transports {
		names[t.Name] = true
	}
	for i, p := range c.WireGuard.Peers {
		if p.Transport != "" && !names[p.Transport] {
			return fmt.Errorf("wireguard.peers[%d]: transport %q not found in transports", i, p.Transport)
		}
	}
	return nil
}

func normalizeTrafficShaper(name string, cfg *TrafficShaper) error {
	if cfg == nil {
		return nil
	}
	if cfg.UploadBps < 0 {
		return fmt.Errorf("%s.upload_bps must be >= 0", name)
	}
	if cfg.DownloadBps < 0 {
		return fmt.Errorf("%s.download_bps must be >= 0", name)
	}
	if cfg.LatencyMillis < 0 {
		return fmt.Errorf("%s.latency_ms must be >= 0", name)
	}
	if (cfg.UploadBps > 0 || cfg.DownloadBps > 0) && cfg.LatencyMillis == 0 {
		cfg.LatencyMillis = 15
	}
	return nil
}

// ParsePortRange parses "port" or "start-end" into an inclusive port range.
func ParsePortRange(raw string) (int, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, 0, fmt.Errorf("port range is empty")
	}
	startText, endText, hasDash := strings.Cut(raw, "-")
	if !hasDash {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port %q", raw)
		}
		if port < 1 || port > 65535 {
			return 0, 0, fmt.Errorf("port %d must be between 1 and 65535", port)
		}
		return port, port, nil
	}
	start, err := strconv.Atoi(strings.TrimSpace(startText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port %q", startText)
	}
	end, err := strconv.Atoi(strings.TrimSpace(endText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port %q", endText)
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return 0, 0, fmt.Errorf("ports must be between 1 and 65535")
	}
	if start > end {
		return 0, 0, fmt.Errorf("start port %d must be <= end port %d", start, end)
	}
	return start, end, nil
}

func normalizeForwards(name string, forwards []Forward) error {
	for i := range forwards {
		if forwards[i].Proto == "" {
			forwards[i].Proto = "tcp"
		}
		forwards[i].Proto = strings.ToLower(forwards[i].Proto)
		if forwards[i].Proto != "tcp" && forwards[i].Proto != "udp" {
			return fmt.Errorf("%s %d: proto must be tcp or udp", name, i)
		}
		if forwards[i].Listen == "" || forwards[i].Target == "" {
			return fmt.Errorf("%s %d: listen and target are required", name, i)
		}
		forwards[i].ProxyProtocol = strings.ToLower(forwards[i].ProxyProtocol)
		switch forwards[i].ProxyProtocol {
		case "", "v1", "v2":
		default:
			return fmt.Errorf("%s %d: proxy_protocol must be v1, v2, or empty", name, i)
		}
		if forwards[i].Proto == "udp" && forwards[i].ProxyProtocol == "v1" {
			return fmt.Errorf("%s %d: UDP proxy_protocol requires v2", name, i)
		}
		if err := ValidateForwardEndpoints(forwards[i], name == "reverse_forward"); err != nil {
			return fmt.Errorf("%s %d: %w", name, i, err)
		}
	}
	return nil
}

func (c *Config) addCompatibilityOutboundProxies() {
	if c.Proxy.FallbackSOCKS5 != "" {
		c.addOutboundProxyIfMissing(OutboundProxy{
			Type:    "socks5",
			Address: c.Proxy.FallbackSOCKS5,
			Roles:   []string{"socks"},
		})
	}
	if c.Inbound.HostDialProxySOCKS5 != "" {
		c.addOutboundProxyIfMissing(OutboundProxy{
			Type:    "socks5",
			Address: c.Inbound.HostDialProxySOCKS5,
			Roles:   []string{"inbound"},
		})
	}
}

func (c *Config) addEnvironmentOutboundProxies() {
	for _, env := range []string{"ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "all_proxy", "https_proxy", "http_proxy"} {
		raw := strings.TrimSpace(os.Getenv(env))
		if raw == "" {
			continue
		}
		p, err := outboundProxyFromURL(raw)
		if err != nil {
			continue
		}
		if len(p.Roles) == 0 {
			p.Roles = []string{"socks", "inbound"}
		}
		c.addOutboundProxyIfMissing(p)
	}
}

func (c *Config) addOutboundProxyIfMissing(p OutboundProxy) {
	for _, existing := range c.Proxy.OutboundProxies {
		if existing.Type == p.Type && existing.Address == p.Address && strings.Join(existing.Roles, ",") == strings.Join(p.Roles, ",") {
			return
		}
	}
	c.Proxy.OutboundProxies = append(c.Proxy.OutboundProxies, p)
}

func normalizeOutboundProxies(proxies []OutboundProxy) error {
	for i := range proxies {
		if proxies[i].Address == "" {
			return fmt.Errorf("proxy.outbound_proxies %d: address is required", i)
		}
		if strings.Contains(proxies[i].Address, "://") {
			p, err := outboundProxyFromURL(proxies[i].Address)
			if err != nil {
				return fmt.Errorf("proxy.outbound_proxies %d: %w", i, err)
			}
			if proxies[i].Type == "" {
				proxies[i].Type = p.Type
			}
			if proxies[i].Username == "" {
				proxies[i].Username = p.Username
			}
			if proxies[i].Password == "" {
				proxies[i].Password = p.Password
			}
			proxies[i].Address = p.Address
		}
		proxies[i].Type = strings.ToLower(strings.TrimSpace(proxies[i].Type))
		if proxies[i].Type == "" {
			proxies[i].Type = "socks5"
		}
		if proxies[i].Type == "socks" {
			proxies[i].Type = "socks5"
		}
		if proxies[i].Type != "socks5" && proxies[i].Type != "http" {
			return fmt.Errorf("proxy.outbound_proxies %d: type must be socks5 or http", i)
		}
		if _, _, err := net.SplitHostPort(proxies[i].Address); err != nil {
			return fmt.Errorf("proxy.outbound_proxies %d address %q: %w", i, proxies[i].Address, err)
		}
		if len(proxies[i].Roles) == 0 {
			proxies[i].Roles = []string{"socks", "inbound"}
		}
		for j := range proxies[i].Roles {
			proxies[i].Roles[j] = strings.ToLower(strings.TrimSpace(proxies[i].Roles[j]))
			switch proxies[i].Roles[j] {
			case "socks", "proxy", "client", "inbound", "wireguard", "both":
			default:
				return fmt.Errorf("proxy.outbound_proxies %d: unknown role %q", i, proxies[i].Roles[j])
			}
		}
		for _, subnet := range proxies[i].Subnets {
			if _, err := netip.ParsePrefix(subnet); err != nil {
				return fmt.Errorf("proxy.outbound_proxies %d subnet %q: %w", i, subnet, err)
			}
		}
	}
	return nil
}

func outboundProxyFromURL(raw string) (OutboundProxy, error) {
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return OutboundProxy{}, err
	}
	typ := strings.ToLower(u.Scheme)
	if typ == "socks" {
		typ = "socks5"
	}
	if typ != "socks5" && typ != "http" && typ != "https" {
		return OutboundProxy{}, fmt.Errorf("unsupported proxy URL scheme %q", u.Scheme)
	}
	if typ == "https" {
		typ = "http"
	}
	if u.Host == "" {
		return OutboundProxy{}, fmt.Errorf("proxy URL missing host")
	}
	p := OutboundProxy{Type: typ, Address: u.Host}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

func MergeWGQuickFile(dst *WireGuard, path string) error {
	return mergeWGQuickFile(dst, path, false)
}

// MergeWGQuickFileStrict is the hostile-input variant of MergeWGQuickFile, see
// MergeWGQuickStrict for the semantics.
func MergeWGQuickFileStrict(dst *WireGuard, path string) error {
	return mergeWGQuickFile(dst, path, true)
}

func mergeWGQuickFile(dst *WireGuard, path string, strict bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return mergeWGQuick(dst, string(b), strict)
}

// MergeWGQuick parses the ini-like wg-quick format into WireGuard. It merges
// into dst instead of replacing it so YAML and CLI layers can intentionally add
// peers or override individual fields.
//
// Use MergeWGQuickStrict to parse INI text supplied from an untrusted source
// (for example, the runtime API or a user-supplied URL): strict mode rejects
// PreUp/PostUp/PreDown/PostDown so a hostile config cannot stage shell hooks
// even if scripts.allow is later flipped on, satisfying the threat model.
func MergeWGQuick(dst *WireGuard, text string) error {
	return mergeWGQuick(dst, text, false)
}

// MergeWGQuickStrict is the hostile-input variant of MergeWGQuick. It is the
// parser to use whenever the wg-quick INI text was supplied by something
// outside the operator's TCB (the runtime API, a downloaded file, etc.).
// Other wg-quick fields and #! directives remain accepted because they only
// describe how to talk to a peer or where to find dynamic mesh information,
// which is by design under the peer's control.
func MergeWGQuickStrict(dst *WireGuard, text string) error {
	return mergeWGQuick(dst, text, true)
}

func mergeWGQuick(dst *WireGuard, text string, strict bool) error {
	sc := bufio.NewScanner(strings.NewReader(text))
	section := ""
	var peer *Peer
	lineNo := 0
	for sc.Scan() {
		lineNo++
		rawLine := strings.TrimSpace(sc.Text())
		// #! directives are parsed before comment stripping so standard
		// wg-quick clients see them as ordinary comments and ignore them.
		if strings.HasPrefix(rawLine, "#!") {
			if err := applyWGDirective(dst, peer, section, rawLine[2:], lineNo); err != nil {
				return err
			}
			continue
		}
		line := strings.TrimSpace(stripComment(rawLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				dst.Peers = append(dst.Peers, Peer{})
				peer = &dst.Peers[len(dst.Peers)-1]
			} else {
				peer = nil
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("wg config line %d: expected key=value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch section {
		case "interface":
			if strict {
				// Strict-mode INI comes from a source we don't fully trust
				// (the runtime API or a downloaded .conf). The hook keys are
				// silently *dropped*, not rejected — wg-quick configs in the
				// wild routinely carry routing-table PostUp/PostDown lines
				// that are meaningless for this userspace runtime, and we
				// shouldn't refuse the whole config just because the operator
				// pasted one in. Execution is still gated by scripts.allow
				// at the engine layer (engine.go), so dropping at parse time
				// is sufficient defense-in-depth for the strict path.
				switch key {
				case "preup", "postup", "predown", "postdown":
					continue
				}
			}
			if err := setInterface(dst, key, value); err != nil {
				return fmt.Errorf("wg config line %d: %w", lineNo, err)
			}
		case "peer":
			if peer == nil {
				return fmt.Errorf("wg config line %d: peer option before [Peer]", lineNo)
			}
			if err := setPeer(peer, key, value); err != nil {
				return fmt.Errorf("wg config line %d: %w", lineNo, err)
			}
		default:
			return fmt.Errorf("wg config line %d: option outside [Interface] or [Peer]", lineNo)
		}
	}
	return sc.Err()
}

// applyWGDirective processes a single #! directive line (the #! prefix is
// already stripped). Per-peer directives are applied to the current peer
// pointer; global directives update the WireGuard-level fields.
func applyWGDirective(dst *WireGuard, peer *Peer, section, directive string, lineNo int) error {
	key, value, hasValue := strings.Cut(directive, "=")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)

	switch strings.ToUpper(key) {
	case "TURN":
		if !hasValue || value == "" {
			return fmt.Errorf("wg config line %d: #!TURN requires a URL value", lineNo)
		}
		dst.TURNDirectives = append(dst.TURNDirectives, value)

	case "TCP":
		if !hasValue {
			// #!TCP with no value in [Interface] enables TCP listener.
			if section == "interface" || section == "" {
				dst.TCPListen = true
			}
			return nil
		}
		if peer == nil {
			// Global #!TCP=... in [Interface]: treat as listener flag.
			switch strings.ToLower(value) {
			case "supported", "required":
				dst.TCPListen = true
			}
			return nil
		}
		switch strings.ToLower(value) {
		case "no", "":
			peer.TCPMode = "no"
		case "supported":
			peer.TCPMode = "supported"
		case "required":
			peer.TCPMode = "required"
		default:
			return fmt.Errorf("wg config line %d: #!TCP value must be no|supported|required, got %q", lineNo, value)
		}

	case "SKIPVERIFYTLS":
		if peer == nil {
			return fmt.Errorf("wg config line %d: #!SkipVerifyTLS is only valid in [Peer]", lineNo)
		}
		switch strings.ToLower(value) {
		case "yes", "true", "1":
			t := true
			peer.SkipVerifyTLS = &t
		case "no", "false", "0":
			f := false
			peer.SkipVerifyTLS = &f
		default:
			return fmt.Errorf("wg config line %d: #!SkipVerifyTLS value must be yes|no, got %q", lineNo, value)
		}

	case "URL":
		if peer == nil {
			return fmt.Errorf("wg config line %d: #!URL is only valid in [Peer]", lineNo)
		}
		if !hasValue || value == "" {
			return fmt.Errorf("wg config line %d: #!URL requires a URL value", lineNo)
		}
		peer.ConnectURL = value

	case "CONTROL":
		if peer == nil {
			return fmt.Errorf("wg config line %d: #!Control is only valid in [Peer]", lineNo)
		}
		if !hasValue || value == "" {
			return fmt.Errorf("wg config line %d: #!Control requires a URL value", lineNo)
		}
		peer.ControlURL = value
		peer.MeshEnabled = true
	}
	return nil
}

func stripComment(s string) string {
	for i, r := range s {
		if r == '#' {
			return s[:i]
		}
	}
	return s
}

func setInterface(wg *WireGuard, key, value string) error {
	switch key {
	case "privatekey":
		wg.PrivateKey = value
	case "listenport":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("invalid ListenPort %q", value)
		}
		wg.ListenPort = &n
	case "address", "addresses":
		wg.Addresses = append(wg.Addresses, splitList(value)...)
	case "dns":
		wg.DNS = append(wg.DNS, splitList(value)...)
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid MTU %q", value)
		}
		wg.MTU = n
	case "preup":
		wg.PreUp = append(wg.PreUp, value)
	case "postup":
		wg.PostUp = append(wg.PostUp, value)
	case "predown":
		wg.PreDown = append(wg.PreDown, value)
	case "postdown":
		wg.PostDown = append(wg.PostDown, value)
	case "table", "saveconfig":
		// wg-quick settings that do not map to this userspace runtime.
	default:
		return fmt.Errorf("unsupported interface key %q", key)
	}
	return nil
}

func setPeer(peer *Peer, key, value string) error {
	switch key {
	case "publickey":
		peer.PublicKey = value
	case "presharedkey":
		peer.PresharedKey = value
	case "endpoint":
		peer.Endpoint = value
	case "allowedips":
		peer.AllowedIPs = append(peer.AllowedIPs, splitList(value)...)
	case "persistentkeepalive":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid PersistentKeepalive %q", value)
		}
		peer.PersistentKeepalive = n
	case "transport":
		peer.Transport = value
	default:
		return fmt.Errorf("unsupported peer key %q", key)
	}
	return nil
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func ParsePeerArg(s string) (Peer, error) {
	var p Peer
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return Peer{}, fmt.Errorf("peer fields must be key=value")
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "public", "publickey", "public_key":
			p.PublicKey = v
		case "preshared", "presharedkey", "preshared_key":
			p.PresharedKey = v
		case "endpoint":
			p.Endpoint = v
		case "allowed", "allowedips", "allowed_ips":
			p.AllowedIPs = splitList(v)
		case "keepalive", "persistentkeepalive", "persistent_keepalive":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return Peer{}, fmt.Errorf("invalid keepalive %q", v)
			}
			p.PersistentKeepalive = n
		case "uploadbps", "upload_bps":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return Peer{}, fmt.Errorf("invalid upload_bps %q", v)
			}
			p.TrafficShaper.UploadBps = n
		case "downloadbps", "download_bps":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return Peer{}, fmt.Errorf("invalid download_bps %q", v)
			}
			p.TrafficShaper.DownloadBps = n
		case "latencyms", "latency_ms", "traffic_latency_ms":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return Peer{}, fmt.Errorf("invalid latency_ms %q", v)
			}
			p.TrafficShaper.LatencyMillis = n
		default:
			return Peer{}, fmt.Errorf("unknown peer field %q", k)
		}
	}
	return p, nil
}

func ParseForwardArg(s string) (Forward, error) {
	var f Forward
	left, target, ok := strings.Cut(s, "=")
	if !ok {
		return f, fmt.Errorf("forward must be proto://listen=target or listen=target")
	}
	if proto, rest, ok := strings.Cut(left, "://"); ok {
		f.Proto = strings.ToLower(proto)
		f.Listen = rest
	} else {
		f.Proto = "tcp"
		f.Listen = left
	}
	if base, opts, ok := strings.Cut(target, ","); ok {
		target = base
		for _, opt := range strings.Split(opts, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(opt), "=")
			if !ok {
				return f, fmt.Errorf("invalid forward option %q", opt)
			}
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "proxy_protocol":
				f.ProxyProtocol = strings.ToLower(strings.TrimSpace(value))
			case "allow_unnamed_dgram":
				b, err := strconv.ParseBool(strings.TrimSpace(value))
				if err != nil {
					return f, fmt.Errorf("invalid allow_unnamed_dgram %q", value)
				}
				f.AllowUnnamedDGRAM = b
			case "frame_bytes":
				n, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil {
					return f, fmt.Errorf("invalid frame_bytes %q", value)
				}
				f.FrameBytes = n
			default:
				return f, fmt.Errorf("unknown forward option %q", key)
			}
		}
	}
	f.Target = target
	if f.Proto != "tcp" && f.Proto != "udp" {
		return f, fmt.Errorf("forward proto must be tcp or udp")
	}
	if f.ProxyProtocol != "" && f.ProxyProtocol != "v1" && f.ProxyProtocol != "v2" {
		return f, fmt.Errorf("forward proxy_protocol must be v1 or v2")
	}
	if f.Proto == "udp" && f.ProxyProtocol == "v1" {
		return f, fmt.Errorf("UDP forward proxy_protocol requires v2")
	}
	if err := ValidateForwardEndpoints(f, false); err != nil {
		return f, err
	}
	return f, nil
}

func ParseOutboundProxyArg(s string) (OutboundProxy, error) {
	var p OutboundProxy
	main := s
	var opts string
	if left, right, ok := strings.Cut(s, ";"); ok {
		main = left
		opts = right
	}
	if strings.Contains(main, "://") {
		parsed, err := outboundProxyFromURL(main)
		if err != nil {
			return OutboundProxy{}, err
		}
		p = parsed
	} else {
		p.Type = "socks5"
		p.Address = main
	}
	for opts != "" {
		var part string
		part, opts, _ = strings.Cut(opts, ";")
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return OutboundProxy{}, fmt.Errorf("invalid outbound proxy option %q", part)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "role", "roles", "for":
			p.Roles = splitList(v)
		case "subnet", "subnets":
			p.Subnets = splitList(v)
		case "type":
			p.Type = v
		case "username":
			p.Username = v
		case "password":
			p.Password = v
		default:
			return OutboundProxy{}, fmt.Errorf("unknown outbound proxy option %q", k)
		}
	}
	cfg := Default()
	cfg.Proxy.OutboundProxies = []OutboundProxy{p}
	if err := normalizeOutboundProxies(cfg.Proxy.OutboundProxies); err != nil {
		return OutboundProxy{}, err
	}
	return cfg.Proxy.OutboundProxies[0], nil
}

func AddressAddrs(addresses []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range addresses {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Addr())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", s, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func AddressPrefixes(addresses []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range addresses {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", s, err)
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out, nil
}

func DNSAddrs(dns []string) ([]netip.Addr, []string) {
	var addrs []netip.Addr
	var ignored []string
	for _, s := range dns {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			ignored = append(ignored, s)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, ignored
}

func PeerAllowedPrefixes(peers []Peer) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, p := range peers {
		for _, s := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				if addr, err2 := netip.ParseAddr(s); err2 == nil {
					bits := 128
					if addr.Is4() {
						bits = 32
					}
					prefix = netip.PrefixFrom(addr, bits)
				} else {
					return nil, fmt.Errorf("peer %d allowed_ip %q: %w", i, s, err)
				}
			}
			out = append(out, prefix.Masked())
		}
	}
	return out, nil
}
