// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import "strings"

// Config describes one pluggable transport entry from the YAML config.
type Config struct {
	// Name is a unique identifier referenced by peers.
	Name string `yaml:"name" json:"name"`
	// Base is the framing protocol: udp | turn | tcp | tls | dtls | http |
	// https | quic | quic-ws | url
	Base string `yaml:"base" json:"base"`
	// Listen enables server-mode: the transport binds a fixed port and
	// accepts incoming WireGuard connections.
	Listen bool `yaml:"listen" json:"listen"`
	// ListenPort overrides the wireguard.listen_port for this transport.
	// Zero means inherit from wireguard.listen_port.
	ListenPort *int `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	// ListenAddresses restricts the listen socket to specific IPs.
	// Empty means all interfaces.
	ListenAddresses []string `yaml:"listen_addresses,omitempty" json:"listen_addresses,omitempty"`

	// TLS holds TLS / DTLS / HTTPS / QUIC certificate and validation options.
	TLS TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
	// TURN configures TURN as the base transport. This replaces the older
	// legacy form "base: udp" + "proxy.type: turn", which is still accepted
	// and normalized into this field for backward compatibility.
	TURN TURNConfig `yaml:"turn,omitempty" json:"turn,omitempty"`
	// URL is the full base URL for the "url" auto-negotiation transport,
	// e.g. "https://example.com/wg". Only used when Base = "url".
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// WebSocket configures HTTP path / Host header details for HTTP-based transports.
	WebSocket WebSocketConfig `yaml:"websocket,omitempty" json:"websocket,omitempty"`

	// Proxy configures an optional proxy layer beneath the base transport.
	Proxy ProxyConfig `yaml:"proxy,omitempty" json:"proxy,omitempty"`

	// IPv6Translate maps IPv4 addresses to IPv6 using NAT64/DNS64 prefix.
	IPv6Translate bool `yaml:"ipv6_translate,omitempty" json:"ipv6_translate,omitempty"`
	// IPv6Prefix is the NAT64 /96 prefix. Defaults to "64:ff9b::/96".
	IPv6Prefix string `yaml:"ipv6_prefix,omitempty" json:"ipv6_prefix,omitempty"`
}

// TLSConfig holds certificate and validation settings for all TLS-based
// transports and proxies.
type TLSConfig struct {
	// CertFile path to PEM certificate. Empty → auto-generate self-signed.
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	// KeyFile path to PEM private key. Required when CertFile is set.
	KeyFile string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	// VerifyPeer enables remote certificate verification. Default false
	// because WireGuard already provides mutual authentication.
	VerifyPeer bool `yaml:"verify_peer,omitempty" json:"verify_peer,omitempty"`
	// ReloadInterval is how often the cert file is checked for renewal,
	// e.g. "60s". Empty or zero means no hot-reload.
	ReloadInterval string `yaml:"reload_interval,omitempty" json:"reload_interval,omitempty"`
	// CAFile path to PEM CA bundle used to validate the peer certificate.
	// For clients, empty means use the system roots. For servers that require
	// client certificates, a CAFile is mandatory.
	CAFile string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	// ServerSNI controls the client-side TLS Server Name Indication.
	// Unset means infer from the target hostname.
	// Explicit null means send no SNI at all.
	// A string value forces that SNI.
	ServerSNI OptionalString `yaml:"server_sni,omitempty" json:"server_sni,omitempty"`

	verifyPeerSet bool
}

type WebSocketConfig struct {
	// Path is the HTTP path used for the WebSocket upgrade. Defaults to "/".
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// UpgradeMode selects the HTTP upgrade protocol used by client-mode
	// HTTP/HTTPS transports:
	//   "" | "websocket" → RFC 6455 WebSocket upgrade (default)
	//   "proxyguard"     → ProxyGuard UoTLV/1 native HTTP upgrade
	//
	// Listen mode always accepts both WebSocket and UoTLV/1 on the same path.
	UpgradeMode string `yaml:"upgrade_mode,omitempty" json:"upgrade_mode,omitempty"`
	// ConnectHost overrides the host used for DNS lookup and TCP/QUIC
	// connection. When empty the peer endpoint host is used. This is the
	// first of three independently configurable host values for domain
	// fronting:
	//   ConnectHost  → DNS + actual TCP/QUIC connect
	//   TLS.ServerSNI → TLS ClientHello SNI
	//   HostHeader   → HTTP Host / :authority header (inner, often encrypted)
	ConnectHost string `yaml:"connect_host,omitempty" json:"connect_host,omitempty"`
	// HostHeader overrides the HTTP Host / :authority header sent in the
	// upgrade request. Used for domain fronting where the HTTP layer is
	// encrypted and the CDN routes on the inner host. Empty means use the
	// target host.
	HostHeader string `yaml:"host_header,omitempty" json:"host_header,omitempty"`
	// SNIHostname is deprecated. Use tls.server_sni instead.
	SNIHostname string `yaml:"sni_hostname,omitempty" json:"sni_hostname,omitempty"`
}

// ProxyConfig selects an optional proxy layer and its settings.
type ProxyConfig struct {
	// Type is: none | socks5 | http | https. "turn" is still accepted as a legacy
	// compatibility alias and is normalized into base: turn.
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	TURN   TURNConfig        `yaml:"turn,omitempty" json:"turn,omitempty"`
	SOCKS5 SOCKS5ProxyConfig `yaml:"socks5,omitempty" json:"socks5,omitempty"`
	HTTP   HTTPProxyConfig   `yaml:"http,omitempty" json:"http,omitempty"`
}

// TURNConfig configures a TURN relay as the transport base.
type TURNConfig struct {
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Realm    string `yaml:"realm,omitempty" json:"realm,omitempty"`
	// Protocol is how to reach the TURN server: udp | tcp | tls | dtls
	// Note: TURN does not need encryption for security, its only to bypass firewalls or hide the VPN as web traffic
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	// NoCreatePermission skips CreatePermission calls (open relays).
	NoCreatePermission bool `yaml:"no_create_permission,omitempty" json:"no_create_permission,omitempty"`
	// IncludeWGPublicKey appends the encrypted WireGuard public key to the
	// TURN username so the relay can associate allocations. The Wireguard public key is encrypted with the TURN password
	IncludeWGPublicKey bool `yaml:"include_wg_public_key,omitempty" json:"include_wg_public_key,omitempty"`
	// TLS configures TURN over TLS / DTLS. For TURN this is primarily useful
	// for obfuscation and optional client/server certificate filtering.
	TLS TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
	// Permissions is a list of IP/CIDR allowed to send relay traffic.
	Permissions []string `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// TURNProxyConfig is kept as a compatibility alias for older code paths.
type TURNProxyConfig = TURNConfig

// NormalizeConfig rewrites legacy transport encodings into the current
// canonical shape without changing behavior.
func NormalizeConfig(cfg Config) Config {
	if (cfg.Base == "" || cfg.Base == "udp") && strings.EqualFold(cfg.Proxy.Type, "turn") {
		cfg.Base = "turn"
		if cfg.TURN.Server == "" {
			cfg.TURN = cfg.Proxy.TURN
		}
		cfg.Proxy.Type = ""
		cfg.Proxy.TURN = TURNConfig{}
	}
	if cfg.Base == "turn" && cfg.TURN.Server == "" && cfg.Proxy.TURN.Server != "" {
		cfg.TURN = cfg.Proxy.TURN
	}
	return cfg
}

// SOCKS5ProxyConfig configures a SOCKS5 proxy.
type SOCKS5ProxyConfig struct {
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

// HTTPProxyConfig configures an HTTP CONNECT proxy.
type HTTPProxyConfig struct {
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// TLS configures HTTPS proxy transport.
	// When verify_peer is omitted, HTTPS proxies default to:
	// false for anonymous proxies, true when credentials are configured.
	TLS TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// IsConnectionOriented reports whether a transport config describes a
// connection-oriented transport (TCP/TLS/DTLS/HTTP/HTTPS, or anything
// carried over a stream proxy such as SOCKS5 or HTTP CONNECT).
func IsConnectionOriented(cfg Config) bool {
	cfg = NormalizeConfig(cfg)
	switch cfg.Base {
	case "tcp", "tls", "dtls", "http", "https", "quic", "quic-ws", "url":
		return true
	}
	// UDP base can still be connection-oriented when routed through a stream
	// proxy.
	switch cfg.Proxy.Type {
	case "socks5", "http":
		return true
	}
	return false
}

// ValidateBase checks that the Base field is one of the supported values.
func ValidateBase(base string) error {
	switch base {
	case "", "udp", "turn", "tcp", "tls", "dtls", "http", "https", "quic", "quic-ws", "url":
		return nil
	}
	return &ConfigError{Field: "base", Value: base, Msg: "must be one of: udp turn tcp tls dtls http https quic quic-ws url"}
}

// ValidateProxyType checks that the proxy Type field is valid.
func ValidateProxyType(t string) error {
	switch t {
	case "", "none", "turn", "socks5", "http":
		return nil
	}
	return &ConfigError{Field: "proxy.type", Value: t, Msg: "must be one of: none turn socks5 http"}
}

func ValidateWebSocketUpgradeMode(mode string) error {
	switch mode {
	case "", "websocket", "proxyguard":
		return nil
	}
	return &ConfigError{Field: "websocket.upgrade_mode", Value: mode, Msg: "must be one of: websocket proxyguard"}
}

// ConfigError is returned when a transport configuration field is invalid.
type ConfigError struct {
	Field string
	Value string
	Msg   string
}

func (e *ConfigError) Error() string {
	return "transport config " + e.Field + "=" + e.Value + ": " + e.Msg
}
