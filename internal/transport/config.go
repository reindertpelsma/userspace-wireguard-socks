// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

// Config describes one pluggable transport entry from the YAML config.
type Config struct {
	// Name is a unique identifier referenced by peers.
	Name string `yaml:"name" json:"name"`
	// Base is the framing protocol: udp | tcp | tls | dtls | http | https
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

	// TLS holds TLS/DTLS certificate and validation options.
	TLS TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
	// WebSocket configures HTTP upgrade details for http/https base transports.
	WebSocket WebSocketConfig `yaml:"websocket,omitempty" json:"websocket,omitempty"`

	// Proxy configures an optional proxy layer beneath the base transport.
	Proxy ProxyConfig `yaml:"proxy,omitempty" json:"proxy,omitempty"`

	// IPv6Translate maps IPv4 addresses to IPv6 using NAT64/DNS64 prefix.
	IPv6Translate bool `yaml:"ipv6_translate,omitempty" json:"ipv6_translate,omitempty"`
	// IPv6Prefix is the NAT64 /96 prefix. Defaults to "64:ff9b::/96".
	IPv6Prefix string `yaml:"ipv6_prefix,omitempty" json:"ipv6_prefix,omitempty"`
}

// TLSConfig holds certificate and validation settings for TLS, DTLS, and
// HTTPS transports.
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
}

type WebSocketConfig struct {
	// Path is the HTTP path used for the WebSocket upgrade. Defaults to "/".
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// HostHeader overrides the HTTP Host header sent during the upgrade.
	// Empty means use the target host.
	HostHeader string `yaml:"host_header,omitempty" json:"host_header,omitempty"`
	// SNIHostname overrides the outer TLS SNI name for https transports.
	// Empty means use the dial target host.
	SNIHostname string `yaml:"sni_hostname,omitempty" json:"sni_hostname,omitempty"`
}

// ProxyConfig selects an optional proxy layer and its settings.
type ProxyConfig struct {
	// Type is: none | turn | socks5 | http
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	TURN   TURNProxyConfig   `yaml:"turn,omitempty" json:"turn,omitempty"`
	SOCKS5 SOCKS5ProxyConfig `yaml:"socks5,omitempty" json:"socks5,omitempty"`
	HTTP   HTTPProxyConfig   `yaml:"http,omitempty" json:"http,omitempty"`
}

// TURNProxyConfig configures a TURN relay as the proxy layer.
type TURNProxyConfig struct {
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Realm    string `yaml:"realm,omitempty" json:"realm,omitempty"`
	// Protocol is how to reach the TURN server: udp | tcp | tls | dtls
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	// NoCreatePermission skips CreatePermission calls (open relays).
	NoCreatePermission bool `yaml:"no_create_permission,omitempty" json:"no_create_permission,omitempty"`
	// IncludeWGPublicKey appends the encrypted WireGuard public key to the
	// TURN username so the relay can associate allocations.
	IncludeWGPublicKey bool `yaml:"include_wg_public_key,omitempty" json:"include_wg_public_key,omitempty"`
	// ValidateCert controls TLS certificate validation when reaching the
	// TURN server over TLS/DTLS. Default true (nil = use true).
	ValidateCert *bool `yaml:"validate_cert,omitempty" json:"validate_cert,omitempty"`
	// Permissions is a list of IP/CIDR allowed to send relay traffic.
	Permissions []string `yaml:"permissions,omitempty" json:"permissions,omitempty"`
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
	// ValidateCert overrides the default cert-validation behaviour.
	// nil = auto (skip when no credentials, verify when credentials set).
	// true = always verify. false = never verify.
	ValidateCert *bool `yaml:"validate_cert,omitempty" json:"validate_cert,omitempty"`
}

// IsConnectionOriented reports whether a transport config describes a
// connection-oriented transport (TCP/TLS/DTLS/HTTP/HTTPS, or anything
// carried over a stream proxy such as SOCKS5 or HTTP CONNECT).
func IsConnectionOriented(cfg Config) bool {
	switch cfg.Base {
	case "tcp", "tls", "dtls", "http", "https":
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
	case "", "udp", "tcp", "tls", "dtls", "http", "https":
		return nil
	}
	return &ConfigError{Field: "base", Value: base, Msg: "must be one of: udp tcp tls dtls http https"}
}

// ValidateProxyType checks that the proxy Type field is valid.
func ValidateProxyType(t string) error {
	switch t {
	case "", "none", "turn", "socks5", "http":
		return nil
	}
	return &ConfigError{Field: "proxy.type", Value: t, Msg: "must be one of: none turn socks5 http"}
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
