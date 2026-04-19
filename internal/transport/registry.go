// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"fmt"
	"net/netip"
)

// BuildRegistry constructs a MultiTransportBind from a slice of Config
// entries.  wgPubKey is the WireGuard public key of this instance, embedded
// in TURN usernames when IncludeWGPublicKey is set.
//
// Backward-compatibility: if configs is empty and legacyUDP is true a single
// default UDP transport is added.
func BuildRegistry(
	configs []Config,
	wgPubKey [32]byte,
	defaultListenPort int,
	peerLookup PeerLookup,
	onEndpointReset EndpointResetFunc,
	legacyUDP bool,
) (*MultiTransportBind, error) {
	bind := NewMultiTransportBind(peerLookup, onEndpointReset)

	if len(configs) == 0 {
		if legacyUDP {
			t := NewUDPTransport("udp", nil, NewDirectDialer(false, netip.Prefix{}))
			bind.AddTransport(t)
			bind.AddListenTransport(t)
		}
		return bind, nil
	}

	for i, cfg := range configs {
		cfg = NormalizeConfig(cfg)
		if cfg.Name == "" {
			return nil, fmt.Errorf("transport[%d]: name is required", i)
		}
		if err := ValidateBase(cfg.Base); err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
		}
		if err := ValidateProxyType(cfg.Proxy.Type); err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
		}
		if err := ValidateWebSocketUpgradeMode(cfg.WebSocket.UpgradeMode); err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
		}

		// Validate UDP listen address count.
		if cfg.Base == "" || cfg.Base == "udp" {
			if len(cfg.ListenAddresses) > 1 {
				return nil, fmt.Errorf("transport %q: udp transport only supports a single listen address", cfg.Name)
			}
		}

		// Resolve listen port.
		listenPort := defaultListenPort
		if cfg.ListenPort != nil {
			listenPort = *cfg.ListenPort
		}

		// Build proxy dialer.
		dialer, err := buildDialer(cfg)
		if err != nil {
			return nil, fmt.Errorf("transport %q: dialer: %w", cfg.Name, err)
		}

		// Build base transport.
		t, err := buildBaseTransport(cfg, dialer, wgPubKey)
		if err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
		}

		bind.AddTransport(t)
		if cfg.Listen {
			bind.AddListenTransportWithPort(t, listenPort)
		}
	}

	// Set the deterministic default transport for ParseEndpoint.
	defaultName := resolveDefaultTransportName(configs, "")
	if defaultName != "" {
		bind.SetDefaultTransport(defaultName)
	}

	return bind, nil
}

// ResolveDefaultTransportName picks the default transport name from a list of
// configs.  If override is non-empty it is returned directly.  Otherwise the
// first NCO transport is used; if none exist the first transport is used.
func ResolveDefaultTransportName(configs []Config, override string) string {
	return resolveDefaultTransportName(configs, override)
}

func resolveDefaultTransportName(configs []Config, override string) string {
	if override != "" {
		return override
	}
	for _, tc := range configs {
		if !IsConnectionOriented(tc) {
			return tc.Name
		}
	}
	if len(configs) > 0 {
		return configs[0].Name
	}
	return ""
}

// buildDialer creates the ProxyDialer for a transport config.
func buildDialer(cfg Config) (ProxyDialer, error) {
	var prefix netip.Prefix
	if cfg.IPv6Translate && cfg.IPv6Prefix != "" {
		var err error
		prefix, err = netip.ParsePrefix(cfg.IPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("ipv6_prefix: %w", err)
		}
	}
	direct := NewDirectDialer(cfg.IPv6Translate, prefix)

	switch cfg.Proxy.Type {
	case "", "none":
		return direct, nil

	case "socks5":
		pc := cfg.Proxy.SOCKS5
		return NewSOCKS5Dialer(pc.Server, pc.Username, pc.Password)

	case "http":
		pc := cfg.Proxy.HTTP
		scheme := "http"
		// If the transport itself is TLS/HTTPS we use HTTPS proxy by default.
		if cfg.Base == "tls" || cfg.Base == "https" {
			scheme = "https"
		}
		return NewHTTPConnectDialer(pc.Server, scheme, pc.Username, pc.Password, pc.TLS)

	}
	return direct, nil
}

// buildBaseTransport creates the Transport for a config entry.
func buildBaseTransport(cfg Config, dialer ProxyDialer, wgPubKey [32]byte) (Transport, error) {
	listenAddrs := cfg.ListenAddresses
	var wsOpts []WebSocketOption
	if cfg.WebSocket.Path != "" {
		wsOpts = append(wsOpts, WithWebSocketPath(cfg.WebSocket.Path))
	}
	if cfg.WebSocket.UpgradeMode != "" {
		wsOpts = append(wsOpts, WithWebSocketUpgradeMode(HTTPUpgradeMode(cfg.WebSocket.UpgradeMode)))
	}
	if cfg.WebSocket.ConnectHost != "" {
		wsOpts = append(wsOpts, WithWebSocketConnectHost(cfg.WebSocket.ConnectHost))
	}
	if cfg.WebSocket.HostHeader != "" {
		wsOpts = append(wsOpts, WithWebSocketHostHeader(cfg.WebSocket.HostHeader))
	}
	if cfg.WebSocket.SNIHostname != "" && !cfg.TLS.ServerSNI.IsSet() {
		wsOpts = append(wsOpts, WithWebSocketSNIHostname(cfg.WebSocket.SNIHostname))
	}

	switch cfg.Base {
	case "", "udp":
		d, ok := dialer.(*DirectDialer)
		if !ok {
			// For UDP over SOCKS5 the DirectDialer is embedded in SOCKS5Dialer.
			d = NewDirectDialer(cfg.IPv6Translate, netip.Prefix{})
		}
		return NewUDPTransport(cfg.Name, listenAddrs, d), nil

	case "turn":
		return NewTURNTransport(cfg.Name, cfg.TURN, dialer, wgPubKey)

	case "tcp":
		return NewTCPTransport(cfg.Name, dialer, listenAddrs), nil

	case "tls":
		certMgr, err := buildCertManager(cfg.TLS, cfg.Listen)
		if err != nil {
			return nil, err
		}
		return NewTLSTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS), nil

	case "dtls":
		certMgr, err := buildCertManager(cfg.TLS, true)
		if err != nil {
			return nil, err
		}
		return NewDTLSTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS), nil

	case "http":
		return NewWebSocketTransport(cfg.Name, "http", dialer, listenAddrs, nil, cfg.TLS, wsOpts...), nil

	case "https":
		certMgr, err := buildCertManager(cfg.TLS, cfg.Listen)
		if err != nil {
			return nil, err
		}
		return NewWebSocketTransport(cfg.Name, "https", dialer, listenAddrs, certMgr, cfg.TLS, wsOpts...), nil

	case "quic":
		certMgr, err := buildCertManager(cfg.TLS, cfg.Listen)
		if err != nil {
			return nil, err
		}
		return NewQUICTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS, cfg.WebSocket.Path, cfg.WebSocket.HostHeader, cfg.WebSocket.ConnectHost), nil

	case "quic-ws":
		certMgr, err := buildCertManager(cfg.TLS, cfg.Listen)
		if err != nil {
			return nil, err
		}
		return NewQUICWebSocketTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS, cfg.WebSocket.Path, cfg.WebSocket.HostHeader, cfg.WebSocket.ConnectHost), nil

	case "url":
		if cfg.URL == "" {
			return nil, fmt.Errorf("url transport requires url field (e.g. https://example.com/wg)")
		}
		certMgr, err := buildCertManager(cfg.TLS, cfg.Listen)
		if err != nil {
			return nil, err
		}
		return NewURLTransport(cfg.Name, cfg.URL, dialer, listenAddrs, certMgr, cfg.TLS, cfg.WebSocket.ConnectHost, cfg.WebSocket.HostHeader)
	}
	return nil, fmt.Errorf("unsupported base protocol %q", cfg.Base)
}
