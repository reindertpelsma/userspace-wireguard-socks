// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"fmt"
	"net/netip"
	"time"
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
		if cfg.Name == "" {
			return nil, fmt.Errorf("transport[%d]: name is required", i)
		}
		if err := ValidateBase(cfg.Base); err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
		}
		if err := ValidateProxyType(cfg.Proxy.Type); err != nil {
			return nil, fmt.Errorf("transport %q: %w", cfg.Name, err)
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
			_ = listenPort
			bind.AddListenTransport(t)
		}
	}
	return bind, nil
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
		return NewHTTPConnectDialer(pc.Server, scheme, pc.Username, pc.Password, pc.ValidateCert)

	case "turn":
		// TURN is a transport, not a dialer — handled in buildBaseTransport.
		return direct, nil
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
	if cfg.WebSocket.HostHeader != "" {
		wsOpts = append(wsOpts, WithWebSocketHostHeader(cfg.WebSocket.HostHeader))
	}
	if cfg.WebSocket.SNIHostname != "" {
		wsOpts = append(wsOpts, WithWebSocketSNIHostname(cfg.WebSocket.SNIHostname))
	}

	switch cfg.Base {
	case "", "udp":
		if cfg.Proxy.Type == "turn" {
			return NewTURNTransport(cfg.Name, cfg.Proxy.TURN, wgPubKey), nil
		}
		d, ok := dialer.(*DirectDialer)
		if !ok {
			// For UDP over SOCKS5 the DirectDialer is embedded in SOCKS5Dialer.
			d = NewDirectDialer(cfg.IPv6Translate, netip.Prefix{})
		}
		return NewUDPTransport(cfg.Name, listenAddrs, d), nil

	case "tcp":
		return NewTCPTransport(cfg.Name, dialer, listenAddrs), nil

	case "tls":
		certMgr, err := buildCertManager(cfg.TLS)
		if err != nil {
			return nil, err
		}
		return NewTLSTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS.VerifyPeer), nil

	case "dtls":
		certMgr, err := buildCertManager(cfg.TLS)
		if err != nil {
			return nil, err
		}
		return NewDTLSTransport(cfg.Name, dialer, listenAddrs, certMgr, cfg.TLS.VerifyPeer), nil

	case "http":
		return NewWebSocketTransport(cfg.Name, "http", dialer, listenAddrs, nil, cfg.TLS.VerifyPeer, wsOpts...), nil

	case "https":
		certMgr, err := buildCertManager(cfg.TLS)
		if err != nil {
			return nil, err
		}
		return NewWebSocketTransport(cfg.Name, "https", dialer, listenAddrs, certMgr, cfg.TLS.VerifyPeer, wsOpts...), nil
	}
	return nil, fmt.Errorf("unsupported base protocol %q", cfg.Base)
}

// buildCertManager creates and starts a CertManager from TLS config.
func buildCertManager(tlsCfg TLSConfig) (*CertManager, error) {
	var reload time.Duration
	if tlsCfg.ReloadInterval != "" {
		var err error
		reload, err = time.ParseDuration(tlsCfg.ReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("tls.reload_interval: %w", err)
		}
	}
	mgr := &CertManager{
		CertFile:       tlsCfg.CertFile,
		KeyFile:        tlsCfg.KeyFile,
		ReloadInterval: reload,
	}
	if err := mgr.Start(); err != nil {
		return nil, fmt.Errorf("cert manager: %w", err)
	}
	return mgr, nil
}
