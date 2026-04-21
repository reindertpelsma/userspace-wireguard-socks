// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package transport

import (
	"fmt"
	"net/netip"
)

type BuildOptions struct {
	DirectDialerFactory func(cfg Config) (ProxyDialer, error)
}

func BuildRegistry(
	configs []Config,
	wgPubKey [32]byte,
	defaultListenPort int,
	peerLookup PeerLookup,
	onEndpointReset EndpointResetFunc,
	legacyUDP bool,
) (*MultiTransportBind, error) {
	return BuildRegistryWithOptions(configs, wgPubKey, defaultListenPort, peerLookup, onEndpointReset, legacyUDP, BuildOptions{})
}

func BuildRegistryWithOptions(
	configs []Config,
	_ [32]byte,
	defaultListenPort int,
	peerLookup PeerLookup,
	onEndpointReset EndpointResetFunc,
	legacyUDP bool,
	opts BuildOptions,
) (*MultiTransportBind, error) {
	bind := NewMultiTransportBind(peerLookup, onEndpointReset)
	if len(configs) == 0 {
		if legacyUDP {
			direct, err := directDialerForConfig(Config{}, opts)
			if err != nil {
				return nil, err
			}
			d, ok := direct.(*DirectDialer)
			if !ok {
				d = NewDirectDialer(false, netip.Prefix{})
			}
			t := NewUDPTransport("udp", nil, d)
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
		if cfg.Base != "" && cfg.Base != "udp" {
			return nil, fmt.Errorf("transport %q: base %q is not supported in lite builds", cfg.Name, cfg.Base)
		}
		if cfg.Proxy.Type != "" && cfg.Proxy.Type != "none" {
			return nil, fmt.Errorf("transport %q: proxy type %q is not supported in lite builds", cfg.Name, cfg.Proxy.Type)
		}
		if len(cfg.ListenAddresses) > 1 {
			return nil, fmt.Errorf("transport %q: udp transport only supports a single listen address", cfg.Name)
		}
		listenPort := defaultListenPort
		if cfg.ListenPort != nil {
			listenPort = *cfg.ListenPort
		}
		direct, err := directDialerForConfig(cfg, opts)
		if err != nil {
			return nil, err
		}
		d, ok := direct.(*DirectDialer)
		if !ok {
			d = NewDirectDialer(cfg.IPv6Translate, netip.Prefix{})
		}
		t := NewUDPTransport(cfg.Name, cfg.ListenAddresses, d)
		bind.AddTransport(t)
		if cfg.Listen {
			bind.AddListenTransportWithPort(t, listenPort)
		}
	}
	defaultName := resolveDefaultTransportName(configs, "")
	if defaultName != "" {
		bind.SetDefaultTransport(defaultName)
	}
	return bind, nil
}

func ResolveDefaultTransportName(configs []Config, override string) string {
	return resolveDefaultTransportName(configs, override)
}

func resolveDefaultTransportName(configs []Config, override string) string {
	if override != "" {
		return override
	}
	if len(configs) > 0 {
		return configs[0].Name
	}
	return ""
}

func buildDialer(cfg Config, opts BuildOptions) (ProxyDialer, error) {
	return directDialerForConfig(cfg, opts)
}

func directDialerForConfig(cfg Config, opts BuildOptions) (ProxyDialer, error) {
	if opts.DirectDialerFactory != nil {
		return opts.DirectDialerFactory(cfg)
	}
	var prefix netip.Prefix
	if cfg.IPv6Translate && cfg.IPv6Prefix != "" {
		var err error
		prefix, err = netip.ParsePrefix(cfg.IPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("ipv6_prefix: %w", err)
		}
	}
	return NewDirectDialer(cfg.IPv6Translate, prefix), nil
}
