// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

type taggedEndpointTransport struct {
	Transport transport.Config
	Endpoint  string
}

func parseTURNDirectiveURL(name, rawURL string) (transport.Config, error) {
	u, tags, err := parseTaggedURL(rawURL)
	if err != nil {
		return transport.Config{}, fmt.Errorf("invalid TURN URL %q: %w", rawURL, err)
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	if u.Host == "" {
		return transport.Config{}, fmt.Errorf("TURN URL %q missing host", rawURL)
	}
	proto, upgradeMode, err := decodeTURNSchemeTags(tags)
	if err != nil {
		return transport.Config{}, err
	}
	cfg := transport.Config{
		Name: name,
		Base: "turn",
		TURN: transport.TURNConfig{
			Server:   u.Host,
			Username: username,
			Password: password,
			Protocol: proto,
		},
	}
	if upgradeMode != "" || u.Path != "" || proto == "http" || proto == "https" || proto == "quic" {
		cfg.WebSocket = transport.WebSocketConfig{
			Path:        normalizeTaggedPath(u.Path, "/turn"),
			UpgradeMode: upgradeMode,
		}
	}
	return cfg, nil
}

func parsePeerEndpointTransport(name, raw string) (taggedEndpointTransport, bool, error) {
	u, tags, err := parseTaggedURL(raw)
	if err != nil {
		return taggedEndpointTransport{}, false, nil
	}
	if u == nil {
		return taggedEndpointTransport{}, false, nil
	}
	if u.Host == "" {
		return taggedEndpointTransport{}, false, fmt.Errorf("endpoint %q missing host", raw)
	}
	cfg, endpoint, err := decodePeerEndpointTags(name, u, tags)
	if err != nil {
		return taggedEndpointTransport{}, true, err
	}
	return taggedEndpointTransport{Transport: cfg, Endpoint: endpoint}, true, nil
}

func parseTaggedURL(raw string) (*url.URL, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "://") {
		return nil, nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "" {
		return nil, nil, nil
	}
	return u, splitTaggedScheme(u.Scheme), nil
}

func splitTaggedScheme(scheme string) []string {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return nil
	}
	if scheme == "turns" {
		return []string{"turns"}
	}
	parts := strings.Split(scheme, "+")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func decodeTURNSchemeTags(tags []string) (protocol, upgradeMode string, err error) {
	tags = withoutTag(tags, "turn")
	var proto string
	var raw bool
	var ws bool
	var wss bool
	for _, tag := range tags {
		switch tag {
		case "turns":
			if err := setSingleTag(&proto, "tls"); err != nil {
				return "", "", err
			}
		case "udp", "tcp", "tls", "dtls", "http", "https", "quic":
			if err := setSingleTag(&proto, tag); err != nil {
				return "", "", err
			}
		case "ws":
			ws = true
		case "wss":
			wss = true
		case "raw":
			raw = true
		default:
			return "", "", fmt.Errorf("unsupported TURN scheme tag %q", tag)
		}
	}
	switch {
	case proto == "" && wss:
		proto = "https"
	case proto == "" && (ws || raw):
		proto = "http"
	case proto == "":
		proto = "udp"
	}
	if wss && proto != "https" {
		return "", "", fmt.Errorf("TURN scheme tag wss requires https transport")
	}
	if (ws || wss || raw) && proto != "http" && proto != "https" {
		return "", "", fmt.Errorf("TURN websocket/raw tags require http or https transport")
	}
	if raw {
		upgradeMode = "proxyguard"
	} else if proto == "http" || proto == "https" {
		upgradeMode = "websocket"
	}
	return proto, upgradeMode, nil
}

func decodePeerEndpointTags(name string, u *url.URL, tags []string) (transport.Config, string, error) {
	base, upgradeMode, urlScheme, err := decodePeerEndpointBase(tags)
	if err != nil {
		return transport.Config{}, "", err
	}
	endpoint, err := taggedEndpointHostPort(u, base)
	if err != nil {
		return transport.Config{}, "", err
	}
	cfg := transport.Config{Name: name, Base: base}
	switch base {
	case "url":
		urlCopy := *u
		urlCopy.Scheme = urlScheme
		if urlCopy.Path == "" {
			urlCopy.Path = "/"
		}
		cfg.URL = urlCopy.String()
	case "http", "https", "quic", "quic-ws":
		cfg.WebSocket = transport.WebSocketConfig{
			Path:        normalizeTaggedPath(u.Path, "/"),
			UpgradeMode: upgradeMode,
		}
	}
	return cfg, endpoint, nil
}

func decodePeerEndpointBase(tags []string) (base, upgradeMode, urlScheme string, err error) {
	var proto string
	var raw bool
	var ws bool
	var wss bool
	for _, tag := range tags {
		switch tag {
		case "udp", "tcp", "tls", "dtls", "http", "https", "quic":
			if err := setSingleTag(&proto, tag); err != nil {
				return "", "", "", err
			}
		case "ws":
			ws = true
		case "wss":
			wss = true
		case "raw":
			raw = true
		default:
			return "", "", "", fmt.Errorf("unsupported endpoint scheme tag %q", tag)
		}
	}
	switch {
	case proto == "" && wss:
		proto = "https"
	case proto == "" && (ws || raw):
		proto = "http"
	case proto == "":
		proto = "udp"
	}
	if wss && proto != "https" {
		return "", "", "", fmt.Errorf("endpoint tag wss requires https transport")
	}
	switch proto {
	case "udp", "tcp", "tls", "dtls":
		if ws || wss || raw {
			return "", "", "", fmt.Errorf("endpoint websocket/raw tags require http, https, or quic transport")
		}
		return proto, "", "", nil
	case "http":
		if wss {
			return "", "", "", fmt.Errorf("endpoint tag wss requires https transport")
		}
		if raw {
			return "http", "proxyguard", "", nil
		}
		return "http", "websocket", "", nil
	case "https":
		if raw {
			return "https", "proxyguard", "", nil
		}
		if ws || wss {
			return "https", "websocket", "", nil
		}
		return "url", "", "https", nil
	case "quic":
		if raw {
			return "", "", "", fmt.Errorf("endpoint raw tag is not supported for quic")
		}
		if ws || wss {
			return "quic-ws", "", "", nil
		}
		return "quic", "", "", nil
	default:
		return "", "", "", fmt.Errorf("unsupported endpoint transport %q", proto)
	}
}

func taggedEndpointHostPort(u *url.URL, base string) (string, error) {
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("endpoint %q missing host", u.String())
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	port := ""
	switch base {
	case "http":
		port = "80"
	case "https", "quic", "quic-ws", "url":
		port = "443"
	default:
		port = "51820"
	}
	return net.JoinHostPort(host, port), nil
}

func normalizeTaggedPath(path, defaultPath string) string {
	if strings.TrimSpace(path) == "" {
		return defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func setSingleTag(dst *string, value string) error {
	if *dst != "" && *dst != value {
		return fmt.Errorf("conflicting scheme tags %q and %q", *dst, value)
	}
	*dst = value
	return nil
}

func withoutTag(tags []string, want string) []string {
	out := tags[:0]
	for _, tag := range tags {
		if tag != want {
			out = append(out, tag)
		}
	}
	return out
}
