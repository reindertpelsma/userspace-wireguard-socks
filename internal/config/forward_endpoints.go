// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package config

import (
	"fmt"
	"net"
	"strings"
)

type ForwardEndpointKind int

const (
	ForwardEndpointHostPort ForwardEndpointKind = iota
	ForwardEndpointUnixStream
	ForwardEndpointUnixDgram
	ForwardEndpointUnixSeqpacket
)

type ForwardEndpoint struct {
	Raw     string
	Kind    ForwardEndpointKind
	Address string
}

func (e ForwardEndpoint) IsUnix() bool {
	return e.Kind != ForwardEndpointHostPort
}

func (e ForwardEndpoint) UsesMessages() bool {
	return e.Kind == ForwardEndpointUnixDgram || e.Kind == ForwardEndpointUnixSeqpacket
}

func (e ForwardEndpoint) Network() string {
	switch e.Kind {
	case ForwardEndpointUnixStream:
		return "unix"
	case ForwardEndpointUnixDgram:
		return "unixgram"
	case ForwardEndpointUnixSeqpacket:
		return "unixpacket"
	default:
		return ""
	}
}

func ParseForwardEndpoint(proto, raw string) (ForwardEndpoint, error) {
	var ep ForwardEndpoint
	ep.Raw = strings.TrimSpace(raw)
	if ep.Raw == "" {
		return ep, fmt.Errorf("endpoint is required")
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != "tcp" && proto != "udp" {
		return ep, fmt.Errorf("unsupported forward proto %q", proto)
	}
	scheme, addr, ok := splitUnixEndpoint(ep.Raw)
	if !ok {
		if _, _, err := net.SplitHostPort(ep.Raw); err != nil {
			return ep, err
		}
		ep.Kind = ForwardEndpointHostPort
		ep.Address = ep.Raw
		return ep, nil
	}
	if addr == "" {
		return ep, fmt.Errorf("unix socket path is required")
	}
	switch scheme {
	case "unix":
		if proto == "udp" {
			ep.Kind = ForwardEndpointUnixDgram
		} else {
			ep.Kind = ForwardEndpointUnixStream
		}
	case "unix+stream":
		ep.Kind = ForwardEndpointUnixStream
	case "unix+dgram":
		ep.Kind = ForwardEndpointUnixDgram
	case "unix+seqpacket":
		ep.Kind = ForwardEndpointUnixSeqpacket
	default:
		return ep, fmt.Errorf("unsupported unix endpoint scheme %q", scheme)
	}
	if proto == "udp" && ep.Kind == ForwardEndpointUnixStream {
		return ep, fmt.Errorf("UDP does not support unix stream endpoints")
	}
	ep.Address = addr
	return ep, nil
}

func ValidateForwardEndpoints(f Forward, reverse bool) error {
	listen, err := ParseForwardEndpoint(f.Proto, f.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", f.Listen, err)
	}
	target, err := ParseForwardEndpoint(f.Proto, f.Target)
	if err != nil {
		return fmt.Errorf("target %q: %w", f.Target, err)
	}
	if reverse {
		if listen.IsUnix() {
			return fmt.Errorf("reverse forward listen must be ip:port, not a unix socket")
		}
	} else {
		if target.IsUnix() {
			return fmt.Errorf("forward target must be host:port, not a unix socket")
		}
	}
	if f.AllowUnnamedDGRAM && (reverse || listen.Kind != ForwardEndpointUnixDgram) {
		return fmt.Errorf("allow_unnamed_dgram only applies to forward listeners using unix+dgram")
	}
	if f.FrameBytes != 0 && f.FrameBytes != 2 && f.FrameBytes != 4 {
		return fmt.Errorf("frame_bytes must be 2, 4, or empty")
	}
	if f.Proto == "udp" && f.FrameBytes != 0 {
		return fmt.Errorf("frame_bytes is only valid for TCP forwards")
	}
	if f.FrameBytes != 0 {
		usesMessageSocket := listen.UsesMessages() || target.UsesMessages()
		if !usesMessageSocket {
			return fmt.Errorf("frame_bytes only applies when a TCP forward uses unix+dgram or unix+seqpacket")
		}
	}
	return nil
}

func splitUnixEndpoint(raw string) (scheme, addr string, ok bool) {
	for _, prefix := range []string{
		"unix+stream://",
		"unix+dgram://",
		"unix+seqpacket://",
		"unix://",
		"unix+stream:",
		"unix+dgram:",
		"unix+seqpacket:",
		"unix:",
	} {
		if strings.HasPrefix(raw, prefix) {
			scheme = strings.TrimSuffix(strings.TrimSuffix(prefix, "://"), ":")
			addr = strings.TrimPrefix(raw, prefix)
			return scheme, addr, true
		}
	}
	return "", "", false
}
