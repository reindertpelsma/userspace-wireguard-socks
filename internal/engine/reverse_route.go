// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func (e *Engine) matchReverseForward(network string, dst netip.AddrPort) (config.Forward, bool) {
	proto := networkBase(network)
	e.forwardMu.Lock()
	defer e.forwardMu.Unlock()
	for _, rt := range e.forwardNames {
		if !rt.reverse || rt.forward.Proto != proto {
			continue
		}
		listen, err := netip.ParseAddrPort(rt.forward.Listen)
		if err != nil || listen.Port() != dst.Port() {
			continue
		}
		if listen.Addr().IsUnspecified() {
			if e.localAddrContains(dst.Addr()) && listen.Addr().Is6() == dst.Addr().Is6() {
				return rt.forward, true
			}
			continue
		}
		if listen.Addr() == dst.Addr() {
			return rt.forward, true
		}
	}
	return config.Forward{}, false
}

func (e *Engine) dialReverseForwardTarget(ctx context.Context, network string, f config.Forward, src, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	host, err := d.DialContext(ctx, networkBase(network), f.Target)
	if err != nil {
		return nil, err
	}
	if f.ProxyProtocol == "" {
		return host, nil
	}
	header, err := proxyProtocolBytes(f.ProxyProtocol, network, src, dst)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	if len(header) == 0 {
		return host, nil
	}
	if networkBase(network) == "udp" {
		return &proxyProtocolUDPConn{Conn: host, header: header}, nil
	}
	if _, err := host.Write(header); err != nil {
		_ = host.Close()
		return nil, fmt.Errorf("write PROXY header: %w", err)
	}
	return host, nil
}

type proxyProtocolUDPConn struct {
	net.Conn
	header []byte
}

func (c *proxyProtocolUDPConn) Write(p []byte) (int, error) {
	packet := make([]byte, 0, len(c.header)+len(p))
	packet = append(packet, c.header...)
	packet = append(packet, p...)
	if _, err := c.Conn.Write(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}
