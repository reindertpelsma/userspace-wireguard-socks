// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func (e *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.proxyDial(ctx, network, address)
}

// DialTunnelContext dials only through WireGuard. Unlike DialContext it never
// uses the direct or fallback SOCKS5 path when the destination is outside
// AllowedIPs.
func (e *Engine) DialTunnelContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.dialTunnelOnly(ctx, network, address, netip.AddrPort{})
}

// ListenTCP creates a TCP listener bound to the userspace WireGuard netstack.
// Nothing is bound on the host network.
func (e *Engine) ListenTCP(addr netip.AddrPort) (net.Listener, error) {
	if e.net == nil {
		return nil, errors.New("engine is not started")
	}
	ln, err := e.net.ListenTCPAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return e.wrapPeerListener(ln), nil
}

// ListenUDP creates a UDP socket bound inside the userspace WireGuard netstack.
func (e *Engine) ListenUDP(addr netip.AddrPort) (net.PacketConn, error) {
	if e.net == nil {
		return nil, errors.New("engine is not started")
	}
	pc, err := e.net.ListenUDPAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return e.wrapPeerPacketConn(pc), nil
}

// DialUDP creates a UDP socket inside the userspace WireGuard netstack. The
// remote address, when set, must still match peer AllowedIPs.
func (e *Engine) DialUDP(laddr, raddr netip.AddrPort) (net.Conn, error) {
	if e.net == nil {
		return nil, errors.New("engine is not started")
	}
	if raddr.IsValid() && !e.allowedContains(raddr.Addr()) {
		return nil, errors.New("remote address does not match any WireGuard AllowedIPs")
	}
	c, err := e.net.DialUDPAddrPort(laddr, raddr)
	if err != nil {
		return nil, err
	}
	if !raddr.IsValid() {
		return c, nil
	}
	return e.wrapDialedPeerConn("udp", c, raddr), nil
}
