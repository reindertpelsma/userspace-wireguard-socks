// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	xicmp "golang.org/x/net/icmp"
)

func (e *Engine) dialSocketOutbound(ctx context.Context, network string, aclSrc, bindSrc, dst netip.AddrPort) (net.Conn, error) {
	if dst.Addr().Is6() && !e.socketIPv6Enabled() {
		return nil, fmt.Errorf("IPv6 is disabled")
	}
	if !e.outboundAllowed(aclSrc, dst, network) {
		return nil, errProxyACL
	}
	if f, ok := e.matchReverseForward(network, dst); ok {
		return e.dialReverseForwardTarget(ctx, network, f, aclSrc, dst)
	}
	if rewritten, ok, err := e.proxyHostForwardTarget(dst); err != nil {
		return nil, err
	} else if ok {
		return e.dialDirectHost(ctx, network, bindSrc, rewritten)
	}
	if e.tunnelAddrBlocked(dst.Addr()) {
		return nil, errAddressFiltered
	}
	if e.allowedContains(dst.Addr()) {
		return e.dialNetstack(ctx, network, bindSrc, dst)
	}
	if e.localPrefixContainsUnrouted(dst.Addr()) {
		return nil, errVirtualSubnetUnrouted
	}
	if c, matched, err := e.dialOutboundProxy(ctx, network, dst, outboundRoleSocks); matched || err != nil {
		return c, err
	}
	if !*e.cfg.Proxy.FallbackDirect {
		return nil, fmt.Errorf("%s: %w", dst.Addr(), errProxyFallbackDisabled)
	}
	return e.dialDirectHost(ctx, network, bindSrc, dst)
}

func (e *Engine) dialSocketICMP(aclSrc, bind, dest netip.AddrPort) (net.Conn, error) {
	if dest.Addr().Is6() && !e.socketIPv6Enabled() {
		return nil, fmt.Errorf("IPv6 is disabled")
	}
	aclDest := netip.AddrPortFrom(dest.Addr(), 0)
	if !e.outboundAllowed(aclSrc, aclDest, "icmp") {
		return nil, errProxyACL
	}
	if rewritten, ok, err := e.proxyHostForwardTarget(aclDest); err != nil {
		return nil, err
	} else if ok {
		dest = netip.AddrPortFrom(rewritten.Addr(), 0)
	}
	if e.tunnelAddrBlocked(dest.Addr()) {
		return nil, errAddressFiltered
	}
	bindIP := e.hostDirectBindIP(bind.Addr(), dest.Addr())
	if e.allowedContains(dest.Addr()) {
		return e.net.DialPingAddr(bindIP, dest.Addr())
	}
	if e.localPrefixContainsUnrouted(dest.Addr()) {
		return nil, errVirtualSubnetUnrouted
	}
	if !*e.cfg.Proxy.FallbackDirect {
		return nil, fmt.Errorf("%s: %w", dest.Addr(), errProxyFallbackDisabled)
	}
	return e.dialHostPing(bindIP, dest.Addr())
}

func (e *Engine) dialDirectHost(ctx context.Context, network string, bindSrc, dst netip.AddrPort) (net.Conn, error) {
	if e.fallbackDialer != nil && strings.HasPrefix(network, "tcp") {
		if cd, ok := e.fallbackDialer.(interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}); ok {
			return cd.DialContext(ctx, network, dst.String())
		}
		return e.fallbackDialer.Dial(network, dst.String())
	}
	if e.fallbackDialer != nil && strings.HasPrefix(network, "udp") {
		return nil, errors.New("fallback_socks5 does not support UDP ASSOCIATE in this runtime")
	}
	var d net.Dialer
	if la := e.hostDirectLocalAddr(network, bindSrc, dst); la != nil {
		d.LocalAddr = la
	}
	return d.DialContext(ctx, network, dst.String())
}

func (e *Engine) dialHostPing(bindIP, dst netip.Addr) (net.Conn, error) {
	network := "udp4"
	if dst.Is6() {
		network = "udp6"
	}
	laddr := ""
	if bind := e.hostDirectBindIP(bindIP, dst); bind.IsValid() {
		laddr = bind.String()
	}
	pc, err := xicmp.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return &connectedPacketConn{
		PacketConn: pc,
		remote:     &net.IPAddr{IP: net.IP(dst.AsSlice())},
	}, nil
}

func (e *Engine) hostDirectLocalAddr(network string, bindSrc, dst netip.AddrPort) net.Addr {
	ip := e.hostDirectBindIP(bindSrc.Addr(), dst.Addr())
	if !ip.IsValid() && bindSrc.Port() == 0 {
		return nil
	}
	switch networkBase(network) {
	case "udp":
		return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(bindSrc.Port())}
	default:
		return &net.TCPAddr{IP: net.IP(ip.AsSlice()), Port: int(bindSrc.Port())}
	}
}

func (e *Engine) hostDirectBindIP(bindIP, dst netip.Addr) netip.Addr {
	if !bindIP.IsValid() {
		return netip.Addr{}
	}
	bindIP = bindIP.Unmap()
	dst = dst.Unmap()
	if bindIP.IsUnspecified() || bindIP.Is4() != dst.Is4() {
		return netip.Addr{}
	}
	if e.localAddrContains(bindIP) || e.allowedContains(bindIP) || e.localPrefixContainsUnrouted(bindIP) {
		return netip.Addr{}
	}
	return bindIP
}

func (e *Engine) socketIPv6Enabled() bool {
	if e.cfg.Proxy.IPv6 != nil && !*e.cfg.Proxy.IPv6 {
		return false
	}
	for _, addr := range e.localAddrs {
		if addr.Is6() {
			return true
		}
	}
	return e.allowedHasIPv6()
}

type connectedPacketConn struct {
	net.PacketConn
	remote net.Addr
}

func (c *connectedPacketConn) Read(p []byte) (int, error) {
	for {
		n, _, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
}

func (c *connectedPacketConn) Write(p []byte) (int, error) {
	return c.PacketConn.WriteTo(p, c.remote)
}

func (c *connectedPacketConn) RemoteAddr() net.Addr {
	return c.remote
}
