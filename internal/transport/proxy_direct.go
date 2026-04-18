// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"net"
	"net/netip"
)

// DirectDialer is a ProxyDialer that dials directly through the host network
// with no proxy.  Optional IPv6 translation maps IPv4 target addresses to a
// NAT64 /96 prefix before dialling.
type DirectDialer struct {
	// IPv6Translate enables NAT64/DNS64 address translation.
	IPv6Translate bool
	// IPv6Prefix is the NAT64 prefix.  Must be a /96.
	// Defaults to the well-known prefix 64:ff9b::/96.
	IPv6Prefix netip.Prefix
}

// NewDirectDialer creates a DirectDialer.  If ipv6Translate is true and
// prefix is the zero value the well-known prefix 64:ff9b::/96 is used.
func NewDirectDialer(ipv6Translate bool, prefix netip.Prefix) *DirectDialer {
	if ipv6Translate && !prefix.IsValid() {
		// Well-known NAT64 prefix (RFC 6146)
		prefix = netip.MustParsePrefix("64:ff9b::/96")
	}
	return &DirectDialer{IPv6Translate: ipv6Translate, IPv6Prefix: prefix}
}

// DialContext dials network+addr directly.  When IPv6Translate is set, any
// IPv4 literal address is rewritten to its NAT64 representation before
// dialling.
func (d *DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.IPv6Translate {
		addr = d.translateAddr(addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// DialPacket opens a UDP PacketConn for not-connection-oriented UDP traffic.
// remoteHint is translated when IPv6Translate is set.
func (d *DirectDialer) DialPacket(ctx context.Context, remoteHint string) (net.PacketConn, string, error) {
	if d.IPv6Translate {
		remoteHint = d.translateAddr(remoteHint)
	}
	// For direct UDP we listen on any local port and report the remote hint
	// as the effective address so callers can route the packet.
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, "", err
	}
	return pc, remoteHint, nil
}

// SupportsHostname returns true; direct dialling resolves via the OS
// resolver.
func (d *DirectDialer) SupportsHostname() bool { return true }

// translateAddr rewrites an IPv4 host portion of addr to its NAT64 form.
// The port suffix is preserved unchanged.
func (d *DirectDialer) translateAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a host:port string – return unchanged.
		return addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return addr
	}
	translated := TranslateToIPv6(ip, d.IPv6Prefix)
	return net.JoinHostPort(translated.String(), port)
}
