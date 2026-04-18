// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"net/netip"
)

// TranslateToIPv6 embeds an IPv4 address into a NAT64 /96 prefix.
// The IPv4 address occupies the last 32 bits of the 128-bit IPv6 address.
// prefix must be a /96; its host bits are ignored.
func TranslateToIPv6(addr netip.Addr, prefix netip.Prefix) netip.Addr {
	if !addr.Is4() {
		return addr
	}
	v4 := addr.As4()
	p128 := prefix.Addr().As16()
	// Embed IPv4 in bits 96–127.
	p128[12] = v4[0]
	p128[13] = v4[1]
	p128[14] = v4[2]
	p128[15] = v4[3]
	return netip.AddrFrom16(p128)
}

// TranslateFromIPv6 extracts an IPv4 address from a NAT64 /96 prefix.
// Returns (addr, true) when addr falls within prefix, or (addr, false)
// when addr is not an IPv6 address in the given prefix.
func TranslateFromIPv6(addr netip.Addr, prefix netip.Prefix) (netip.Addr, bool) {
	if !addr.Is6() || !prefix.Contains(addr) {
		return addr, false
	}
	b := addr.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}
