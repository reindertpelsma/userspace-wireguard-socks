// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"net/netip"
	"testing"
)

func TestUDPListenerGroupPeerOwnerLimit(t *testing.T) {
	g := &udpListenerGroup{
		peerOwner: make(map[string]udpPeerOwnerEntry),
	}

	first := netip.MustParseAddrPort("192.0.2.1:10000")
	for i := 0; i < maxUDPListenerPeerOwners+8; i++ {
		addr := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 250)}),
			uint16(10000+i),
		)
		g.recordPeerOwner(addr, "token")
	}

	if got := len(g.peerOwner); got != maxUDPListenerPeerOwners {
		t.Fatalf("peerOwner size = %d, want %d", got, maxUDPListenerPeerOwners)
	}
	if owner := g.ownerFor(first); owner != "" {
		t.Fatalf("oldest peer owner = %q, want eviction", owner)
	}
	latest := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte((maxUDPListenerPeerOwners + 7) % 250)}), uint16(10000+maxUDPListenerPeerOwners+7))
	if owner := g.ownerFor(latest); owner != "token" {
		t.Fatalf("latest peer owner = %q, want token", owner)
	}
}
