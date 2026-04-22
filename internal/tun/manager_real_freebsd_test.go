// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build freebsd

package tun

import (
	"net/netip"
	"os"
	"testing"
)

func TestRealFreeBSDTUNConfigureSmallRoute(t *testing.T) {
	if os.Getenv("UWG_TEST_REAL_TUN") != "1" {
		t.Skip("set UWG_TEST_REAL_TUN=1 to run real host TUN configuration test")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}
	addr := netip.MustParsePrefix("198.19.0.2/32")
	route := netip.MustParsePrefix("198.19.0.0/24")
	mgr, err := Create(Options{MTU: 1380})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if err := Configure(mgr, Options{
		Name:      mgr.Name(),
		MTU:       1380,
		Configure: true,
		Addresses: []netip.Prefix{addr},
		Routes:    []netip.Prefix{route},
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.RemoveRoute(route)
	defer mgr.RemoveAddress(addr)
}
