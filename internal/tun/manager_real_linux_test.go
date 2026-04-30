// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package tun

import (
	"net/netip"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

func TestRealLinuxTUNConfigureSmallRoute(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN configuration test")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}
	addr := netip.MustParsePrefix("198.19.0.2/32")
	route := netip.MustParsePrefix("198.19.0.0/24")
	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
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

func TestRealLinuxTUNConfigureDefaultRoutes(t *testing.T) {
	if !testconfig.Get().RealTUNDefault {
		t.Skip("set UWG_TEST_REAL_TUN_DEFAULT=1 or -uwgs-real-tun-default to run default-route host TUN test")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}
	addr4 := netip.MustParsePrefix("198.19.0.2/32")
	addr6 := netip.MustParsePrefix("2001:db8:ffff::2/128")
	route4 := netip.MustParsePrefix("0.0.0.0/0")
	route6 := netip.MustParsePrefix("::/0")
	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if err := Configure(mgr, Options{
		Name:      mgr.Name(),
		MTU:       1380,
		Configure: true,
		Addresses: []netip.Prefix{addr4, addr6},
		Routes:    []netip.Prefix{route4, route6},
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.RemoveRoute(route6)
	defer mgr.RemoveRoute(route4)
	defer mgr.RemoveAddress(addr6)
	defer mgr.RemoveAddress(addr4)
}
