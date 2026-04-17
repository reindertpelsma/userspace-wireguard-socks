// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package engine

import (
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

func systemCreateTUNDevice(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

func configureHostTUNKernel(cfg hostTUNKernelConfig) error {
	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			return err
		}
	}
	for _, prefix := range cfg.Addresses {
		addr := &netlink.Addr{IPNet: ipNetFromPrefix(prefix)}
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	for _, prefix := range cfg.Routes {
		route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNetFromPrefix(prefix)}
		if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	return nil
}

func ipNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	bits := 128
	ip := net.IP(prefix.Addr().AsSlice()).To16()
	if prefix.Addr().Is4() {
		bits = 32
		ip = net.IP(prefix.Addr().AsSlice()).To4()
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(prefix.Bits(), bits)}
}
