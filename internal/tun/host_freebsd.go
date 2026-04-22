// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build freebsd

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type freebsdManager struct {
	baseManager
}

func Create(opts Options) (Manager, error) {
	dev, err := wgtun.CreateTUN(opts.Name, opts.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil || name == "" {
		name = opts.Name
	}
	local4, local6 := captureBypassLocalAddrs()
	return &freebsdManager{
		baseManager: baseManager{
			device:        dev,
			name:          name,
			mtu:           opts.MTU,
			localIPv4:     local4,
			localIPv6:     local6,
			dnsResolvConf: opts.DNSResolvConf,
		},
	}, nil
}

func (m *freebsdManager) AddAddress(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return runBSD("ifconfig", m.name, "inet", prefix.Addr().String(), prefix.Addr().String(), "netmask", ipv4Netmask(prefix.Bits()), "alias")
	}
	return runBSD("ifconfig", m.name, "inet6", prefix.Addr().String(), "prefixlen", strconv.Itoa(prefix.Bits()), "alias")
}

func (m *freebsdManager) RemoveAddress(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return runBSD("ifconfig", m.name, "inet", prefix.Addr().String(), prefix.Addr().String(), "remove")
	}
	return runBSD("ifconfig", m.name, "inet6", prefix.Addr().String(), "delete")
}

func (m *freebsdManager) AddRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return runBSD("route", "-n", "add", "-inet", prefix.String(), "-interface", m.name)
	}
	return runBSD("route", "-n", "add", "-inet6", prefix.String(), "-interface", m.name)
}

func (m *freebsdManager) RemoveRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return runBSD("route", "-n", "delete", "-inet", prefix.String(), "-interface", m.name)
	}
	return runBSD("route", "-n", "delete", "-inet6", prefix.String(), "-interface", m.name)
}

func (m *freebsdManager) SetDNSServers(addrs []netip.Addr) error {
	if handled, err := m.writeResolvConf(addrs); handled {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}
	return fmt.Errorf("tun dns configuration on freebsd requires dns_resolv_conf")
}

func (m *freebsdManager) ClearDNSServers() error {
	if handled, err := m.restoreResolvConf(); handled {
		return err
	}
	return nil
}

func (m *freebsdManager) Start() error {
	if m.mtu > 0 {
		if err := runBSD("ifconfig", m.name, "mtu", strconv.Itoa(m.mtu)); err != nil {
			return err
		}
	}
	return runBSD("ifconfig", m.name, "up")
}

func (m *freebsdManager) Stop() error {
	return runBSD("ifconfig", m.name, "down")
}

func (m *freebsdManager) Close() error { return m.device.Close() }

func Configure(mgr Manager, opts Options) error {
	if !opts.Configure {
		return nil
	}
	if err := mgr.Start(); err != nil {
		return err
	}
	for _, prefix := range opts.Addresses {
		if err := mgr.AddAddress(prefix); err != nil {
			return err
		}
	}
	for _, prefix := range opts.Routes {
		if err := mgr.AddRoute(prefix); err != nil {
			return err
		}
	}
	if err := mgr.SetDNSServers(opts.DNSServers); err != nil {
		return err
	}
	return nil
}

func runBSD(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func ipv4Netmask(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
}
