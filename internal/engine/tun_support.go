// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/netstackex"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const tunICMPForwardTimeout = 5 * time.Second

var createHostTUNDevice = systemCreateTUNDevice

type hostTUNKernelConfig struct {
	Name      string
	MTU       int
	Addresses []netip.Prefix
	Routes    []netip.Prefix
}

func (e *Engine) startHostTUN(localAddrs []netip.Addr) error {
	e.localAddrs = localAddrs
	if !e.cfg.TUN.Enabled {
		if len(e.cfg.TUN.Up) > 0 || len(e.cfg.TUN.Down) > 0 {
			e.log.Printf("warning: tun up/down scripts are present but tun.enabled is false; commands were not executed")
		}
		return nil
	}
	mtu := e.cfg.TUN.MTU
	if mtu <= 0 {
		mtu = e.cfg.WireGuard.MTU
	}
	stackDev, stackNet, err := netstackex.CreateNetTUN(localAddrs, nil, mtu)
	if err != nil {
		return fmt.Errorf("create host TUN netstack: %w", err)
	}
	defer func() {
		if err != nil {
			_ = stackDev.Close()
		}
	}()
	if err = stackNet.SetPromiscuous(true); err != nil {
		return fmt.Errorf("enable host TUN promiscuous netstack: %w", err)
	}
	if err = stackNet.SetSpoofing(true); err != nil {
		return fmt.Errorf("enable host TUN spoofing netstack: %w", err)
	}
	if err = stackNet.SetTCPReceiveBufferLimit(e.cfg.Inbound.TCPReceiveWindowBytes); err != nil {
		return fmt.Errorf("set host TUN TCP receive buffer limit: %w", err)
	}
	if e.cfg.Inbound.TCPMSSClamp != nil && *e.cfg.Inbound.TCPMSSClamp {
		if err = stackNet.SetTCPMSSClamp(true); err != nil {
			return fmt.Errorf("set host TUN TCP MSS clamping: %w", err)
		}
	}
	stackNet.SetTCPForwarder(e.cfg.Inbound.TCPReceiveWindowBytes, e.tcpForwarderMaxInFlight(), e.handleTUNTCPForward)
	stackNet.SetUDPForwarder(e.handleTUNUDPForward)
	stackNet.SetICMPForwarder(e.handleTUNICMPForward)

	hostDev, err := createHostTUNDevice(e.cfg.TUN.Name, mtu)
	if err != nil {
		return fmt.Errorf("create host TUN %q: %w", e.cfg.TUN.Name, err)
	}
	defer func() {
		if err != nil {
			_ = hostDev.Close()
		}
	}()
	name, nameErr := hostDev.Name()
	if nameErr != nil || name == "" {
		name = e.cfg.TUN.Name
	}
	if e.cfg.TUN.Configure {
		addresses, cfgErr := config.AddressPrefixes(e.cfg.WireGuard.Addresses)
		if cfgErr != nil {
			return cfgErr
		}
		kernelCfg := hostTUNKernelConfig{
			Name:      name,
			MTU:       mtu,
			Addresses: addresses,
			Routes:    e.hostTUNRoutePrefixes(),
		}
		if err = configureHostTUNKernel(kernelCfg); err != nil {
			return fmt.Errorf("configure host TUN %s: %w", name, err)
		}
	}
	e.hostTun = hostDev
	e.hostTunStack = stackDev
	e.hostTunNet = stackNet
	e.hostTunName = name
	if e.cfg.Scripts.Allow {
		for _, cmd := range e.cfg.TUN.Up {
			if err = runShell(cmd); err != nil {
				return fmt.Errorf("tun up %q: %w", cmd, err)
			}
		}
	} else if len(e.cfg.TUN.Up) > 0 || len(e.cfg.TUN.Down) > 0 {
		e.log.Printf("warning: tun up/down scripts are present but scripts.allow is false; commands were not executed")
	}
	go e.pumpTUNPackets("host->tun-netstack", hostDev, stackDev, mtu)
	go e.pumpTUNPackets("tun-netstack->host", stackDev, hostDev, mtu)
	return nil
}

func (e *Engine) pumpTUNPackets(name string, src, dst tun.Device, mtu int) {
	batch := src.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	size := mtu + 128
	if size < 2048 {
		size = 2048
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	for {
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-e.closed:
			default:
				if !isClosedErr(err) {
					e.log.Printf("host TUN pump %s stopped: %v", name, err)
				}
			}
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(bufs[i]) {
				continue
			}
			packet := append([]byte(nil), bufs[i][:sizes[i]]...)
			if _, err := dst.Write([][]byte{packet}, 0); err != nil {
				select {
				case <-e.closed:
				default:
					if !isClosedErr(err) {
						e.log.Printf("host TUN pump %s write failed: %v", name, err)
					}
				}
				return
			}
		}
	}
}

func (e *Engine) handleTUNTCPForward(req *gtcp.ForwarderRequest) {
	id := req.ID()
	src, dst, ok := idAddrs(id)
	if !ok {
		req.Complete(true)
		return
	}
	target, err := e.dialSocketOutbound(context.Background(), "tcp", src, src, dst)
	if err != nil {
		if e.cfg.Log.Verbose {
			e.log.Printf("host TUN tcp %s -> %s failed: %v", src, dst, err)
		}
		req.Complete(true)
		return
	}
	defer target.Close()
	tcpConn, err := netstackex.NewTCPConnFromForwarder(req)
	if err != nil {
		req.Complete(true)
		return
	}
	var app net.Conn = tcpConn
	req.Complete(false)
	defer app.Close()
	proxyBothIdle(app, target, e.tcpIdleTimeout())
}

func (e *Engine) handleTUNUDPForward(req *gudp.ForwarderRequest) {
	id := req.ID()
	src, dst, ok := idAddrs(id)
	if !ok {
		return
	}
	app, err := netstackex.NewUDPConnFromForwarder(req)
	if err != nil {
		return
	}
	target, err := e.dialSocketOutbound(context.Background(), "udp", src, src, dst)
	if err != nil {
		if e.cfg.Log.Verbose {
			e.log.Printf("host TUN udp %s -> %s failed: %v", src, dst, err)
		}
		_ = app.Close()
		return
	}
	go func() {
		defer app.Close()
		defer target.Close()
		proxyUDP(app, target, e.udpIdleTimeout())
	}()
}

func (e *Engine) handleTUNICMPForward(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	src, dst, ok := transportEndpointAddrs(id)
	if !ok {
		return false
	}
	request, isIPv6, ok := inboundICMPEchoRequest(pkt)
	if !ok {
		return false
	}
	go e.forwardTUNICMPEcho(src, dst, request, isIPv6)
	return true
}

func (e *Engine) forwardTUNICMPEcho(src, dst netip.Addr, request []byte, isIPv6 bool) {
	if e.hostTunNet == nil {
		return
	}
	srcAP := netip.AddrPortFrom(src, 0)
	dstAP := netip.AddrPortFrom(dst, 0)
	conn, err := e.dialSocketICMP(srcAP, srcAP, dstAP)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tunICMPForwardTimeout))
	if _, err := conn.Write(request); err != nil {
		return
	}
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	packet := inboundICMPEchoReply(src, dst, request, isIPv6)
	if len(packet) != 0 {
		e.hostTunNet.InjectOutboundPacket(packet)
	}
}

func (e *Engine) hostTUNRoutePrefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	if e.cfg.TUN.RouteAllowedIPs == nil || *e.cfg.TUN.RouteAllowedIPs {
		for _, peer := range e.cfg.WireGuard.Peers {
			for _, raw := range peer.AllowedIPs {
				if p, err := netip.ParsePrefix(raw); err == nil {
					prefixes = append(prefixes, p)
				}
			}
		}
	}
	for _, raw := range e.cfg.TUN.Routes {
		if p, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return reduceRoutePrefixes(prefixes)
}

func reduceRoutePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	clean := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p.IsValid() {
			clean = append(clean, p.Masked())
		}
	}
	sort.Slice(clean, func(i, j int) bool {
		a, b := clean[i], clean[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		return a.String() < b.String()
	})
	out := make([]netip.Prefix, 0, len(clean))
	for _, p := range clean {
		covered := false
		for _, existing := range out {
			if existing.Addr().Is4() == p.Addr().Is4() && existing.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if a.Addr().String() != b.Addr().String() {
			return a.Addr().String() < b.Addr().String()
		}
		return a.Bits() < b.Bits()
	})
	return out
}
