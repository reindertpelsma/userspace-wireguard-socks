// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/netstackex"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	hosttun "github.com/reindertpelsma/userspace-wireguard-socks/internal/tun"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustKeyForTUNTest(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestReduceRoutePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("172.18.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("10.1.2.0/24"),
		netip.MustParsePrefix("fd00:1::/64"),
		netip.MustParsePrefix("fd00::/16"),
	}
	got := reduceRoutePrefixes(in)
	want := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("fd00::/16"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reduced prefixes mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestHostTUNOutboundTCPThroughFallbackDirect(t *testing.T) {
	hostIP := testHostIPv4(t)
	ln := listenTCP4ForTUNTest(t)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	hostTun := newFakeTUNDevice("uwgtest0", 1420)
	oldCreate := createHostTUNManager
	createHostTUNManager = func(opts hosttun.Options) (hosttun.Manager, error) {
		if opts.Name != "uwgtest0" || opts.MTU != 1420 {
			t.Fatalf("createHostTUNManager(%q, %d), want uwgtest0/1420", opts.Name, opts.MTU)
		}
		return newFakeHostTUNManager(hostTun), nil
	}
	t.Cleanup(func() { createHostTUNManager = oldCreate })

	cfg := config.Default()
	cfg.WireGuard.Addresses = []string{"100.64.10.1/32"}
	cfg.TUN.Enabled = true
	cfg.TUN.Name = "uwgtest0"
	dropIPv4Invalid := false
	cfg.Filtering.DropIPv4Invalid = &dropIPv4Invalid
	cfg.Log.Verbose = true
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	eng, err := New(cfg, log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.startHostTUN([]netip.Addr{netip.MustParseAddr("100.64.10.1")}); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	appDev, appNet, err := netstackex.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.10.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer appDev.Close()
	stopBridge := bridgeAppNetstackToFakeTUN(t, appDev, hostTun, 1420)
	defer stopBridge()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	conn, err := appNet.DialContext(ctx, "tcp", net.JoinHostPort(hostIP.String(), port))
	if err != nil {
		t.Log(logs.String())
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("tun outbound tcp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("tun outbound tcp"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tun outbound tcp" {
		t.Fatalf("unexpected echo %q", buf)
	}
}

func TestHostTUNOutboundTCPIPv6ThroughFallbackDirect(t *testing.T) {
	hostIP := testHostIPv6(t)
	ln := listenTCP6ForTUNTest(t)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	hostTun := newFakeTUNDevice("uwgtest6", 1280)
	oldCreate := createHostTUNManager
	createHostTUNManager = func(opts hosttun.Options) (hosttun.Manager, error) {
		if opts.Name != "uwgtest6" || opts.MTU != 1280 {
			t.Fatalf("createHostTUNManager(%q, %d), want uwgtest6/1280", opts.Name, opts.MTU)
		}
		return newFakeHostTUNManager(hostTun), nil
	}
	t.Cleanup(func() { createHostTUNManager = oldCreate })

	cfg := config.Default()
	cfg.WireGuard.Addresses = []string{"fd00:10::1/128"}
	cfg.WireGuard.MTU = 1280
	cfg.TUN.Enabled = true
	cfg.TUN.Name = "uwgtest6"
	cfg.TUN.MTU = 1280
	cfg.Log.Verbose = true
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	eng, err := New(cfg, log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.startHostTUN([]netip.Addr{netip.MustParseAddr("fd00:10::1")}); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	appDev, appNet, err := netstackex.CreateNetTUN([]netip.Addr{netip.MustParseAddr("fd00:10::1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer appDev.Close()
	stopBridge := bridgeAppNetstackToFakeTUN(t, appDev, hostTun, 1280)
	defer stopBridge()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	conn, err := appNet.DialContext(ctx, "tcp", net.JoinHostPort(hostIP.String(), port))
	if err != nil {
		t.Log(logs.String())
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("tun outbound tcp6")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("tun outbound tcp6"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tun outbound tcp6" {
		t.Fatalf("unexpected echo %q", buf)
	}
}

func listenTCP6ForTUNTest(t *testing.T) net.Listener {
	t.Helper()
	for port := 18120; port < 18160; port++ {
		ln, err := net.Listen("tcp6", net.JoinHostPort("::", strconv.Itoa(port)))
		if err == nil {
			return ln
		}
	}
	ln, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 listen unavailable: %v", err)
	}
	return ln
}

func listenTCP4ForTUNTest(t *testing.T) net.Listener {
	t.Helper()
	for port := 18080; port < 18120; port++ {
		ln, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err == nil {
			return ln
		}
	}
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func bridgeAppNetstackToFakeTUN(t *testing.T, appDev tun.Device, fake *fakeTUNDevice, mtu int) func() {
	t.Helper()
	const tunPacketOffset = 4
	done := make(chan struct{})
	go func() {
		buf := [][]byte{make([]byte, mtu+128+tunPacketOffset)}
		sizes := make([]int, 1)
		for {
			n, err := appDev.Read(buf, sizes, tunPacketOffset)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				packet := append([]byte(nil), buf[i][tunPacketOffset:tunPacketOffset+sizes[i]]...)
				select {
				case fake.incoming <- packet:
				case <-done:
					return
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case packet := <-fake.outgoing:
				buf := make([]byte, tunPacketOffset+len(packet))
				copy(buf[tunPacketOffset:], packet)
				_, _ = appDev.Write([][]byte{buf}, tunPacketOffset)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

func testHostIPv6(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is6() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("no non-loopback IPv6 address available for host TUN fallback test")
	return netip.Addr{}
}

func testHostIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is4() && !ip.IsLoopback() {
				return ip
			}
		}
	}
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		defer c.Close()
		if udp, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(udp.IP); ok && ip.Is4() && !ip.IsLoopback() {
				return ip.Unmap()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address available for host TUN fallback test")
	return netip.Addr{}
}

type fakeTUNDevice struct {
	name      string
	mtu       int
	incoming  chan []byte
	outgoing  chan []byte
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeTUNDevice(name string, mtu int) *fakeTUNDevice {
	d := &fakeTUNDevice{
		name:     name,
		mtu:      mtu,
		incoming: make(chan []byte, 1024),
		outgoing: make(chan []byte, 1024),
		events:   make(chan tun.Event, 2),
		closed:   make(chan struct{}),
	}
	d.events <- tun.EventUp
	return d
}

func (d *fakeTUNDevice) File() *os.File { return nil }

func (d *fakeTUNDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-d.incoming:
		if len(bufs) == 0 || len(sizes) == 0 || len(bufs[0]) < offset+len(packet) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *fakeTUNDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if len(buf) < offset {
			continue
		}
		packet := append([]byte(nil), buf[offset:]...)
		select {
		case d.outgoing <- packet:
		case <-d.closed:
			return 0, net.ErrClosed
		}
	}
	return len(bufs), nil
}

func (d *fakeTUNDevice) MTU() (int, error) { return d.mtu, nil }

func (d *fakeTUNDevice) Name() (string, error) { return d.name, nil }

func (d *fakeTUNDevice) Events() <-chan tun.Event { return d.events }

func (d *fakeTUNDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.events)
	})
	return nil
}

func (d *fakeTUNDevice) BatchSize() int { return 1 }

type fakeHostTUNManager struct {
	dev tun.Device
}

func newFakeHostTUNManager(dev tun.Device) *fakeHostTUNManager {
	return &fakeHostTUNManager{dev: dev}
}

func (m *fakeHostTUNManager) Device() tun.Device { return m.dev }
func (m *fakeHostTUNManager) Name() string {
	name, _ := m.dev.Name()
	return name
}
func (m *fakeHostTUNManager) LocalAddrs() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
}
func (m *fakeHostTUNManager) AddAddress(netip.Prefix) error    { return nil }
func (m *fakeHostTUNManager) RemoveAddress(netip.Prefix) error { return nil }
func (m *fakeHostTUNManager) AddRoute(netip.Prefix) error      { return nil }
func (m *fakeHostTUNManager) RemoveRoute(netip.Prefix) error   { return nil }
func (m *fakeHostTUNManager) SetDNSServers([]netip.Addr) error { return nil }
func (m *fakeHostTUNManager) ClearDNSServers() error           { return nil }
func (m *fakeHostTUNManager) Start() error                     { return nil }
func (m *fakeHostTUNManager) Stop() error                      { return nil }
func (m *fakeHostTUNManager) BypassDialer(bool, netip.Prefix) transport.ProxyDialer {
	return transport.NewDirectDialer(false, netip.Prefix{})
}
func (m *fakeHostTUNManager) Close() error { return m.dev.Close() }

// TestMTUConfigDefaults verifies that wireguard.mtu defaults to 1420 and that
// tun.mtu inherits wireguard.mtu when not explicitly set.
func TestMTUConfigDefaults(t *testing.T) {
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKeyForTUNTest(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.0.1/32"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.MTU != 1420 {
		t.Errorf("wireguard.mtu default = %d, want 1420", cfg.WireGuard.MTU)
	}
	if cfg.TUN.MTU != 1420 {
		t.Errorf("tun.mtu should inherit wireguard.mtu: got %d, want 1420", cfg.TUN.MTU)
	}
}

// TestMTUCustomPropagation verifies that a custom wireguard.mtu is passed to
// the host TUN manager and that tun.mtu inherits it.
func TestMTUCustomPropagation(t *testing.T) {
	const customMTU = 1300

	var gotMTU int
	oldCreate := createHostTUNManager
	createHostTUNManager = func(opts hosttun.Options) (hosttun.Manager, error) {
		gotMTU = opts.MTU
		return newFakeHostTUNManager(newFakeTUNDevice(opts.Name, opts.MTU)), nil
	}
	t.Cleanup(func() { createHostTUNManager = oldCreate })

	dropIPv4Invalid := false
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKeyForTUNTest(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.0.1/32"}
	cfg.WireGuard.MTU = customMTU
	cfg.TUN.Enabled = true
	cfg.TUN.Name = "uwgmtutest"
	cfg.Filtering.DropIPv4Invalid = &dropIPv4Invalid
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.TUN.MTU != customMTU {
		t.Errorf("tun.mtu after Normalize = %d, want %d", cfg.TUN.MTU, customMTU)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.startHostTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if gotMTU != customMTU {
		t.Errorf("createHostTUNManager received MTU %d, want %d", gotMTU, customMTU)
	}
}

// TestMTUDefaultTCPMSSClamp confirms that inbound.tcp_mss_clamp defaults to
// true after config normalization. The packet-level MSS rewriting is covered
// by the netstackex unit tests (TestClampMSS_*); this test guards the config
// path so the default cannot silently regress.
func TestMTUDefaultTCPMSSClamp(t *testing.T) {
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKeyForTUNTest(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.0.1/32"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.Inbound.TCPMSSClamp == nil || !*cfg.Inbound.TCPMSSClamp {
		t.Error("inbound.tcp_mss_clamp should default to true after Normalize")
	}
}

// TestHostTUNTCPMSSClampFunctional verifies that TCP connections work
// end-to-end through the host TUN stack when MSS clamping is explicitly
// enabled at a low MTU. Guards against MSS rewriting accidentally breaking TCP.
func TestHostTUNTCPMSSClampFunctional(t *testing.T) {
	hostIP := testHostIPv4(t)
	ln := listenTCP4ForTUNTest(t)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	const clampMTU = 1300
	hostTun := newFakeTUNDevice("uwgmsstest", clampMTU)
	oldCreate := createHostTUNManager
	createHostTUNManager = func(opts hosttun.Options) (hosttun.Manager, error) {
		return newFakeHostTUNManager(hostTun), nil
	}
	t.Cleanup(func() { createHostTUNManager = oldCreate })

	mssClamp := true
	dropIPv4Invalid := false
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKeyForTUNTest(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.11.1/32"}
	cfg.WireGuard.MTU = clampMTU
	cfg.TUN.Enabled = true
	cfg.TUN.Name = "uwgmsstest"
	cfg.TUN.MTU = clampMTU
	cfg.Inbound.TCPMSSClamp = &mssClamp
	cfg.Filtering.DropIPv4Invalid = &dropIPv4Invalid
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.startHostTUN([]netip.Addr{netip.MustParseAddr("100.64.11.1")}); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	appDev, appNet, err := netstackex.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.11.1")}, nil, clampMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer appDev.Close()
	stopBridge := bridgeAppNetstackToFakeTUN(t, appDev, hostTun, clampMTU)
	defer stopBridge()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	conn, err := appNet.DialContext(ctx, "tcp", net.JoinHostPort(hostIP.String(), port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	const msg = "mss-clamp-functional"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read with MSS clamp on: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}
