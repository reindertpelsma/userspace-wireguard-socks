// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestHostedDNSDropsMalformedUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	e := &Engine{}
	go e.serveTunnelDNSUDP(pc)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0xff, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("malformed DNS unexpectedly produced %d response bytes", n)
	}
}

func TestHostedDNSLimitsInflightUDPTransactions(t *testing.T) {
	oldExchange := systemDNSExchange
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		entered <- struct{}{}
		<-release
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, nil
	}
	defer func() {
		close(release)
		systemDNSExchange = oldExchange
	}()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	e := &Engine{dnsSem: make(chan struct{}, 2)}
	go e.serveTunnelDNSUDP(pc)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, id := range []uint16{1, 2} {
		if _, err := c.Write(packDNSQuery(t, id, "hold.test.")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for DNS transaction to enter blocked resolver")
		}
	}

	if _, err := c.Write(packDNSQuery(t, 3, "refused.test.")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var buf [512]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	var resp dns.Msg
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if resp.Id != 3 || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("overflow DNS response = id %d rcode %d, want id 3 REFUSED", resp.Id, resp.Rcode)
	}
}

func TestConfiguredDNSDoesNotFallbackToSystem(t *testing.T) {
	cfg := config.Default()
	cfg.WireGuard.DNS = []string{"192.0.2.1"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if addrs, err := e.lookupHost(ctx, "localhost"); err == nil {
		t.Fatalf("configured DNS unexpectedly fell back to system resolver: %v", addrs)
	}
}

func packDNSQuery(t testing.TB, id uint16, name string) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Id = id
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func TestHostedDNSOverWireGuardUDPAndTCP(t *testing.T) {
	// Race reports under macOS+race here are the same gvisor
	// pkg/buffer.viewPool reuse pattern as TestRelayForwardingMultiPeer.
	// Suppressed at the repo level via .gorace.suppressions — see
	// the file for rationale and upstream-tracking notes.
	oldExchange := systemDNSExchange
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			if q.Name == "egress.test." && q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.IPv4(198, 51, 100, 7),
				})
			}
		}
		return resp, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	serverKey, clientKey := mustDNSKey(t), mustDNSKey(t)
	serverPort := freeDNSUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.55.1/32"}
	serverCfg.DNSServer.Listen = "100.64.55.1:53"
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.55.2/32"},
	}}
	server := mustStartDNSEngine(t, serverCfg)
	defer server.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.55.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.55.1/32"},
		PersistentKeepalive: 1,
	}}
	client := mustStartDNSEngine(t, clientCfg)
	defer client.Close()

	target := netip.MustParseAddrPort("100.64.55.1:53")
	udpConn, err := client.DialUDP(netip.AddrPort{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	resp := exchangeTestDNSUDP(t, udpConn, "egress.test.", dns.TypeA)
	assertDNSA(t, resp, "egress.test.", net.IPv4(198, 51, 100, 7))

	if _, err := udpConn.Write([]byte{0xff, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := udpConn.Read(make([]byte, 512)); err == nil {
		t.Fatalf("malformed tunnel DNS unexpectedly produced %d response bytes", n)
	}

	tcpConn := retryDNSTCPDial(t, client, "100.64.55.1:53")
	defer tcpConn.Close()
	dc := &dns.Conn{Conn: tcpConn}
	req := new(dns.Msg)
	req.SetQuestion("egress.test.", dns.TypeA)
	if err := dc.WriteMsg(req); err != nil {
		t.Fatal(err)
	}
	resp, err = dc.ReadMsg()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("TCP DNS transaction ID mismatch: got %d want %d", resp.Id, req.Id)
	}
	assertDNSA(t, resp, "egress.test.", net.IPv4(198, 51, 100, 7))

	badTCP := retryDNSTCPDial(t, client, "100.64.55.1:53")
	defer badTCP.Close()
	if _, err := badTCP.Write([]byte{0, 3, 0xff, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = badTCP.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := badTCP.Read(make([]byte, 512)); err == nil {
		t.Fatalf("malformed TCP tunnel DNS unexpectedly produced %d response bytes", n)
	}
}

func exchangeTestDNSUDP(t *testing.T, conn net.Conn, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	packed, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(packed); err != nil {
			last = err
			continue
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			last = err
			continue
		}
		var resp dns.Msg
		if err := resp.Unpack(buf[:n]); err != nil {
			last = err
			continue
		}
		if resp.Id == req.Id {
			return &resp
		}
	}
	t.Fatalf("DNS UDP exchange failed: %v", last)
	return nil
}

func assertDNSA(t *testing.T, msg *dns.Msg, name string, want net.IP) {
	t.Helper()
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if ok && a.Hdr.Name == name && a.A.Equal(want) {
			return
		}
	}
	t.Fatalf("DNS response missing A %s -> %s: %+v", name, want, msg.Answer)
}

func retryDNSTCPDial(t *testing.T, e *Engine, addr string) net.Conn {
	t.Helper()
	var last error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := e.DialTunnelContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			return conn
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP DNS dial failed: %v", last)
	return nil
}

func mustStartDNSEngine(t *testing.T, cfg config.Config) *Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	return eng
}

func mustDNSKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeDNSUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
