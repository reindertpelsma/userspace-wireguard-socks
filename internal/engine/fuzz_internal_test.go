// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func FuzzUDPUnreachablePacket(f *testing.F) {
	for _, seed := range []struct {
		src string
		dst string
	}{
		{"100.64.1.2:12345", "192.0.2.10:53"},
		{"[fd00::2]:12345", "[2001:db8::10]:53"},
		{"127.0.0.1:1", "224.0.0.1:2"},
		{"not-an-addr", "also-bad"},
	} {
		f.Add(seed.src, seed.dst)
	}
	f.Fuzz(func(t *testing.T, srcRaw, dstRaw string) {
		if len(srcRaw) > 256 || len(dstRaw) > 256 {
			t.Skip()
		}
		src, err := netip.ParseAddrPort(srcRaw)
		if err != nil {
			return
		}
		dst, err := netip.ParseAddrPort(dstRaw)
		if err != nil {
			return
		}
		_ = udpUnreachablePacket(src, dst)
	})
}

func FuzzHostedDNSUDPHandler(f *testing.F) {
	for _, seed := range [][]byte{
		{0xff, 0x00, 0x01},
		{},
		validDNSQuerySeed(f, "example.test."),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 4096 {
			packet = packet[:4096]
		}
		oldExchange := systemDNSExchange
		systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			return resp, nil
		}
		defer func() { systemDNSExchange = oldExchange }()

		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		go (&Engine{}).serveTunnelDNSUDP(pc)

		c, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = c.Write(packet)
		_, _ = c.Read(make([]byte, 1500))
	})
}

func validDNSQuerySeed(t testing.TB, name string) []byte {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	packet, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
