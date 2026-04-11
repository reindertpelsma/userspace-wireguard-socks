// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

func TestSocketProtocolDNSFrameUsesTCPFallback(t *testing.T) {
	oldExchange := systemDNSExchange
	var sawUDP, sawTCP bool
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if !tcp {
			sawUDP = true
			resp.Truncated = true
			return resp, nil
		}
		sawTCP = true
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "large.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30},
			Txt: []string{"this response came from tcp fallback"},
		})
		return resp, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	server, client := net.Pipe()
	defer client.Close()
	go (&Engine{}).serveSocketProtocol(server, netip.AddrPort{})

	req := new(dns.Msg)
	req.SetQuestion("large.test.", dns.TypeTXT)
	payload, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(client, socketproto.Frame{ID: socketproto.ClientIDBase + 99, Action: socketproto.ActionDNS, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := socketproto.ReadFrame(client, socketproto.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Action != socketproto.ActionDNS {
		t.Fatalf("DNS frame action = %d payload %q", frame.Action, frame.Payload)
	}
	var resp dns.Msg
	if err := resp.Unpack(frame.Payload); err != nil {
		t.Fatal(err)
	}
	if !sawUDP || !sawTCP {
		t.Fatalf("DNS fallback calls: udp=%v tcp=%v", sawUDP, sawTCP)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("DNS response missing TCP fallback answer: %+v", resp.Answer)
	}
}
