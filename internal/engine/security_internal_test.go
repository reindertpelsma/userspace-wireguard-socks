// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMarkPacketECNRejectsShortIPv4OptionsHeader(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x46 // IPv4 with IHL=6 (24-byte header expected)
	packet[1] = 0x03 // ECN-capable
	if markPacketECN(packet) {
		t.Fatal("markPacketECN unexpectedly accepted a truncated IPv4 options header")
	}
}

func TestServeSOCKSConnTimesOutAfterHandshakeBeforeRequest(t *testing.T) {
	oldDeadline := socksRequestDeadline
	socksRequestDeadline = 40 * time.Millisecond
	defer func() { socksRequestDeadline = oldDeadline }()

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		(&Engine{}).serveSOCKSConn(server)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if reply != [2]byte{0x05, 0x00} {
		t.Fatalf("handshake reply = %v, want [5 0]", reply)
	}

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	if _, err := client.Read(buf); err == nil {
		// The server writes a general-failure reply before closing. Getting data
		// here is fine; the important part is that the goroutine terminates.
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SOCKS connection did not time out after a completed handshake stall")
	}
}

func TestAPIAuthUsesUpdatedToken(t *testing.T) {
	e := &Engine{cfg: config.Default()}
	e.cfg.API.Token = "old-token"

	called := false
	h := e.apiAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	e.cfg.API.Token = "new-token"

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("Authorization", "Bearer new-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("new token rejected: status=%d called=%v", rec.Code, called)
	}

	called = false
	req = httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("Authorization", "Bearer old-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("old token unexpectedly accepted: status=%d called=%v", rec.Code, called)
	}
}

func TestSocketSessionUDPPeerLimit(t *testing.T) {
	oldLimit := maxSocketUDPPeers
	maxSocketUDPPeers = 2
	defer func() { maxSocketUDPPeers = oldLimit }()

	ss := &socketSession{}
	if !ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.1:10001"), time.Hour) {
		t.Fatal("first UDP peer was unexpectedly rejected")
	}
	if !ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.2:10002"), time.Hour) {
		t.Fatal("second UDP peer was unexpectedly rejected")
	}
	if ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.3:10003"), time.Hour) {
		t.Fatal("third UDP peer unexpectedly bypassed the per-session limit")
	}

	ss.udpMu.Lock()
	defer ss.udpMu.Unlock()
	if len(ss.udpPeers) != 2 {
		t.Fatalf("udp peer table size = %d, want 2", len(ss.udpPeers))
	}
	for _, state := range ss.udpPeers {
		if state.timer != nil {
			state.timer.Stop()
		}
	}
}

func TestSocketProtocolDNSFrameHonorsInflightLimit(t *testing.T) {
	oldExchange := systemDNSExchange
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		t.Fatal("socket API DNS path should refuse when dnsSem is exhausted")
		return nil, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	eng := &Engine{dnsSem: make(chan struct{}, 1)}
	eng.dnsSem <- struct{}{}

	server, client := net.Pipe()
	defer client.Close()
	go eng.serveSocketProtocol(server, netip.AddrPort{})

	req := new(dns.Msg)
	req.SetQuestion("limit.test.", dns.TypeA)
	payload, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(client, socketproto.Frame{ID: socketproto.ClientIDBase + 7, Action: socketproto.ActionDNS, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := socketproto.ReadFrame(client, socketproto.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Action != socketproto.ActionDNS {
		t.Fatalf("DNS frame action = %d, want %d", frame.Action, socketproto.ActionDNS)
	}
	var resp dns.Msg
	if err := resp.Unpack(frame.Payload); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("DNS overflow rcode = %d, want REFUSED", resp.Rcode)
	}
}

func TestHTTPProxyClosesIdleIncompleteRequest(t *testing.T) {
	oldReadHeader := proxyHTTPReadHeaderTimeout
	oldRead := proxyHTTPReadTimeout
	oldWrite := proxyHTTPWriteTimeout
	oldIdle := proxyHTTPIdleTimeout
	proxyHTTPReadHeaderTimeout = 40 * time.Millisecond
	proxyHTTPReadTimeout = 40 * time.Millisecond
	proxyHTTPWriteTimeout = 200 * time.Millisecond
	proxyHTTPIdleTimeout = 40 * time.Millisecond
	defer func() {
		proxyHTTPReadHeaderTimeout = oldReadHeader
		proxyHTTPReadTimeout = oldRead
		proxyHTTPWriteTimeout = oldWrite
		proxyHTTPIdleTimeout = oldIdle
	}()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", eng.Addr("http"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		return
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle incomplete HTTP request unexpectedly stayed open")
	}
}

func TestAPIResolveReturnsDNSMessage(t *testing.T) {
	oldExchange := systemDNSExchange
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "resolve.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.ParseIP("203.0.113.10"),
		})
		return resp, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.96.1/32"}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}

	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion("resolve.test.", dns.TypeA)
	payload, err := reqMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+eng.Addr("api")+"/v1/resolve", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("resolve status = %d body=%q", resp.StatusCode, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Fatalf("content-type = %q, want application/dns-message", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var dnsResp dns.Msg
	if err := dnsResp.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if len(dnsResp.Answer) != 1 {
		t.Fatalf("DNS answer count = %d, want 1", len(dnsResp.Answer))
	}
}

func TestProxyResolveRequiresAndAcceptsBasicAuth(t *testing.T) {
	oldExchange := systemDNSExchange
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "proxy.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30},
			Txt: []string{"through proxy auth"},
		})
		return resp, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.Proxy.Username = "alice"
	cfg.Proxy.Password = "secret"
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.96.1/32"}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}

	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion("proxy.test.", dns.TypeTXT)
	payload, err := reqMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + eng.Addr("http") + "/uwg/resolve"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("unauthenticated resolve status = %d body=%q", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authenticated resolve status = %d body=%q", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var dnsResp dns.Msg
	if err := dnsResp.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if len(dnsResp.Answer) != 1 {
		t.Fatalf("DNS answer count = %d, want 1", len(dnsResp.Answer))
	}
}

func TestProxyCredentialsOptionalUsername(t *testing.T) {
	cases := []struct {
		name     string
		cfgUser  string
		cfgPass  string
		gotUser  string
		gotPass  string
		expectOK bool
	}{
		{name: "no auth configured allows anything", expectOK: true},
		{name: "no auth configured ignores supplied creds", gotUser: "x", gotPass: "y", expectOK: true},

		{name: "username+password both required (good)", cfgUser: "u", cfgPass: "p", gotUser: "u", gotPass: "p", expectOK: true},
		{name: "username+password both required (wrong user)", cfgUser: "u", cfgPass: "p", gotUser: "v", gotPass: "p", expectOK: false},
		{name: "username+password both required (wrong pass)", cfgUser: "u", cfgPass: "p", gotUser: "u", gotPass: "q", expectOK: false},

		{name: "password-only accepts any username", cfgPass: "p", gotUser: "anything", gotPass: "p", expectOK: true},
		{name: "password-only accepts empty username", cfgPass: "p", gotUser: "", gotPass: "p", expectOK: true},
		{name: "password-only rejects wrong password", cfgPass: "p", gotUser: "anything", gotPass: "wrong", expectOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{cfg: config.Config{Proxy: config.Proxy{Username: tc.cfgUser, Password: tc.cfgPass}}}
			if got := e.proxyCredentialsOK(tc.gotUser, tc.gotPass); got != tc.expectOK {
				t.Fatalf("proxyCredentialsOK(user=%q,pass=%q) = %v, want %v", tc.gotUser, tc.gotPass, got, tc.expectOK)
			}
		})
	}
}

func TestTunnelDNSTCPClosesIdleClient(t *testing.T) {
	oldDeadline := tunnelDNSTCPDeadline.Load()
	tunnelDNSTCPDeadline.Store(int64(40 * time.Millisecond))
	defer tunnelDNSTCPDeadline.Store(oldDeadline)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go (&Engine{}).serveTunnelDNSTCP(ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("idle DNS TCP connection unexpectedly stayed open")
	}
}
