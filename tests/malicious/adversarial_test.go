// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package malicious

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func TestAPIRequiresTokenAndDoesNotExposeSecrets(t *testing.T) {
	privateKey, peerKey, psk := mustKey(t), mustKey(t), mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = privateKey.String()
	cfg.WireGuard.Addresses = []string{"100.90.0.1/32"}
	cfg.WireGuard.Peers = []config.Peer{{
		PublicKey:    peerKey.PublicKey().String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"100.90.0.2/32"},
	}}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "test-token"
	eng := mustStartEngine(t, cfg)

	resp, _ := apiRequest(t, eng.Addr("api"), "", http.MethodGet, "/v1/status", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d, want 401", resp.StatusCode)
	}

	for _, path := range []string{"/v1/status", "/v1/peers"} {
		resp, body := apiRequest(t, eng.Addr("api"), "test-token", http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, resp.StatusCode, body)
		}
		for _, secret := range []string{privateKey.String(), psk.String()} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatalf("%s leaked key material %q in %s", path, secret, body)
			}
		}
	}

	resp, _ = apiRequest(t, eng.Addr("api"), "", http.MethodPut, "/v1/acls", map[string]any{
		"inbound_default":  "deny",
		"outbound_default": "deny",
		"relay_default":    "deny",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API mutation = %d, want 401", resp.StatusCode)
	}
}

func TestMeanSOCKSClientsDoNotHangOrReachForbiddenTargets(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.90.1.1/32", "10.90.0.2/24"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	disabled := false
	cfg.HostForward.Proxy.Enabled = &disabled
	eng := mustStartEngine(t, cfg)

	payloads := [][]byte{
		nil,
		{0x04, 0x01, 0x00},
		{0x05, 0x00},
		{0x05, 0xff},
		{0x05, 0x01, 0x00, 0x05, 0x01, 0xff},
		{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0xff},
		bytes.Repeat([]byte{0x05}, 512),
	}
	for i, payload := range payloads {
		t.Run(fmt.Sprintf("payload-%d", i), func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", eng.Addr("socks5"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := conn.Write(payload); err != nil && len(payload) != 0 {
				t.Fatal(err)
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			_, _ = io.Copy(io.Discard, conn)
		})
	}

	for _, dst := range []netip.AddrPort{
		netip.MustParseAddrPort("100.90.1.1:80"),
		netip.MustParseAddrPort("10.90.0.99:80"),
		netip.MustParseAddrPort("0.1.2.3:80"),
		netip.MustParseAddrPort("224.0.0.1:80"),
		netip.MustParseAddrPort("[fe80::1]:80"),
		netip.MustParseAddrPort("[ff02::1]:80"),
	} {
		if rep := socksConnectReply(t, eng.Addr("socks5"), dst); rep == 0 {
			t.Fatalf("SOCKS CONNECT to forbidden target %s unexpectedly succeeded", dst)
		}
	}
}

func TestHalfOpenSOCKSFloodAndAPIMutation(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.90.2.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "test-token"
	eng := mustStartEngine(t, cfg)

	before := runtime.NumGoroutine()
	dialTimeout := time.Second
	deadline := 500 * time.Millisecond
	if runtime.GOOS == "android" {
		dialTimeout = 3 * time.Second
		deadline = 1500 * time.Millisecond
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", eng.Addr("socks5"), dialTimeout)
			if err != nil {
				t.Errorf("dial half-open %d: %v", i, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(deadline))
			_, _ = conn.Write([]byte{0x05, 0x02})
			time.Sleep(25 * time.Millisecond)
		}(i)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defaultAction := "allow"
			if i%2 == 0 {
				defaultAction = "deny"
			}
			resp, body := apiRequest(t, eng.Addr("api"), "test-token", http.MethodPut, "/v1/acls", map[string]any{
				"inbound_default":  "allow",
				"outbound_default": defaultAction,
				"relay_default":    "deny",
			})
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("ACL mutation status=%d body=%s", resp.StatusCode, body)
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+64 {
		t.Fatalf("goroutine count grew too much after half-open flood: before=%d after=%d", before, after)
	}
}
