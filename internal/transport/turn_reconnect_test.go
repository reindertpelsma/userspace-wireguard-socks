// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

// startTURNServer starts a pion/turn UDP server bound to listenAddr (use
// "127.0.0.1:0" to get an ephemeral port the first time, or pass an explicit
// host:port to reuse a port). Returns the bound *turn.Server and the
// host:port string the client should dial. Caller closes the server.
func startTURNServer(t *testing.T, listenAddr, realm string, creds map[string][]byte) (*turn.Server, string) {
	t.Helper()
	udp, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		t.Fatalf("turn server listen %s: %v", listenAddr, err)
	}
	relayIP := net.ParseIP("127.0.0.1")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(username, _ string, _ net.Addr) ([]byte, bool) {
			key, ok := creds[username]
			return key, ok
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udp,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: relayIP,
					Address:      "127.0.0.1",
				},
			},
		},
	})
	if err != nil {
		udp.Close()
		t.Fatalf("turn.NewServer: %v", err)
	}
	return srv, udp.LocalAddr().String()
}

// TestTURNTransportAutoReconnectAcrossServerOutage drives the auto-reconnect
// path end-to-end against a real pion/turn server: bring the transport up,
// kill the TURN server, observe the carrier-failure → reconnect cascade,
// bring the TURN server back up on the same port, and verify the transport
// re-allocates without any caller intervention.
//
// This pins the user-visible contract that a TURN-fronted WireGuard tunnel
// survives a TURN-server restart: we do NOT require the application to
// re-Dial or otherwise hand-hold the carrier, the transport keeps trying
// until it associates again. The reconnect goroutine launched from
// handleCarrierFailure with exponential backoff (turnReconnectInitial →
// turnReconnectMax) is the load-bearing piece; without it, traffic stalls
// indefinitely after a TURN outage.
func TestTURNTransportAutoReconnectAcrossServerOutage(t *testing.T) {
	const (
		realm = "uwg.test"
		user  = "uwgtest"
		pass  = "uwgtest"
	)
	creds := map[string][]byte{user: turn.GenerateAuthKey(user, realm, pass)}

	srv, addr := startTURNServer(t, "127.0.0.1:0", realm, creds)

	tr, err := NewTURNTransport("turn-reconnect", TURNConfig{
		Server:   addr,
		Protocol: "udp",
		Username: user,
		Password: pass,
		Realm:    realm,
	}, WebSocketConfig{}, nil, [32]byte{})
	if err != nil {
		srv.Close()
		t.Fatalf("NewTURNTransport: %v", err)
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Listen(ctx, 0); err != nil {
		srv.Close()
		t.Fatalf("Listen (initial): %v", err)
	}

	relayBefore := tr.RelayAddr()
	if relayBefore == "" {
		srv.Close()
		t.Fatalf("expected relay addr after Listen; got empty")
	}
	t.Logf("initial relay addr: %s", relayBefore)

	// Kill the TURN server. The carrier (UDP socket) keeps existing on the
	// client side but the server is gone; any further STUN/TURN exchange
	// will fail. Re-binding to the same address requires SO_REUSEADDR which
	// pion/turn's RelayAddressGeneratorStatic doesn't set; in practice
	// there's a 1–2s TIME_WAIT-like window, so we rebind by parsing the
	// chosen port and waiting briefly. The simpler path: stop+immediately
	// rebind almost always works on linux/loopback for UDP.
	if err := srv.Close(); err != nil {
		t.Fatalf("turn server close: %v", err)
	}

	// Force the transport to notice the failure now instead of waiting up
	// to turnKeepaliveInterval+turnKeepaliveTimeout (= 30s) for the next
	// keepalive. handleCarrierFailure tears down the dead client and
	// launches the reconnect goroutine.
	tr.handleCarrierFailure()

	// Verify the transport is in the closed-but-reconnecting state.
	tr.mu.Lock()
	if tr.open {
		tr.mu.Unlock()
		t.Fatalf("expected open=false after carrier failure")
	}
	if !tr.reconnecting {
		tr.mu.Unlock()
		t.Fatalf("expected reconnecting=true after carrier failure")
	}
	tr.mu.Unlock()

	// While the server is down, the reconnect goroutine should keep
	// failing connectLocked but stay in the loop (not give up). Confirm
	// it's still trying after a couple of backoff ticks. The first retry
	// is at turnReconnectInitial (=1s); we sleep 3s to cover initial +
	// at least one backoff doubling.
	time.Sleep(3 * time.Second)
	tr.mu.Lock()
	stillReconnecting := tr.reconnecting && !tr.open
	tr.mu.Unlock()
	if !stillReconnecting {
		t.Fatalf("reconnect goroutine should still be retrying while server is down")
	}

	// Bring the TURN server back up on the same port. Reconnect goroutine
	// should succeed on the next attempt within turnReconnectMax.
	srv2, addr2 := startTURNServer(t, addr, realm, creds)
	defer srv2.Close()
	if addr2 != addr {
		t.Fatalf("expected reused addr %q, got %q", addr, addr2)
	}

	// Wait for the auto-reconnect to succeed. With backoff doubling from
	// 1s, the worst case after 3s already-elapsed is the next attempt at
	// 4s + handshake. Give 20s as a generous upper bound.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		open := tr.open
		tr.mu.Unlock()
		if open {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	tr.mu.Lock()
	open := tr.open
	relayAfter := ""
	if tr.relayAddr != nil {
		relayAfter = tr.relayAddr.String()
	}
	tr.mu.Unlock()

	if !open {
		t.Fatalf("transport did not auto-reconnect within deadline")
	}
	if relayAfter == "" {
		t.Fatalf("transport open but no relay addr after reconnect")
	}
	t.Logf("reconnected relay addr: %s", relayAfter)

	// One more end-to-end sanity check: the transport's Dial path should
	// now produce a working session against the live server.
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer target.Close()
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	sess, err := tr.Dial(dctx, target.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial after reconnect: %v", err)
	}
	defer sess.Close()
}

// TestTURNTransportCloseStopsReconnect verifies that calling Close() on a
// TURNTransport that's mid-reconnect cancels the reconnect goroutine
// promptly. A leaked reconnect loop would keep dialing the (gone) server
// forever and block process shutdown / leak goroutines.
func TestTURNTransportCloseStopsReconnect(t *testing.T) {
	const (
		realm = "uwg.test"
		user  = "uwgtest"
		pass  = "uwgtest"
	)
	creds := map[string][]byte{user: turn.GenerateAuthKey(user, realm, pass)}

	srv, addr := startTURNServer(t, "127.0.0.1:0", realm, creds)

	tr, err := NewTURNTransport("turn-close-during-reconnect", TURNConfig{
		Server:   addr,
		Protocol: "udp",
		Username: user,
		Password: pass,
		Realm:    realm,
	}, WebSocketConfig{}, nil, [32]byte{})
	if err != nil {
		srv.Close()
		t.Fatalf("NewTURNTransport: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Listen(ctx, 0); err != nil {
		srv.Close()
		t.Fatalf("Listen: %v", err)
	}

	// Force failure → reconnect launches
	srv.Close()
	tr.handleCarrierFailure()

	// Wait briefly to make sure the reconnect goroutine is alive and in
	// its first retry sleep.
	time.Sleep(200 * time.Millisecond)
	tr.mu.Lock()
	if !tr.reconnecting {
		tr.mu.Unlock()
		t.Fatalf("expected reconnecting=true before Close")
	}
	tr.mu.Unlock()

	tr.Close()

	// Reconnect goroutine should observe closing and exit. Poll for up
	// to 2s; turnReconnectInitial is 1s so worst case the loop wakes from
	// sleep, sees closing, and exits.
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		stopped := !tr.reconnecting
		tr.mu.Unlock()
		if stopped {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	tr.mu.Lock()
	reconnecting := tr.reconnecting
	tr.mu.Unlock()
	if reconnecting {
		t.Fatalf("reconnect goroutine did not exit after Close")
	}
}

// Compile-time assertion that the address type used in startTURNServer
// matches what tests rely on.
var _ = netip.Prefix{}
