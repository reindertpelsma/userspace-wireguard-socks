// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// TestTransportConformanceMatrix is the unified round-trip matrix called for in
// docs/internal/uwgsocks-coverage-audit.md (priority #3). Each transport gets a
// fresh listener+dialer pair, the same payload set is exchanged client→server
// and server→client, and the listener closes cleanly. Adding a new transport
// means appending a row to the table; the per-transport tests in bind_test.go
// stay as the place for transport-specific quirks (TLS SNI, large packets,
// HTTP/3 advertisement, etc).
//
// The matrix is the only test that asserts every production transport carries
// a packet under the same harness — so a regression that silently breaks one
// transport (a refactor that misroutes a context, a protocol-version bump that
// only the bespoke test covers) shows up here.
func TestTransportConformanceMatrix(t *testing.T) {
	t.Parallel()

	type transportPair struct {
		server transport.Transport
		client transport.Transport
	}

	// Each factory returns a (server, client) Transport pair. Some transports
	// (TCP/TLS/DTLS/WebSocket) use one Transport for both ends; QUIC and the
	// WebSocket-over-TLS variant need separate ends with different TLS configs,
	// so the factory shape accommodates both.
	//
	// UDP is intentionally omitted: UDP listener sessions are one-packet-by-
	// design (each datagram is its own session, matching WireGuard's per-packet
	// model), so the "one accept → many round-trips" shape doesn't apply. UDP
	// is covered separately by TestBindRoamingAcrossTransports and the
	// engine-level integration tests that exercise the per-packet path.
	cases := []struct {
		name        string
		make        func(t *testing.T) transportPair
		bidi        bool // exercise server→client direction in addition to client→server
		dialTimeout time.Duration
	}{
		{
			name: "tcp",
			make: func(t *testing.T) transportPair {
				tr := transport.NewTCPTransport("tcp-conf", loopbackDialer{}, []string{"127.0.0.1"})
				return transportPair{server: tr, client: tr}
			},
			bidi: true,
		},
		{
			name: "tls",
			make: func(t *testing.T) transportPair {
				certMgr := &transport.CertManager{}
				if err := certMgr.Start(); err != nil {
					t.Fatal(err)
				}
				tr := transport.NewTLSTransport("tls-conf", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})
				return transportPair{server: tr, client: tr}
			},
			bidi: true,
		},
		{
			name: "dtls",
			make: func(t *testing.T) transportPair {
				certMgr := &transport.CertManager{}
				if err := certMgr.Start(); err != nil {
					t.Fatal(err)
				}
				tr := transport.NewDTLSTransport("dtls-conf", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})
				return transportPair{server: tr, client: tr}
			},
			bidi:        true,
			dialTimeout: 15 * time.Second,
		},
		{
			name: "websocket-http",
			make: func(t *testing.T) transportPair {
				tr := transport.NewWebSocketTransport(
					"ws-conf",
					"http",
					loopbackDialer{},
					[]string{"127.0.0.1"},
					nil,
					transport.TLSConfig{},
					transport.WithWebSocketPath("/wireguard"),
				)
				return transportPair{server: tr, client: tr}
			},
			bidi: true,
		},
		{
			name: "websocket-https",
			make: func(t *testing.T) transportPair {
				ca := newTestCA(t)
				serverCert, serverKey := ca.issueLeaf(t, "wss-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)

				server := transport.NewWebSocketTransport(
					"wss-server",
					"https",
					loopbackDialer{},
					[]string{"127.0.0.1"},
					serverMgr,
					transport.TLSConfig{},
					transport.WithWebSocketPath("/wireguard"),
				)
				client := transport.NewWebSocketTransport(
					"wss-client",
					"https",
					loopbackDialer{},
					nil,
					nil,
					transport.TLSConfig{
						VerifyPeer: true,
						CAFile:     ca.caFile,
					},
					transport.WithWebSocketPath("/wireguard"),
				)
				return transportPair{server: server, client: client}
			},
			bidi:        true,
			dialTimeout: 10 * time.Second,
		},
		{
			name: "quic",
			make: func(t *testing.T) transportPair {
				skipQUICOnRestrictedGVisor(t)
				ca := newTestCA(t)
				serverCert, serverKey := ca.issueLeaf(t, "quic-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)

				server := transport.NewQUICTransport(
					"quic-server",
					loopbackDialer{},
					[]string{"127.0.0.1"},
					serverMgr,
					transport.TLSConfig{},
					"/wireguard",
					"",
					"",
				)
				client := transport.NewQUICTransport(
					"quic-client",
					loopbackDialer{},
					nil,
					nil,
					transport.TLSConfig{
						VerifyPeer: true,
						CAFile:     ca.caFile,
					},
					"/wireguard",
					"quic-server",
					"",
				)
				return transportPair{server: server, client: client}
			},
			bidi:        true,
			dialTimeout: 10 * time.Second,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dialTimeout := tc.dialTimeout
			if dialTimeout == 0 {
				dialTimeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()

			pair := tc.make(t)

			ln, err := pair.server.Listen(ctx, 0)
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer ln.Close()

			serverSess := make(chan transport.Session, 1)
			serverErr := make(chan error, 1)
			go func() {
				sess, err := ln.Accept(ctx)
				if err != nil {
					serverErr <- err
					return
				}
				serverSess <- sess
			}()

			clientSess, err := pair.client.Dial(ctx, ln.Addr().String())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer clientSess.Close()

			// UDP is not connection-oriented — Accept() blocks until a packet
			// arrives. Send a primer from the client so the matrix has the same
			// shape across all transports. For connection-oriented transports
			// the primer is just the first frame on an already-accepted session.
			primer := []byte("conformance-primer")
			if err := clientSess.WritePacket(primer); err != nil {
				t.Fatalf("WritePacket primer: %v", err)
			}

			var srvSess transport.Session
			select {
			case srvSess = <-serverSess:
			case err := <-serverErr:
				t.Fatalf("server accept: %v", err)
			case <-ctx.Done():
				t.Fatal("timeout waiting for server accept")
			}
			defer srvSess.Close()

			got, err := srvSess.ReadPacket()
			if err != nil {
				t.Fatalf("server read primer: %v", err)
			}
			if string(got) != string(primer) {
				t.Fatalf("primer payload mismatch: got %q want %q", got, primer)
			}

			// 10 round-trips client→server.
			sendRecv(t, clientSess, srvSess, 10)

			if tc.bidi {
				// Reverse direction: a regression that breaks read-side framing
				// in only one direction (e.g. a length-prefix endianness flip
				// applied client-only) gets caught here.
				sendRecv(t, srvSess, clientSess, 10)
			}
		})
	}
	// Sanity: tls config helper is used so the import survives lite-tag toggling.
	_ = tls.VersionTLS13
}
