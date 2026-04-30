// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

func TestTransportAdversarialSoakMatrix(t *testing.T) {
	tc := testconfig.Get()
	if !tc.TransportSoak {
		t.Skip("set UWGS_TRANSPORT_SOAK=1 or -uwgs-transport-soak to run adversarial transport soak coverage")
	}
	duration := 15 * time.Second
	if tc.TransportSoakSeconds > 0 {
		duration = time.Duration(tc.TransportSoakSeconds) * time.Second
	}

	for _, tc := range []struct {
		name string
		make func(t *testing.T) transportSoakPair
	}{
		{
			name: "tcp",
			make: func(t *testing.T) transportSoakPair {
				tr := transport.NewTCPTransport("tcp-soak", loopbackDialer{}, []string{"127.0.0.1"})
				return transportSoakPair{server: tr, client: tr}
			},
		},
		{
			name: "tls",
			make: func(t *testing.T) transportSoakPair {
				certMgr := &transport.CertManager{}
				if err := certMgr.Start(); err != nil {
					t.Fatal(err)
				}
				tr := transport.NewTLSTransport("tls-soak", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})
				return transportSoakPair{server: tr, client: tr}
			},
		},
		{
			name: "websocket-http",
			make: func(t *testing.T) transportSoakPair {
				tr := transport.NewWebSocketTransport("ws-soak", "http", loopbackDialer{}, []string{"127.0.0.1"}, nil, transport.TLSConfig{}, transport.WithWebSocketPath("/wireguard"))
				return transportSoakPair{server: tr, client: tr, poisonNetwork: "tcp"}
			},
		},
		{
			name: "websocket-https",
			make: func(t *testing.T) transportSoakPair {
				ca := newTestCA(t)
				serverCert, serverKey := ca.issueLeaf(t, "wss-soak-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)
				server := transport.NewWebSocketTransport("wss-soak-server", "https", loopbackDialer{}, []string{"127.0.0.1"}, serverMgr, transport.TLSConfig{}, transport.WithWebSocketPath("/wireguard"))
				client := transport.NewWebSocketTransport("wss-soak-client", "https", loopbackDialer{}, nil, nil, transport.TLSConfig{VerifyPeer: true, CAFile: ca.caFile}, transport.WithWebSocketPath("/wireguard"))
				return transportSoakPair{server: server, client: client}
			},
		},
		{
			name: "quic-webtransport",
			make: func(t *testing.T) transportSoakPair {
				skipQUICOnRestrictedGVisor(t)
				ca := newTestCA(t)
				serverCert, serverKey := ca.issueLeaf(t, "quic-soak-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)
				server := transport.NewQUICTransport("quic-soak-server", loopbackDialer{}, []string{"127.0.0.1"}, serverMgr, transport.TLSConfig{}, "/wireguard", "", "")
				client := transport.NewQUICTransport("quic-soak-client", loopbackDialer{}, nil, nil, transport.TLSConfig{VerifyPeer: true, CAFile: ca.caFile}, "/wireguard", "quic-soak-server", "")
				return transportSoakPair{server: server, client: client, poisonNetwork: "udp"}
			},
		},
		{
			name: "quic-websocket",
			make: func(t *testing.T) transportSoakPair {
				skipQUICOnRestrictedGVisor(t)
				ca := newTestCA(t)
				serverCert, serverKey := ca.issueLeaf(t, "quic-ws-soak-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)
				server := transport.NewQUICWebSocketTransport("quic-ws-soak-server", loopbackDialer{}, []string{"127.0.0.1"}, serverMgr, transport.TLSConfig{}, "/wireguard", "", "")
				client := transport.NewQUICWebSocketTransport("quic-ws-soak-client", loopbackDialer{}, nil, nil, transport.TLSConfig{VerifyPeer: true, CAFile: ca.caFile}, "/wireguard", "quic-ws-soak-server", "")
				return transportSoakPair{server: server, client: client, poisonNetwork: "udp"}
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runTransportAdversarialSoak(t, tc.make(t), duration)
		})
	}
}

type transportSoakPair struct {
	server        transport.Transport
	client        transport.Transport
	poisonNetwork string
}

func runTransportAdversarialSoak(t *testing.T, pair transportSoakPair, duration time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	ln, err := pair.server.Listen(ctx, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 64)
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for ctx.Err() == nil {
			sess, err := ln.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			serverWG.Add(1)
			go func() {
				defer serverWG.Done()
				defer sess.Close()
				for ctx.Err() == nil {
					pkt, err := sess.ReadPacket()
					if err != nil {
						return
					}
					if err := sess.WritePacket(pkt); err != nil {
						return
					}
				}
			}()
		}
	}()

	var clientWG sync.WaitGroup
	for i := 0; i < 3; i++ {
		i := i
		clientWG.Add(1)
		go func() {
			defer clientWG.Done()
			rng := rand.New(rand.NewSource(int64(1000 + i)))
			round := 0
			for ctx.Err() == nil {
				if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 3*time.Second {
					return
				}
				dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
				sess, err := pair.client.Dial(dialCtx, ln.Addr().String())
				dialErr := dialCtx.Err()
				dialCancel()
				if err != nil {
					if ctx.Err() == nil && dialErr == nil {
						errc <- fmt.Errorf("worker %d dial: %w", i, err)
					}
					return
				}
				for j := 0; j < 6 && ctx.Err() == nil; j++ {
					payload := make([]byte, 32+rng.Intn(900))
					for k := range payload {
						payload[k] = byte(i ^ round ^ j ^ k)
					}
					if err := sess.WritePacket(payload); err != nil {
						_ = sess.Close()
						if ctx.Err() != nil {
							return
						}
						errc <- fmt.Errorf("worker %d write: %w", i, err)
						return
					}
					got, err := sess.ReadPacket()
					if err != nil {
						_ = sess.Close()
						if ctx.Err() != nil {
							return
						}
						errc <- fmt.Errorf("worker %d read: %w", i, err)
						return
					}
					if !bytes.Equal(got, payload) {
						_ = sess.Close()
						errc <- fmt.Errorf("worker %d payload mismatch: got %d want %d bytes", i, len(got), len(payload))
						return
					}
				}
				_ = sess.Close()
				round++
			}
		}()
	}

	clientWG.Add(1)
	go func() {
		defer clientWG.Done()
		poisonTransportListener(ctx, pair.poisonNetwork, ln.Addr().String())
	}()

	done := make(chan struct{})
	go func() {
		clientWG.Wait()
		cancel()
		_ = ln.Close()
		serverWG.Wait()
		close(done)
	}()

	select {
	case err := <-errc:
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		t.Fatal(err)
	case <-done:
	case <-time.After(duration + 10*time.Second):
		cancel()
		_ = ln.Close()
		t.Fatal("transport adversarial soak did not shut down")
	}
}

func poisonTransportListener(ctx context.Context, network, addr string) {
	if network == "" {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		switch network {
		case "udp":
			conn, err := net.DialTimeout("udp", addr, 200*time.Millisecond)
			if err != nil {
				continue
			}
			_, _ = conn.Write([]byte("not a quic packet"))
			_ = conn.Close()
		default:
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err != nil {
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Write([]byte("GET /bad HTTP/1.1\r\nHost: bad\r\n\r\n"))
			_ = conn.Close()
		}
	}
}
