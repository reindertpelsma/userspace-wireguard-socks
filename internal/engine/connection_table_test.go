// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func TestDefaultIdleTimeouts(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.Inbound.TCPIdleTimeoutSeconds != 15*60 {
		t.Fatalf("TCP idle timeout = %d, want 900", cfg.Inbound.TCPIdleTimeoutSeconds)
	}
	if cfg.Inbound.UDPIdleTimeoutSeconds != 30 {
		t.Fatalf("UDP idle timeout = %d, want 30", cfg.Inbound.UDPIdleTimeoutSeconds)
	}
	if cfg.Inbound.ConnectionTableGraceSeconds != 30 {
		t.Fatalf("connection table grace = %d, want 30", cfg.Inbound.ConnectionTableGraceSeconds)
	}
	if cfg.Inbound.TCPMaxBufferedBytes != 256<<20 {
		t.Fatalf("TCP max buffered bytes = %d, want %d", cfg.Inbound.TCPMaxBufferedBytes, 256<<20)
	}
}

func TestConnectionTableGraceReapsOldTCP(t *testing.T) {
	cfg := config.Default()
	cfg.Inbound.MaxConnections = 1
	cfg.Inbound.ConnectionTableGraceSeconds = 1
	e, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	first, ok := e.acquireConn("tcp")
	if !ok {
		t.Fatal("first TCP acquire failed")
	}
	killed := make(chan struct{}, 1)
	e.setConnCloser(first, func() { killed <- struct{}{} })

	if _, ok := e.acquireConn("tcp"); ok {
		t.Fatal("new connection was accepted before the grace age elapsed")
	}
	select {
	case <-killed:
		t.Fatal("young TCP connection was killed")
	default:
	}

	time.Sleep(1100 * time.Millisecond)
	second, ok := e.acquireConn("tcp")
	if !ok {
		t.Fatal("new connection was rejected even though an old TCP entry could be reaped")
	}
	defer e.releaseConn(second)

	select {
	case <-killed:
	case <-time.After(time.Second):
		t.Fatal("old TCP connection was not killed when the table was full")
	}
}

func TestConnectionTableGraceDoesNotReapUDP(t *testing.T) {
	cfg := config.Default()
	cfg.Inbound.MaxConnections = 1
	cfg.Inbound.ConnectionTableGraceSeconds = 1
	e, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, ok := e.acquireConn("udp")
	if !ok {
		t.Fatal("first UDP acquire failed")
	}
	defer e.releaseConn(first)
	time.Sleep(1100 * time.Millisecond)
	if _, ok := e.acquireConn("tcp"); ok {
		t.Fatal("TCP acquire reaped an old UDP entry; only TCP entries should be grace-reaped")
	}
}

func TestTCPMaxBufferedBytesDerivesGlobalTCPLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Inbound.MaxConnections = 0
	cfg.Inbound.TCPReceiveWindowBytes = 1024
	cfg.Inbound.TCPMaxBufferedBytes = 2 * 1024
	cfg.Inbound.ConnectionTableGraceSeconds = 60
	e, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	first, ok := e.acquireConn("tcp")
	if !ok {
		t.Fatal("first TCP acquire failed")
	}
	defer e.releaseConn(first)
	second, ok := e.acquireConn("tcp")
	if !ok {
		t.Fatal("second TCP acquire failed")
	}
	defer e.releaseConn(second)
	if _, ok := e.acquireConn("tcp"); ok {
		t.Fatal("third TCP acquire succeeded despite tcp_max_buffered_bytes limit")
	}
	if udp, ok := e.acquireConn("udp"); !ok {
		t.Fatal("TCP buffer limit unexpectedly rejected UDP")
	} else {
		e.releaseConn(udp)
	}
}
