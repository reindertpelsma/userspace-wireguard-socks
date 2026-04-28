// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// chaosProxy is a minimal UDP middleman used by the production-
// faithful mesh chaos test. It listens on a local port, forwards
// every received datagram to a fixed upstream address, and applies
// a drop / delay / jitter policy that can be changed at runtime.
//
// Use case: WireGuard's outer UDP travels A → proxy → B. When the
// proxy starts dropping packets, A's WG keepalive / rekey detects
// path failure (the same way it would in production when a NAT
// drops a stale mapping or the network briefly partitions) and
// the engine's relay-fallback path kicks in "naturally" — same
// code path that fires in real-world incidents.
//
// Single-socket design: the proxy uses ONE UDP socket for both
// directions. Outbound packets to upstream are sent FROM that
// same listening socket, so the upstream sees the proxy's listen
// port as the source — matching real-world NAT semantics where a
// peer behind NAT is reachable at the NAT's public mapping. This
// makes the proxy address mesh-control-advertisable: when the hub
// learns the source of A's WG packets (= proxy.Addr), it can
// advertise that to B and B can dial it back to reach A.
//
// Demux by source: src == upstream → forward to last-seen client;
// otherwise → record src as client, forward to upstream.
//
// Concurrent-safe: policy can be updated mid-flight.
type chaosProxy struct {
	sock     *net.UDPConn // single bidirectional UDP socket
	upstream *net.UDPAddr // the side we forward TO

	mu     sync.RWMutex
	policy chaosPolicy

	// Last src seen that wasn't upstream — used to route reverse-
	// direction replies back to whichever client most recently sent.
	lastSrc atomic.Pointer[net.UDPAddr]

	// Stats for assertions / logging.
	pktsForward atomic.Int64
	pktsDropped atomic.Int64
	pktsDelayed atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}
}

type chaosPolicy struct {
	// LossRate is the probability a datagram is silently dropped
	// instead of forwarded. Range [0.0, 1.0].
	LossRate float64
	// Jitter is the maximum random delay applied to a forwarded
	// datagram. 0 = no jitter. Each datagram's delay is
	// independent: rand.Float64() * Jitter.
	Jitter time.Duration
	// FixedLatency is added to every forwarded datagram on top of
	// the random jitter. Useful to simulate a slower path.
	FixedLatency time.Duration
}

// startChaosProxy listens on a free local port, returns the
// listening UDPAddr (so peers can be configured to send there),
// and forwards every received datagram to upstream applying the
// current policy. The proxy runs in a single recv-demux goroutine
// until Close() is called.
func startChaosProxy(upstream *net.UDPAddr, initial chaosPolicy) (*chaosProxy, error) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	p := &chaosProxy{
		sock:     sock,
		upstream: upstream,
		policy:   initial,
		closed:   make(chan struct{}),
	}
	go p.recvLoop()
	return p, nil
}

func (p *chaosProxy) Addr() *net.UDPAddr {
	return p.sock.LocalAddr().(*net.UDPAddr)
}

func (p *chaosProxy) SetPolicy(pol chaosPolicy) {
	p.mu.Lock()
	p.policy = pol
	p.mu.Unlock()
}

func (p *chaosProxy) Stats() (forwarded, dropped, delayed int64) {
	return p.pktsForward.Load(), p.pktsDropped.Load(), p.pktsDelayed.Load()
}

func (p *chaosProxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.sock.Close()
	})
	return nil
}

// recvLoop reads every datagram on the single socket and demuxes
// by source: packets from upstream get forwarded to the last-seen
// non-upstream src (the client we're fronting); packets from
// anyone else get recorded as the new client and forwarded to
// upstream. This makes the proxy a "full-cone NAT" for one local
// peer: outsiders dialling proxy.Addr reach the client, and the
// upstream sees proxy.Addr as the client's source.
func (p *chaosProxy) recvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-p.closed:
			return
		default:
		}
		_ = p.sock.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := p.sock.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		srcCopy := *src
		// Copy the payload before launching the (possibly
		// delayed) forward — the read buffer is reused next iter.
		payload := append([]byte(nil), buf[:n]...)
		if udpAddrEqual(&srcCopy, p.upstream) {
			// Reply from upstream → forward to last-seen client.
			dst := p.lastSrc.Load()
			if dst == nil {
				// No client has spoken first; nothing to route
				// the reverse-direction datagram to. Drop.
				continue
			}
			to := *dst
			p.applyAndForward(func(b []byte) (int, error) {
				return p.sock.WriteToUDP(b, &to)
			}, payload)
		} else {
			// From client (or any outsider) → record + forward
			// to upstream.
			p.lastSrc.Store(&srcCopy)
			p.applyAndForward(func(b []byte) (int, error) {
				return p.sock.WriteToUDP(b, p.upstream)
			}, payload)
		}
	}
}

// udpAddrEqual returns true if both UDPAddrs refer to the same
// (IP, port) endpoint. We can't use *net.UDPAddr identity since
// these come from different sources (config + read syscalls).
func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

// applyAndForward applies the current policy to a single packet:
// maybe drop, maybe delay, then write via the supplied writer.
func (p *chaosProxy) applyAndForward(write func([]byte) (int, error), payload []byte) {
	p.mu.RLock()
	pol := p.policy
	p.mu.RUnlock()

	if pol.LossRate > 0 && rand.Float64() < pol.LossRate {
		p.pktsDropped.Add(1)
		return
	}
	delay := pol.FixedLatency
	if pol.Jitter > 0 {
		delay += time.Duration(rand.Float64() * float64(pol.Jitter))
	}
	if delay > 0 {
		p.pktsDelayed.Add(1)
		go func() {
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-t.C:
				_, _ = write(payload)
				p.pktsForward.Add(1)
			case <-p.closed:
			}
		}()
		return
	}
	if _, err := write(payload); err == nil {
		p.pktsForward.Add(1)
	}
}

// quickProxyDial is a one-shot "is this proxy actually forwarding"
// helper. Useful in setup to confirm the proxy works before we ask
// WG to dial through it.
func quickProxyDial(ctx context.Context, p *chaosProxy) error {
	c, err := net.DialUDP("udp", nil, p.Addr())
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write([]byte("probe")); err != nil {
		return err
	}
	return nil
}
