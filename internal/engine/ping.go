// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type PingResult struct {
	Target          string      `json:"target"`
	Address         string      `json:"address"`
	Transmitted     int         `json:"transmitted"`
	Received        int         `json:"received"`
	LossPercent     float64     `json:"loss_percent"`
	TimeoutMillis   int64       `json:"timeout_ms"`
	RoundTripMillis []float64   `json:"round_trip_ms,omitempty"`
	Replies         []PingReply `json:"replies"`
	StartedAt       string      `json:"started_at"`
	DurationMillis  float64     `json:"duration_ms"`
}

type PingReply struct {
	Seq             int     `json:"seq"`
	Received        bool    `json:"received"`
	From            string  `json:"from,omitempty"`
	Bytes           int     `json:"bytes,omitempty"`
	RoundTripMillis float64 `json:"round_trip_ms,omitempty"`
	Error           string  `json:"error,omitempty"`
}

func (e *Engine) Ping(ctx context.Context, target string, count int, timeout time.Duration) (PingResult, error) {
	if e.net == nil {
		return PingResult{}, errorsEngineNotStarted()
	}
	if count <= 0 {
		count = 4
	}
	if count > 20 {
		count = 20
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	addr, err := e.resolvePingTarget(ctx, target)
	if err != nil {
		return PingResult{}, err
	}
	if !e.allowedContains(addr) {
		return PingResult{}, fmt.Errorf("%s does not match any WireGuard AllowedIPs", addr)
	}

	network := "ping4"
	var typ icmp.Type = ipv4.ICMPTypeEcho
	var replyTyp icmp.Type = ipv4.ICMPTypeEchoReply
	proto := 1
	if addr.Is6() {
		network = "ping6"
		typ = ipv6.ICMPTypeEchoRequest
		replyTyp = ipv6.ICMPTypeEchoReply
		proto = 58
	}
	conn, err := e.net.DialContext(ctx, network, addr.String())
	if err != nil {
		return PingResult{}, err
	}
	defer conn.Close()

	started := time.Now()
	result := PingResult{
		Target:        target,
		Address:       addr.String(),
		Transmitted:   count,
		TimeoutMillis: timeout.Milliseconds(),
		StartedAt:     started.UTC().Format(time.RFC3339Nano),
	}
	id := (os.Getpid() + rand.Intn(1<<15)) & 0xffff
	buf := make([]byte, 1500)
	for seq := 0; seq < count; seq++ {
		payload := []byte(fmt.Sprintf("uwgsocks ping %d", seq))
		req := icmp.Echo{ID: id, Seq: seq, Data: payload}
		packet, err := (&icmp.Message{Type: typ, Body: &req}).Marshal(nil)
		if err != nil {
			return PingResult{}, err
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return PingResult{}, err
		}
		sentAt := time.Now()
		if _, err := conn.Write(packet); err != nil {
			result.Replies = append(result.Replies, PingReply{Seq: seq, Error: err.Error()})
			continue
		}
		reply := PingReply{Seq: seq}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				reply.Error = err.Error()
				break
			}
			msg, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			// gVisor's ping endpoint owns the ICMP identifier and may rewrite
			// it to the endpoint's local ident. Sequence plus payload are stable
			// for matching our in-flight request.
			if !ok || msg.Type != replyTyp || echo.Seq != seq || !bytes.Equal(echo.Data, payload) {
				continue
			}
			rtt := time.Since(sentAt).Seconds() * 1000
			reply.Received = true
			reply.From = addr.String()
			reply.Bytes = n
			reply.RoundTripMillis = rtt
			result.Received++
			result.RoundTripMillis = append(result.RoundTripMillis, rtt)
			break
		}
		result.Replies = append(result.Replies, reply)
	}
	result.DurationMillis = time.Since(started).Seconds() * 1000
	if result.Transmitted > 0 {
		result.LossPercent = float64(result.Transmitted-result.Received) * 100 / float64(result.Transmitted)
	}
	return result, nil
}

func (e *Engine) resolvePingTarget(ctx context.Context, target string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(target); err == nil {
		if ip.Is6() && !e.proxyIPv6Enabled() {
			return netip.Addr{}, fmt.Errorf("IPv6 is disabled")
		}
		return ip.Unmap(), nil
	}
	addrs, err := e.lookupHost(ctx, target)
	if err != nil {
		return netip.Addr{}, err
	}
	var wg6, wg4 []netip.Addr
	for _, s := range addrs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if ip.Is6() && !e.proxyIPv6Enabled() {
			continue
		}
		if !e.allowedContains(ip) {
			continue
		}
		if ip.Is6() {
			wg6 = append(wg6, ip)
		} else {
			wg4 = append(wg4, ip)
		}
	}
	if len(wg6) > 0 {
		return wg6[0], nil
	}
	if len(wg4) > 0 {
		return wg4[0], nil
	}
	return netip.Addr{}, fmt.Errorf("no WireGuard-routable addresses for %s", target)
}

func errorsEngineNotStarted() error {
	return fmt.Errorf("engine is not started")
}
