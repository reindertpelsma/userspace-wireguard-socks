//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// These stress tests exist to catch any race in the fdproxy lock model
// that the unit tests don't naturally hit. They run concurrent
// add/remove/lookup loops against the per-group maps and rely on
// `go test -race` to actually flag a regression. Without -race they
// still run as smoke tests but don't add much value beyond confirming
// no panic and no deadlock.
//
// They are gated behind UWGS_STRESS=1 so a normal `go test ./...` on a
// developer's laptop or in PR CI doesn't pay for the iteration count.
// release.yml flips the env var on so every release does run them.
// This matches the existing UWGS_SOAK / UWG_TEST_REAL_TUN gating
// convention.
//
// See docs/internal/lock-map-fdproxy.md for the full lock-order rules
// these tests are pinning. The two pre-existing races we found in the
// security audit (replyBind unprotected, udp removeMember reading
// g.order under s.mu only) would both fail under these stress tests
// with -race.

const (
	stressGoroutines = 64
	stressIterations = 2000
)

func skipIfStressDisabled(t *testing.T) {
	t.Helper()
	if !testconfig.Get().Stress {
		t.Skip("set UWGS_STRESS=1 or -uwgs-stress to run lock-order stress tests")
	}
}

// TestStressUDPGroupPeerOwnerChurn drives recordPeerOwner / ownerFor
// concurrently from many goroutines. peerOwner has an LRU eviction
// cap; the test ensures concurrent updates + reads don't trip a race
// or a panic. Run with -race to actually catch regressions.
func TestStressUDPGroupPeerOwnerChurn(t *testing.T) {
	skipIfStressDisabled(t)
	g := &udpListenerGroup{
		peerOwner: make(map[string]udpPeerOwnerEntry),
	}
	var wg sync.WaitGroup
	wg.Add(stressGoroutines)
	for w := 0; w < stressGoroutines; w++ {
		go func(id int) {
			defer wg.Done()
			tok := fmt.Sprintf("token-%d", id)
			for i := 0; i < stressIterations; i++ {
				addr := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{10, 0, byte(id), byte(i % 250)}),
					uint16(40000+(i%2000)),
				)
				g.recordPeerOwner(addr, tok)
				_ = g.ownerFor(addr)
			}
		}(w)
	}
	wg.Wait()
}

// TestStressTCPReplyBindLockedReadWrite hammers setReplyBind / getReplyBind
// from many goroutines simultaneously. This is the regression test for
// the replyBind race we fixed in the security audit (where start() wrote
// without a lock while addTCPListenerMember readers held s.mu only).
// The fix moved both reads and writes under g.mu via these helpers; this
// test pins that.
func TestStressTCPReplyBindLockedReadWrite(t *testing.T) {
	skipIfStressDisabled(t)
	g := &tcpListenerGroup{}
	var wg sync.WaitGroup
	wg.Add(stressGoroutines)
	for w := 0; w < stressGoroutines; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < stressIterations; i++ {
				ap := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{172, 16, byte(id), byte(i % 250)}),
					uint16(50000+(i%1000)),
				)
				g.setReplyBind(ap)
				got := g.getReplyBind()
				if !got.IsValid() {
					t.Errorf("getReplyBind returned invalid AddrPort after set")
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestStressUDPReplyBindLockedReadWrite is the UDP variant of the above.
func TestStressUDPReplyBindLockedReadWrite(t *testing.T) {
	skipIfStressDisabled(t)
	g := &udpListenerGroup{}
	var wg sync.WaitGroup
	wg.Add(stressGoroutines)
	for w := 0; w < stressGoroutines; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < stressIterations; i++ {
				ap := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{172, 17, byte(id), byte(i % 250)}),
					uint16(50000+(i%1000)),
				)
				g.setReplyBind(ap)
				got := g.getReplyBind()
				if !got.IsValid() {
					t.Errorf("getReplyBind returned invalid AddrPort after set")
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestStressTCPGroupMemberChurn drives addMemberLocked / pickMember /
// (a manual member-removal under g.mu) concurrently. addMemberLocked
// is the operation that grows g.members + g.order; pickMember
// round-robins over g.order. Without correct locking, the slice/map
// state would race.
//
// We don't go through Server.addTCPListenerMember because that needs a
// real Unix socket + an upstream API mock — too heavy for a stress
// loop. The race we care about lives in the group operations
// themselves; the Server-side wrapper just adds the s.mu→g.mu nesting
// we cover separately.
func TestStressTCPGroupMemberChurn(t *testing.T) {
	skipIfStressDisabled(t)
	g := &tcpListenerGroup{
		members: make(map[string]*tcpListenerMember),
		accepts: make(map[uint64]*tcpAcceptedConn),
		closed:  make(chan struct{}),
	}
	var picks atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(stressGoroutines)
	for w := 0; w < stressGoroutines; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < stressIterations; i++ {
				m := &tcpListenerMember{
					token:  fmt.Sprintf("m-%d-%d", id, i),
					group:  g,
					closed: make(chan struct{}),
				}
				g.addMemberLocked(m)
				if got := g.pickMember(); got != nil {
					picks.Add(1)
				}
				// Manual remove that mirrors removeMember's g.mu
				// section, without the parent-server-map cleanup
				// step (which we don't have a server for here).
				g.mu.Lock()
				delete(g.members, m.token)
				for j, current := range g.order {
					if current == m.token {
						g.order = append(g.order[:j], g.order[j+1:]...)
						break
					}
				}
				g.mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if picks.Load() == 0 {
		t.Fatal("pickMember never returned a non-nil member; the harness is broken")
	}
}
