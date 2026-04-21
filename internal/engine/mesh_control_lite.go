// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package engine

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

type dynamicPeer struct {
	Peer            config.Peer
	ParentPublicKey string
	Active          bool
	LastControl     time.Time
}

type meshAuthenticator interface{}

func (e *Engine) startMeshControlServer() error {
	if e.cfg.MeshControl.Listen != "" {
		return fmt.Errorf("mesh_control is not supported in lite builds")
	}
	return nil
}

func (e *Engine) startMeshPolling() {}

func (e *Engine) runMeshPolling() {}

func (e *Engine) meshPeerConfig(publicKey string) (config.Peer, int, bool) {
	for i := range e.cfg.WireGuard.Peers {
		if e.cfg.WireGuard.Peers[i].PublicKey == publicKey {
			return e.cfg.WireGuard.Peers[i], i, true
		}
	}
	return config.Peer{}, -1, false
}

func (e *Engine) dynamicPeer(publicKey string) *dynamicPeer {
	e.dynamicMu.RLock()
	defer e.dynamicMu.RUnlock()
	return e.dynamicPeers[publicKey]
}

func (e *Engine) meshInboundACLAllowed(relayPacketMeta) bool { return true }

func (e *Engine) meshAllowLocalACL(relayPacketMeta) bool { return true }

func (e *Engine) meshTrackLocalACL(relayPacketMeta) {}

func (e *Engine) meshSourceAddr() netip.Addr { return netip.Addr{} }

func (e *Engine) applyMeshACLs(parentPublicKey string, rules []acl.Rule) error {
	return e.applyMeshACLsWithDefault(parentPublicKey, acl.Deny, rules, nil)
}

func (e *Engine) applyMeshACLsWithDefault(parentPublicKey string, def acl.Action, inboundRules, outboundRules []acl.Rule) error {
	inList := acl.List{Default: def, Rules: append([]acl.Rule(nil), inboundRules...)}
	if err := inList.Normalize(); err != nil {
		return err
	}
	outList := acl.List{Default: def, Rules: append([]acl.Rule(nil), outboundRules...)}
	if err := outList.Normalize(); err != nil {
		return err
	}
	e.meshACLMu.Lock()
	if e.meshACLsIn == nil {
		e.meshACLsIn = make(map[string]acl.List)
	}
	if e.meshACLsOut == nil {
		e.meshACLsOut = make(map[string]acl.List)
	}
	e.meshACLsIn[parentPublicKey] = inList
	e.meshACLsOut[parentPublicKey] = outList
	e.meshACLMu.Unlock()
	return nil
}

func (e *Engine) reconcileDynamicPeersWithStatic() {
	e.dynamicMu.Lock()
	e.dynamicPeers = make(map[string]*dynamicPeer)
	e.dynamicMu.Unlock()
	_ = e.applyPeerTrafficState(e.cfg.WireGuard.Peers)
}
