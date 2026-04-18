// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgPublicKey derives the WireGuard public key from the configured private key.
func (e *Engine) wgPublicKey() ([32]byte, error) {
	e.cfgMu.RLock()
	priv := e.cfg.WireGuard.PrivateKey
	e.cfgMu.RUnlock()
	key, err := wgtypes.ParseKey(priv)
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse private key: %w", err)
	}
	pub := key.PublicKey()
	var arr [32]byte
	copy(arr[:], pub[:])
	return arr, nil
}

// transportPeerLookup implements transport.PeerLookup.  It returns keepalive
// and buffered-data state for the peer identified by identBytes so that the
// transport layer can decide whether to reconnect proactively.
func (e *Engine) transportPeerLookup(identBytes []byte) transport.PeerInfo {
	if e.dev == nil {
		return transport.PeerInfo{}
	}
	// identBytes format: [2-byte name-len][name][addr]
	// We only need the address part to match a WireGuard peer.
	target := identTargetAddr(identBytes)
	if target == "" {
		return transport.PeerInfo{}
	}

	e.cfgMu.RLock()
	peers := e.cfg.WireGuard.Peers
	e.cfgMu.RUnlock()

	for _, p := range peers {
		if p.Endpoint == target || endpointMatchesTarget(p.Endpoint, target) {
			return transport.PeerInfo{
				PersistentKeepalive: p.PersistentKeepalive,
				// HasBufferedPackets is not directly queryable from wireguard-go;
				// conservatively treat any peer with keepalive as having data.
				HasBufferedPackets: p.PersistentKeepalive > 0,
			}
		}
	}
	return transport.PeerInfo{}
}

// onTransportEndpointReset implements transport.EndpointResetFunc.  Called
// when a connection-oriented transport dies and the engine must update the
// WireGuard IPC peer endpoint back to the static address.
func (e *Engine) onTransportEndpointReset(identBytes []byte, fallbackAddr string) {
	if e.dev == nil || fallbackAddr == "" {
		return
	}
	select {
	case <-e.closed:
		return
	default:
	}
	target := identTargetAddr(identBytes)
	if target == "" {
		target = fallbackAddr
	}

	e.cfgMu.RLock()
	peers := e.cfg.WireGuard.Peers
	e.cfgMu.RUnlock()

	for _, p := range peers {
		if p.Endpoint == "" {
			continue
		}
		if p.Endpoint == target || endpointMatchesTarget(p.Endpoint, target) {
			uapi, err := peerUAPI(p, false, e.cfg.Transports, transport.ResolveDefaultTransportName(e.cfg.Transports, e.cfg.WireGuard.DefaultTransport))
			if err != nil {
				return
			}
			if err := e.dev.IpcSet(uapi); err != nil {
				e.log.Printf("transport endpoint reset for peer %s failed: %v", p.PublicKey, err)
			}
			return
		}
	}
}

// initPeerTransportEndpoints registers static DialEndpoints or
// NotConnOrientedEndpoints in the MultiTransportBind for each configured peer
// that has an Endpoint= and a named transport.
func (e *Engine) initPeerTransportEndpoints() {
	if e.transportBind == nil {
		return
	}
	e.cfgMu.RLock()
	peers := e.cfg.WireGuard.Peers
	transports := e.cfg.Transports
	e.cfgMu.RUnlock()

	// Build a lookup map of transport name → first not-conn-oriented name
	// as the default.
	defaultTransportName := ""
	for _, tc := range transports {
		if !transport.IsConnectionOriented(tc) {
			defaultTransportName = tc.Name
			break
		}
	}
	if defaultTransportName == "" && len(transports) > 0 {
		defaultTransportName = transports[0].Name
	}

	for _, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		tName := peer.Transport
		if tName == "" {
			tName = defaultTransportName
		}
		t := e.transportBind.GetTransport(tName)
		if t == nil {
			continue
		}
		pub, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			continue
		}
		var identBytes []byte
		var ep interface{ DstToBytes() []byte }
		if t.IsConnectionOriented() {
			de := transport.NewDialEndpoint(tName, peer.Endpoint)
			identBytes = de.IdentBytes()
			ep = de
		} else {
			ap, err := netip.ParseAddrPort(peer.Endpoint)
			if err != nil {
				// Hostname endpoint — skip for now; resolved lazily.
				continue
			}
			nce := transport.NewNotConnOrientedEndpoint(tName, ap)
			identBytes = nce.IdentBytes()
			ep = nce
		}
		_ = pub
		_ = identBytes
		_ = ep
		// Register the static endpoint with the bind.
		if de, ok := ep.(*transport.DialEndpoint); ok {
			e.transportBind.SetPeerSession(identBytes, de, t, peer.PersistentKeepalive)
		} else if nce, ok := ep.(*transport.NotConnOrientedEndpoint); ok {
			e.transportBind.SetPeerSession(identBytes, nce, t, peer.PersistentKeepalive)
		}
	}
}

// identTargetAddr extracts the target address string from transport identity bytes.
// Format: [2-byte big-endian name length][name bytes][target bytes]
func identTargetAddr(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	nameLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+nameLen {
		return ""
	}
	return string(b[2+nameLen:])
}

// endpointMatchesTarget checks whether a peer endpoint string matches a
// target address (handles host:port vs plain IP comparisons).
func endpointMatchesTarget(endpoint, target string) bool {
	if endpoint == target {
		return true
	}
	// Try resolving both to AddrPort for normalised comparison.
	ap1, err1 := netip.ParseAddrPort(endpoint)
	ap2, err2 := netip.ParseAddrPort(target)
	if err1 == nil && err2 == nil {
		return ap1 == ap2
	}
	return false
}

// GetTransportStatus returns a summary of active transport sessions for the
// API /v1/status and /v1/transports endpoints.
func (e *Engine) GetTransportStatus() []TransportStatus {
	if e.transportBind == nil {
		return nil
	}
	names := e.transportBind.TransportNames()
	out := make([]TransportStatus, 0, len(names))
	for _, name := range names {
		out = append(out, TransportStatus{
			Name:           name,
			ActiveSessions: e.transportBind.ActiveSessions(),
		})
	}
	return out
}

// TransportStatus is the API representation of one transport's runtime state.
type TransportStatus struct {
	Name           string `json:"name"`
	ActiveSessions int    `json:"active_sessions"`
}

// AddTransportConfig adds a new transport at runtime without restarting.
func (e *Engine) AddTransportConfig(cfg transport.Config) error {
	if e.transportBind == nil {
		return fmt.Errorf("transport bind not active; no transports configured at startup")
	}
	wgPubKey, err := e.wgPublicKey()
	if err != nil {
		return err
	}
	// Build the single transport using the registry helper.
	bind, err := transport.BuildRegistry(
		[]transport.Config{cfg},
		wgPubKey,
		0,
		e.transportPeerLookup,
		e.onTransportEndpointReset,
		false,
	)
	if err != nil {
		return err
	}
	// Transfer transports from the temporary bind to the live bind.
	for _, name := range bind.TransportNames() {
		t := bind.GetTransport(name)
		if t == nil {
			continue
		}
		e.transportBind.AddTransport(t)
		if cfg.Listen {
			e.transportBind.AddListenTransport(t)
		}
	}
	return nil
}

// hexPubKey returns the hex-encoded public key for a peer, used internally
// to match engine peers to transport identity bytes.
func hexPubKey(pubKey string) string {
	key, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(key[:])
}
