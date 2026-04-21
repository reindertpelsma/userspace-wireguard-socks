// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Status is a snapshot of live engine and wireguard-go runtime state. It is
// safe to expose through the management API: private and preshared keys from
// the WireGuard UAPI dump are deliberately ignored while parsing.
type Status struct {
	Running           bool                `json:"running"`
	ListenPort        int                 `json:"listen_port,omitempty"`
	ActiveConnections int                 `json:"active_connections"`
	Peers             []PeerStatus        `json:"peers"`
	DynamicPeers      []DynamicPeerStatus `json:"dynamic_peers,omitempty"`
	Transports        []TransportStatus   `json:"transports,omitempty"`
}

type DynamicPeerStatus struct {
	PublicKey       string   `json:"public_key"`
	ParentPublicKey string   `json:"parent_public_key"`
	Endpoint        string   `json:"endpoint,omitempty"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`
	Active          bool     `json:"active"`
	LastControlTime string   `json:"last_control_time,omitempty"`
}

// PeerStatus mirrors the operational counters reported by wireguard-go for a
// peer. A peer with HasHandshake=false is configured but has never completed a
// WireGuard handshake in the current process.
type PeerStatus struct {
	PublicKey                  string   `json:"public_key"`
	Endpoint                   string   `json:"endpoint,omitempty"`
	EndpointIP                 string   `json:"endpoint_ip,omitempty"`
	AllowedIPs                 []string `json:"allowed_ips,omitempty"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty"`
	HasHandshake               bool     `json:"has_handshake"`
	LastHandshakeTime          string   `json:"last_handshake_time,omitempty"`
	LastHandshakeTimeSec       int64    `json:"last_handshake_time_sec"`
	LastHandshakeTimeNsec      int64    `json:"last_handshake_time_nsec"`
	TransmitBytes              uint64   `json:"transmit_bytes"`
	ReceiveBytes               uint64   `json:"receive_bytes"`
	TransportName              string   `json:"transport_name,omitempty"`
	TransportState             string   `json:"transport_state,omitempty"`
	TransportEndpoint          string   `json:"transport_endpoint,omitempty"`
	TransportSourceAddr        string   `json:"transport_source_addr,omitempty"`
	TransportCarrierRemoteAddr string   `json:"transport_carrier_remote_addr,omitempty"`
	Dynamic                    bool     `json:"dynamic,omitempty"`
	ParentPublicKey            string   `json:"parent_public_key,omitempty"`
	MeshActive                 bool     `json:"mesh_active,omitempty"`
	MeshAcceptACLs             bool     `json:"mesh_accept_acls,omitempty"`
}

// Status returns a live snapshot of configured peers, transfer counters,
// handshake timestamps, and the transparent inbound connection table size.
func (e *Engine) Status() (Status, error) {
	st := Status{
		Running:           e.dev != nil,
		ActiveConnections: e.activeConnectionCount(),
	}
	if e.dev == nil {
		return st, nil
	}
	raw, err := e.dev.IpcGet()
	if err != nil {
		return st, err
	}
	parsed, err := parseStatusUAPI(raw)
	if err != nil {
		return st, err
	}
	parsed.Running = true
	parsed.ActiveConnections = st.ActiveConnections
	parsed.Transports = e.GetTransportStatus()
	e.annotatePeerTransportStatus(&parsed)
	e.annotateDynamicPeerStatus(&parsed)
	return parsed, nil
}

func (e *Engine) activeConnectionCount() int {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return len(e.connTable)
}

func parseStatusUAPI(raw string) (Status, error) {
	var st Status
	var current *PeerStatus
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Status{}, fmt.Errorf("wireguard status: malformed UAPI line %q", line)
		}
		switch key {
		case "private_key", "preshared_key", "protocol_version", "fwmark":
			continue
		case "listen_port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status listen_port: %w", err)
			}
			st.ListenPort = port
		case "public_key":
			publicKey, err := uapiHexKeyToString(value)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status public_key: %w", err)
			}
			st.Peers = append(st.Peers, PeerStatus{PublicKey: publicKey})
			current = &st.Peers[len(st.Peers)-1]
		case "endpoint":
			if current != nil {
				current.Endpoint = value
				current.EndpointIP = endpointIPString(value)
			}
		case "allowed_ip":
			if current != nil {
				current.AllowedIPs = append(current.AllowedIPs, value)
			}
		case "persistent_keepalive_interval":
			seconds, err := strconv.Atoi(value)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status persistent_keepalive_interval: %w", err)
			}
			if current != nil {
				current.PersistentKeepaliveSeconds = seconds
			}
		case "last_handshake_time_sec":
			sec, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status last_handshake_time_sec: %w", err)
			}
			if current != nil {
				current.LastHandshakeTimeSec = sec
			}
		case "last_handshake_time_nsec":
			nsec, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status last_handshake_time_nsec: %w", err)
			}
			if current != nil {
				current.LastHandshakeTimeNsec = nsec
			}
		case "tx_bytes":
			tx, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status tx_bytes: %w", err)
			}
			if current != nil {
				current.TransmitBytes = tx
			}
		case "rx_bytes":
			rx, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard status rx_bytes: %w", err)
			}
			if current != nil {
				current.ReceiveBytes = rx
			}
		}
	}
	for i := range st.Peers {
		peer := &st.Peers[i]
		if peer.LastHandshakeTimeSec <= 0 {
			continue
		}
		peer.HasHandshake = true
		peer.LastHandshakeTime = time.Unix(peer.LastHandshakeTimeSec, peer.LastHandshakeTimeNsec).UTC().Format(time.RFC3339Nano)
	}
	return st, nil
}

func (e *Engine) annotatePeerTransportStatus(st *Status) {
	e.cfgMu.RLock()
	configuredPeers := make([]struct {
		PublicKey string
		Endpoint  string
		Transport string
	}, 0, len(e.cfg.WireGuard.Peers))
	transports := append([]transport.Config(nil), e.cfg.Transports...)
	defaultTransport := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	for _, p := range e.cfg.WireGuard.Peers {
		configuredPeers = append(configuredPeers, struct {
			PublicKey string
			Endpoint  string
			Transport string
		}{
			PublicKey: p.PublicKey,
			Endpoint:  p.Endpoint,
			Transport: p.Transport,
		})
	}
	e.cfgMu.RUnlock()

	if len(st.Peers) == 0 {
		return
	}

	transportKind := make(map[string]string, len(transports))
	for _, tc := range transports {
		tc = transport.NormalizeConfig(tc)
		if transport.IsConnectionOriented(tc) {
			transportKind[tc.Name] = "DialEndpoint"
		} else {
			transportKind[tc.Name] = "NotConnOriented"
		}
	}

	var snapshots []transport.SessionSnapshot
	if e.transportBind != nil {
		snapshots = e.transportBind.SessionSnapshots()
	}

	for i := range st.Peers {
		ps := &st.Peers[i]
		cfgPeer := findConfiguredPeer(configuredPeers, ps.PublicKey)
		configuredTransport := defaultTransport
		configuredEndpoint := ""
		if cfgPeer != nil {
			if cfgPeer.Transport != "" {
				configuredTransport = cfgPeer.Transport
			}
			configuredEndpoint = cfgPeer.Endpoint
		}
		if configuredTransport != "" {
			ps.TransportName = configuredTransport
			if state := transportKind[configuredTransport]; state != "" {
				ps.TransportState = state
			}
		}
		if configuredEndpoint != "" {
			ps.TransportEndpoint = configuredEndpoint
		}

		if snap, ok := matchPeerSnapshot(ps, configuredTransport, configuredEndpoint, snapshots); ok {
			if snap.TransportName != "" {
				ps.TransportName = snap.TransportName
			}
			if snap.State != "" {
				ps.TransportState = snap.State
			}
			if snap.LogicalRemoteAddr != "" {
				ps.TransportEndpoint = snap.LogicalRemoteAddr
			} else if snap.CurrentTarget != "" {
				ps.TransportEndpoint = snap.CurrentTarget
			} else if snap.StaticTarget != "" {
				ps.TransportEndpoint = snap.StaticTarget
			}
			ps.TransportSourceAddr = snap.LocalAddr
			ps.TransportCarrierRemoteAddr = snap.CarrierRemoteAddr
		} else if ps.TransportEndpoint == "" {
			ps.TransportEndpoint = stripTransportPrefix(ps.Endpoint)
		}
	}
}

func (e *Engine) annotateDynamicPeerStatus(st *Status) {
	e.dynamicMu.RLock()
	defer e.dynamicMu.RUnlock()
	if len(e.dynamicPeers) == 0 {
		return
	}
	for i := range st.Peers {
		if dp := e.dynamicPeers[st.Peers[i].PublicKey]; dp != nil {
			st.Peers[i].Dynamic = true
			st.Peers[i].ParentPublicKey = dp.ParentPublicKey
			st.Peers[i].MeshActive = dp.Active
			st.Peers[i].MeshAcceptACLs = dp.Peer.MeshAcceptACLs
			continue
		}
		if peer, _, ok := e.meshPeerConfig(st.Peers[i].PublicKey); ok {
			st.Peers[i].MeshAcceptACLs = peer.MeshAcceptACLs
		}
	}
	st.DynamicPeers = st.DynamicPeers[:0]
	for _, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		item := DynamicPeerStatus{
			PublicKey:       dp.Peer.PublicKey,
			ParentPublicKey: dp.ParentPublicKey,
			Endpoint:        dp.Peer.Endpoint,
			AllowedIPs:      append([]string(nil), dp.Peer.AllowedIPs...),
			Active:          dp.Active,
		}
		if !dp.LastControl.IsZero() {
			item.LastControlTime = dp.LastControl.UTC().Format(time.RFC3339Nano)
		}
		st.DynamicPeers = append(st.DynamicPeers, item)
	}
	sort.Slice(st.DynamicPeers, func(i, j int) bool {
		if st.DynamicPeers[i].ParentPublicKey == st.DynamicPeers[j].ParentPublicKey {
			return st.DynamicPeers[i].PublicKey < st.DynamicPeers[j].PublicKey
		}
		return st.DynamicPeers[i].ParentPublicKey < st.DynamicPeers[j].ParentPublicKey
	})
}

func matchPeerSnapshot(ps *PeerStatus, configuredTransport, configuredEndpoint string, snapshots []transport.SessionSnapshot) (transport.SessionSnapshot, bool) {
	if len(snapshots) == 0 {
		return transport.SessionSnapshot{}, false
	}
	targets := []string{}
	if configuredEndpoint != "" {
		targets = append(targets, configuredEndpoint)
	}
	if ep := stripTransportPrefix(ps.Endpoint); ep != "" {
		targets = append(targets, ep)
	}

	for _, snap := range snapshots {
		if configuredTransport != "" && snap.TransportName != "" && snap.TransportName != configuredTransport {
			continue
		}
		for _, target := range targets {
			if target == "" {
				continue
			}
			if endpointEqualLoose(target, snap.StaticTarget) ||
				endpointEqualLoose(target, snap.CurrentTarget) ||
				endpointEqualLoose(target, snap.LogicalRemoteAddr) ||
				endpointEqualLoose(target, stripTransportPrefix(snap.StaticEndpoint)) ||
				endpointEqualLoose(target, stripTransportPrefix(snap.CurrentEndpoint)) {
				return snap, true
			}
		}
	}

	if configuredTransport == "" {
		var matched *transport.SessionSnapshot
		for i := range snapshots {
			snap := &snapshots[i]
			for _, target := range targets {
				if endpointEqualLoose(target, snap.CurrentTarget) ||
					endpointEqualLoose(target, snap.LogicalRemoteAddr) ||
					endpointEqualLoose(target, stripTransportPrefix(snap.CurrentEndpoint)) {
					if matched != nil {
						return transport.SessionSnapshot{}, false
					}
					matched = snap
				}
			}
		}
		if matched != nil {
			return *matched, true
		}
	}
	return transport.SessionSnapshot{}, false
}

func findConfiguredPeer(peers []struct {
	PublicKey string
	Endpoint  string
	Transport string
}, publicKey string) *struct {
	PublicKey string
	Endpoint  string
	Transport string
} {
	for i := range peers {
		if peers[i].PublicKey == publicKey {
			return &peers[i]
		}
	}
	return nil
}

func stripTransportPrefix(endpoint string) string {
	if idx := strings.LastIndex(endpoint, "@"); idx > 0 {
		return endpoint[idx+1:]
	}
	return endpoint
}

func endpointEqualLoose(a, b string) bool {
	a = stripTransportPrefix(strings.TrimSpace(a))
	b = stripTransportPrefix(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ap1, err1 := netip.ParseAddrPort(a)
	ap2, err2 := netip.ParseAddrPort(b)
	return err1 == nil && err2 == nil && ap1 == ap2
}

func endpointIPString(endpoint string) string {
	endpoint = stripTransportPrefix(endpoint)
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return ""
	}
	return ap.Addr().String()
}

func uapiHexKeyToString(value string) (string, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	var key wgtypes.Key
	if len(raw) != len(key) {
		return "", fmt.Errorf("invalid key length %d", len(raw))
	}
	copy(key[:], raw)
	return key.String(), nil
}
