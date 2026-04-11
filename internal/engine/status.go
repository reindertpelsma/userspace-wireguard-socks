// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Status is a snapshot of live engine and wireguard-go runtime state. It is
// safe to expose through the management API: private and preshared keys from
// the WireGuard UAPI dump are deliberately ignored while parsing.
type Status struct {
	Running           bool         `json:"running"`
	ListenPort        int          `json:"listen_port,omitempty"`
	ActiveConnections int          `json:"active_connections"`
	Peers             []PeerStatus `json:"peers"`
}

// PeerStatus mirrors the operational counters reported by wireguard-go for a
// peer. A peer with HasHandshake=false is configured but has never completed a
// WireGuard handshake in the current process.
type PeerStatus struct {
	PublicKey                  string   `json:"public_key"`
	Endpoint                   string   `json:"endpoint,omitempty"`
	AllowedIPs                 []string `json:"allowed_ips,omitempty"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty"`
	HasHandshake               bool     `json:"has_handshake"`
	LastHandshakeTime          string   `json:"last_handshake_time,omitempty"`
	LastHandshakeTimeSec       int64    `json:"last_handshake_time_sec"`
	LastHandshakeTimeNsec      int64    `json:"last_handshake_time_nsec"`
	TransmitBytes              uint64   `json:"transmit_bytes"`
	ReceiveBytes               uint64   `json:"receive_bytes"`
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
