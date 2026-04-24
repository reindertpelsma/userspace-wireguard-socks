// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

const (
	// turnKeepaliveInterval is how often a TURN binding request is sent to
	// keep the NAT mapping alive.
	turnKeepaliveInterval = 25 * time.Second
	// turnKeepaliveTimeout is the maximum time to wait for a TURN keepalive
	// response before considering the TURN connection dead.
	turnKeepaliveTimeout = 5 * time.Second
)

// TURNTransport is a NOT-connection-oriented transport that relays WireGuard
// UDP packets through a TURN server.  It supports TURN over UDP, TCP, TLS
// (TURNS), and DTLS.
//
// TURN is not connection-oriented because it can multiplex multiple WireGuard
// flows over the same allocation.  However, the underlying carrier (TCP, TLS,
// DTLS) may be replaced when it fails, triggering a full TURN reconnect.
type TURNTransport struct {
	name     string
	cfg      TURNConfig
	wsCfg    WebSocketConfig
	dialer   ProxyDialer
	wgPubKey [32]byte // injected when IncludeWGPublicKey is set
	certMgr  *CertManager

	mu                 sync.Mutex
	client             *turn.Client
	relayConn          net.PacketConn
	relayAddr          *net.UDPAddr
	carrierLocalAddr   string
	carrierRemoteAddr  string
	cancelKA           context.CancelFunc // keepalive goroutine cancel
	basePermissions    []string
	dynamicPermissions []string
	grantedPeers       map[string]bool // already granted
	open               bool
}

// NewTURNTransport creates a TURNTransport from the given transport config.
func NewTURNTransport(name string, cfg TURNConfig, wsCfg WebSocketConfig, dialer ProxyDialer, wgPubKey [32]byte) (*TURNTransport, error) {
	autoGenerate := cfg.Protocol == "dtls"
	certMgr, err := buildCertManager(cfg.TLS, autoGenerate)
	if err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = NewDirectDialer(false, netip.Prefix{})
	}
	return &TURNTransport{
		name:            name,
		cfg:             cfg,
		wsCfg:           wsCfg,
		dialer:          dialer,
		wgPubKey:        wgPubKey,
		certMgr:         certMgr,
		basePermissions: append([]string(nil), cfg.Permissions...),
	}, nil
}

func (t *TURNTransport) Name() string               { return t.name }
func (t *TURNTransport) IsConnectionOriented() bool { return false }

// Dial returns a lightweight write-capable session that sends packets through
// the shared TURN allocation to the requested destination. Read traffic still
// arrives through Listen/Accept because TURN is not connection-oriented.
func (t *TURNTransport) Dial(ctx context.Context, target string) (Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open {
		if err := t.connectLocked(ctx); err != nil {
			return nil, err
		}
	}
	if t.relayConn == nil {
		return nil, fmt.Errorf("turn transport %s: relay allocation is not open", t.name)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("turn transport %s: resolve target %q: %w", t.name, target, err)
	}
	return &turnOutboundSession{
		relayConn: t.relayConn,
		target:    udpAddr,
	}, nil
}

// Listen allocates a TURN relay and returns a TURNListener that can both
// send to specific addresses and receive from any address.
func (t *TURNTransport) Listen(ctx context.Context, _ int) (Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.open {
		return nil, fmt.Errorf("turn transport %s: already open", t.name)
	}
	if err := t.connectLocked(ctx); err != nil {
		return nil, err
	}
	return &turnListener{transport: t}, nil
}

// connectLocked establishes the TURN client and allocates a relay.
// Caller must hold t.mu.
func (t *TURNTransport) connectLocked(ctx context.Context) error {
	username := t.cfg.Username
	if t.cfg.IncludeWGPublicKey {
		enc, err := encryptPubKey(t.wgPubKey[:], t.cfg.Password)
		if err != nil {
			return fmt.Errorf("turn: encrypt wg pubkey: %w", err)
		}
		username = fmt.Sprintf("%s---%s", username, enc)
	}

	carrier, err := t.dialCarrier(ctx)
	if err != nil {
		return fmt.Errorf("turn: dial carrier: %w", err)
	}

	logFac := logging.NewDefaultLoggerFactory()
	cfg := &turn.ClientConfig{
		STUNServerAddr: t.cfg.Server,
		TURNServerAddr: t.cfg.Server,
		Conn:           carrier,
		Username:       username,
		Password:       t.cfg.Password,
		Realm:          t.cfg.Realm,
		LoggerFactory:  logFac,
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		carrier.Close()
		return fmt.Errorf("turn: new client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		return fmt.Errorf("turn: listen: %w", err)
	}
	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		return fmt.Errorf("turn: allocate: %w", err)
	}

	t.client = client
	t.relayConn = relayConn
	t.relayAddr = relayConn.LocalAddr().(*net.UDPAddr)
	t.carrierLocalAddr = addrString(carrier.LocalAddr())
	t.grantedPeers = make(map[string]bool)
	t.open = true

	// Apply any already-configured permissions.
	t.refreshPermissionsLocked()

	// Start keepalive goroutine.
	kaCtx, cancel := context.WithCancel(context.Background())
	t.cancelKA = cancel
	go t.keepaliveLoop(kaCtx)

	return nil
}

// dialCarrier opens the network connection used to reach the TURN server,
// based on cfg.Protocol.
func (t *TURNTransport) dialCarrier(ctx context.Context) (net.PacketConn, error) {
	switch t.cfg.Protocol {
	case "", "udp":
		pc, _, err := t.dialer.DialPacket(ctx, t.cfg.Server)
		if err != nil {
			return nil, err
		}
		t.carrierRemoteAddr = t.cfg.Server
		return pc, nil

	case "tcp":
		conn, err := t.dialer.DialContext(ctx, "tcp", t.cfg.Server)
		if err != nil {
			return nil, err
		}
		t.carrierRemoteAddr = addrString(conn.RemoteAddr())
		return turn.NewSTUNConn(conn), nil

	case "tls", "turns":
		tlsCfg, err := buildTLSClientConfig(t.cfg.TLS, t.certMgr, serverName(t.cfg.Server), false)
		if err != nil {
			return nil, err
		}
		rawConn, err := t.dialer.DialContext(ctx, "tcp", t.cfg.Server)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(rawConn, tlsCfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		t.carrierRemoteAddr = addrString(conn.RemoteAddr())
		return turn.NewSTUNConn(conn), nil

	case "dtls":
		host, port, err := net.SplitHostPort(t.cfg.Server)
		if err != nil {
			return nil, err
		}
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			return nil, err
		}
		pc, _, err := t.dialer.DialPacket(ctx, t.cfg.Server)
		if err != nil {
			return nil, err
		}
		cfg, err := buildDTLSClientConfig(t.cfg.TLS, t.certMgr, host, false)
		if err != nil {
			pc.Close()
			return nil, err
		}
		dtlsConn, err := piondtls.Client(pc, udpAddr, cfg)
		if err != nil {
			pc.Close()
			return nil, err
		}
		t.carrierRemoteAddr = t.cfg.Server
		return turn.NewSTUNConn(dtlsConn), nil

	case "http":
		if strings.EqualFold(strings.TrimSpace(t.wsCfg.UpgradeMode), string(HTTPUpgradeModeProxyGuard)) {
			conn, err := DialTURNHTTPStreamConn(ctx, t.cfg.Server, false, t.dialer, t.certMgr, t.cfg.TLS, t.wsCfg)
			if err != nil {
				return nil, err
			}
			t.carrierRemoteAddr = addrString(conn.RemoteAddr())
			return turn.NewSTUNConn(conn), nil
		}
		pc, err := DialTURNHTTPPacketConn(ctx, t.cfg.Server, false, t.dialer, t.certMgr, t.cfg.TLS, t.wsCfg)
		if err != nil {
			return nil, err
		}
		t.carrierRemoteAddr = t.cfg.Server
		return pc, nil

	case "https":
		if strings.EqualFold(strings.TrimSpace(t.wsCfg.UpgradeMode), string(HTTPUpgradeModeProxyGuard)) {
			conn, err := DialTURNHTTPStreamConn(ctx, t.cfg.Server, true, t.dialer, t.certMgr, t.cfg.TLS, t.wsCfg)
			if err != nil {
				return nil, err
			}
			t.carrierRemoteAddr = addrString(conn.RemoteAddr())
			return turn.NewSTUNConn(conn), nil
		}
		pc, err := DialTURNHTTPPacketConn(ctx, t.cfg.Server, true, t.dialer, t.certMgr, t.cfg.TLS, t.wsCfg)
		if err != nil {
			return nil, err
		}
		t.carrierRemoteAddr = t.cfg.Server
		return pc, nil

	case "quic":
		pc, err := DialTURNQUICPacketConn(ctx, t.cfg.Server, t.dialer, t.certMgr, t.cfg.TLS, t.wsCfg)
		if err != nil {
			return nil, err
		}
		t.carrierRemoteAddr = t.cfg.Server
		return pc, nil
	}
	return nil, fmt.Errorf("turn: unknown carrier protocol %q", t.cfg.Protocol)
}

// UpdatePermissions updates the set of IPs that are allowed to send to this
// relay allocation.  Calling this after Listen is safe from any goroutine.
func (t *TURNTransport) UpdatePermissions(ips []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dynamicPermissions = append(t.dynamicPermissions[:0], ips...)
	if t.open {
		t.refreshPermissionsLocked()
	}
}

// refreshPermissionsLocked sends CreatePermission for each new peer.
// Caller must hold t.mu.
func (t *TURNTransport) refreshPermissionsLocked() {
	if t.cfg.NoCreatePermission || t.client == nil {
		return
	}
	for _, ip := range t.permissionListLocked() {
		if t.grantedPeers[ip] {
			continue
		}
		t.grantedPeers[ip] = true
		addr := parsePermissionAddr(ip)
		if addr != nil {
			_ = t.client.CreatePermission(addr)
		}
	}
}

func (t *TURNTransport) permissionListLocked() []string {
	out := make([]string, 0, len(t.basePermissions)+len(t.dynamicPermissions))
	seen := make(map[string]struct{}, len(t.basePermissions)+len(t.dynamicPermissions))
	for _, ip := range t.basePermissions {
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	for _, ip := range t.dynamicPermissions {
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// keepaliveLoop sends periodic STUN binding requests to prevent NAT timeout.
// If the TURN server stops responding for turnKeepaliveTimeout the TURN
// connection is marked dead and will be reconnected on the next use.
func (t *TURNTransport) keepaliveLoop(ctx context.Context) {
	ticker := time.NewTicker(turnKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.mu.Lock()
			if !t.open || t.client == nil {
				t.mu.Unlock()
				return
			}
			client := t.client
			t.mu.Unlock()

			// SendBindingRequest is a no-op if the STUN client is closed.
			done := make(chan error, 1)
			go func() { _, err := client.SendBindingRequest(); done <- err }()
			select {
			case <-ctx.Done():
				return
			case err := <-done:
				if err != nil {
					t.handleCarrierFailure()
					return
				}
			case <-time.After(turnKeepaliveTimeout):
				t.handleCarrierFailure()
				return
			}
		}
	}
}

// handleCarrierFailure is called when the TURN carrier appears to be dead.
// It closes the current client so the next Listen call reconnects.
func (t *TURNTransport) handleCarrierFailure() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open {
		return
	}
	if t.relayConn != nil {
		t.relayConn.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.client = nil
	t.relayConn = nil
	t.relayAddr = nil
	t.carrierLocalAddr = ""
	t.carrierRemoteAddr = ""
	t.open = false
}

// Close tears down the TURN allocation and the carrier.
func (t *TURNTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancelKA != nil {
		t.cancelKA()
	}
	if t.relayConn != nil {
		t.relayConn.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.client = nil
	t.relayConn = nil
	t.relayAddr = nil
	t.carrierLocalAddr = ""
	t.carrierRemoteAddr = ""
	t.open = false
}

// RelayAddr returns the TURN relay address (host:port) or empty string when
// not yet allocated.
func (t *TURNTransport) RelayAddr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.relayAddr == nil {
		return ""
	}
	return t.relayAddr.String()
}

// WGPublicKeyForTest exposes the embedded WireGuard public key for package-external tests.
func (t *TURNTransport) WGPublicKeyForTest() [32]byte {
	return t.wgPubKey
}

// NoCreatePermissionForTest exposes the TURN permission mode for package-external tests.
func (t *TURNTransport) NoCreatePermissionForTest() bool {
	return t.cfg.NoCreatePermission
}

func (t *TURNTransport) TransportInfo() TransportInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TransportInfo{
		Connected:         t.open && t.relayConn != nil,
		CarrierProtocol:   t.cfg.Protocol,
		CarrierLocalAddr:  t.carrierLocalAddr,
		CarrierRemoteAddr: t.carrierRemoteAddr,
		RelayAddr:         addrString(t.relayAddr),
	}
}

// --- turnListener ----------------------------------------------------------

// turnListener implements Listener for TURN.  Because TURN is not connection-
// oriented each incoming datagram is represented as a turnSession.
type turnListener struct {
	transport *TURNTransport
}

func (l *turnListener) Accept(ctx context.Context) (Session, error) {
	t := l.transport
	t.mu.Lock()
	if !t.open {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	relayConn := t.relayConn
	t.mu.Unlock()

	// Block until a datagram arrives.
	buf := make([]byte, maxUDPPayload)
	n, addr, err := relayConn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return nil, fmt.Errorf("turn: unexpected address type %T", addr)
		}
		udpAddr = net.UDPAddrFromAddrPort(ap)
	}
	return &turnSession{
		pkt:       buf[:n],
		from:      udpAddr,
		relayConn: relayConn,
	}, nil
}

func (l *turnListener) Addr() net.Addr {
	t := l.transport
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.relayAddr
}

func (l *turnListener) Close() error {
	l.transport.Close()
	return nil
}

// --- turnSession -----------------------------------------------------------

// turnSession represents one inbound TURN datagram.  Writes go back to the
// source address through the relay.
type turnSession struct {
	pkt       []byte
	from      *net.UDPAddr
	relayConn net.PacketConn
	read      bool
}

func (s *turnSession) ReadPacket() ([]byte, error) {
	if s.read {
		return nil, net.ErrClosed
	}
	s.read = true
	return s.pkt, nil
}

func (s *turnSession) WritePacket(pkt []byte) error {
	_, err := s.relayConn.WriteTo(pkt, s.from)
	return err
}

func (s *turnSession) RemoteAddr() string { return s.from.String() }
func (s *turnSession) Close() error       { return nil }
func (s *turnSession) SessionInfo() SessionInfo {
	return SessionInfo{
		LocalAddr:         addrString(s.relayConn.LocalAddr()),
		CarrierRemoteAddr: s.from.String(),
		LogicalRemoteAddr: s.from.String(),
	}
}

type turnOutboundSession struct {
	relayConn net.PacketConn
	target    *net.UDPAddr
}

func (s *turnOutboundSession) ReadPacket() ([]byte, error) {
	return nil, net.ErrClosed
}

func (s *turnOutboundSession) WritePacket(pkt []byte) error {
	_, err := s.relayConn.WriteTo(pkt, s.target)
	return err
}

func (s *turnOutboundSession) RemoteAddr() string { return s.target.String() }
func (s *turnOutboundSession) Close() error       { return nil }
func (s *turnOutboundSession) SessionInfo() SessionInfo {
	return SessionInfo{
		LocalAddr:         addrString(s.relayConn.LocalAddr()),
		CarrierRemoteAddr: s.target.String(),
		LogicalRemoteAddr: s.target.String(),
	}
}

// --- helpers ---------------------------------------------------------------

func parsePermissionAddr(ip string) *net.UDPAddr {
	if addr := net.ParseIP(ip); addr != nil {
		return &net.UDPAddr{IP: addr, Port: 5}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", ip)
	if err == nil {
		return udpAddr
	}
	return nil
}

func encryptPubKey(pubKey []byte, password string) (string, error) {
	key := make([]byte, 32)
	copy(key, password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, pubKey, nil)
	combined := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(combined), nil
}
