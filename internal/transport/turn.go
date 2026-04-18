// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

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
	name   string
	cfg    TURNProxyConfig
	wgPubKey [32]byte // injected when IncludeWGPublicKey is set

	mu            sync.Mutex
	client        *turn.Client
	relayConn     net.PacketConn
	relayAddr     *net.UDPAddr
	cancelKA      context.CancelFunc // keepalive goroutine cancel
	allowedPeers  []string           // requested permissions
	grantedPeers  map[string]bool    // already granted
	open          bool
}

// NewTURNTransport creates a TURNTransport from the given proxy config.
func NewTURNTransport(name string, cfg TURNProxyConfig, wgPubKey [32]byte) *TURNTransport {
	return &TURNTransport{
		name:     name,
		cfg:      cfg,
		wgPubKey: wgPubKey,
	}
}

func (t *TURNTransport) Name() string               { return t.name }
func (t *TURNTransport) IsConnectionOriented() bool { return false }

// Dial is not used for TURN in client mode because TURN is always in
// "listen mode" (it has an allocation).  Calling Dial returns an error; use
// Listen instead.
func (t *TURNTransport) Dial(_ context.Context, _ string) (Session, error) {
	return nil, fmt.Errorf("turn transport %s: use Listen, not Dial", t.name)
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
		return net.ListenPacket("udp4", "0.0.0.0:0")

	case "tcp":
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.cfg.Server)
		if err != nil {
			return nil, err
		}
		return turn.NewSTUNConn(conn), nil

	case "tls", "turns":
		skipVerify := false
		if t.cfg.ValidateCert != nil {
			skipVerify = !*t.cfg.ValidateCert
		}
		conn, err := tls.DialWithDialer(&net.Dialer{}, "tcp", t.cfg.Server, &tls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec
		})
		if err != nil {
			return nil, err
		}
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
		skipVerify := false
		if t.cfg.ValidateCert != nil {
			skipVerify = !*t.cfg.ValidateCert
		}
		dtlsConn, err := piondtls.Dial("udp", udpAddr, &piondtls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec
		})
		if err != nil {
			return nil, err
		}
		return turn.NewSTUNConn(dtlsConn), nil
	}
	return nil, fmt.Errorf("turn: unknown carrier protocol %q", t.cfg.Protocol)
}

// UpdatePermissions updates the set of IPs that are allowed to send to this
// relay allocation.  Calling this after Listen is safe from any goroutine.
func (t *TURNTransport) UpdatePermissions(ips []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.allowedPeers = ips
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
	for _, ip := range t.allowedPeers {
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

