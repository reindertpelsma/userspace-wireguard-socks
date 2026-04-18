// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package transport provides pluggable transport implementations for
// WireGuard.  Each transport wraps a base framing protocol (UDP, TCP, TLS,
// DTLS, WebSocket) with an optional proxy layer (none, TURN, SOCKS5, HTTP
// CONNECT) and exposes a unified conn.Bind to wireguard-go via
// MultiTransportBind.
package transport

import (
	"context"
	"errors"
	"net"
)

// ErrUDPNotSupported is returned by ProxyDialer.DialPacket when the proxy
// does not support UDP tunnelling (e.g. HTTP CONNECT proxy).
var ErrUDPNotSupported = errors.New("transport: proxy does not support UDP")

// ErrTransportNotFound is returned when a named transport cannot be located
// in the registry.
var ErrTransportNotFound = errors.New("transport: not found")

// ErrBindAlreadyClosed is returned when an operation is attempted on a closed
// MultiTransportBind.
var ErrBindAlreadyClosed = errors.New("transport: bind already closed")

// Transport is a named framing + optional-proxy combination that can carry
// WireGuard packets.
type Transport interface {
	// Name returns the unique human-readable identifier for this transport.
	Name() string

	// IsConnectionOriented reports true when a single underlying connection
	// is used per peer (TCP, TLS, DTLS, WebSocket, or anything tunnelled
	// through a stream proxy such as SOCKS5 or HTTP CONNECT).
	// UDP and TURN return false.
	IsConnectionOriented() bool

	// Dial opens a client-mode session to target.  target is host:port and
	// may be a hostname when the proxy supports hostname forwarding.
	Dial(ctx context.Context, target string) (Session, error)

	// Listen starts a server-mode listener on the given port.  port==0
	// means pick any free port.  The returned Listener yields incoming
	// sessions via Accept.
	Listen(ctx context.Context, port int) (Listener, error)
}

// Session is a single WireGuard packet exchange channel between two
// endpoints.  For connection-oriented transports each peer has one Session;
// for not-connection-oriented transports (UDP, TURN) a single Session may
// be shared across all peers.
type Session interface {
	// ReadPacket reads the next WireGuard packet payload.  The returned
	// slice is only valid until the next call to ReadPacket.
	// Returns io.EOF or net.ErrClosed when the session is done.
	ReadPacket() ([]byte, error)

	// WritePacket sends one WireGuard packet payload.
	WritePacket(pkt []byte) error

	// RemoteAddr returns a string representation of the peer address for
	// logging.
	RemoteAddr() string

	// Close tears down the session.  Idempotent.
	Close() error
}

// Listener accepts incoming sessions from remote peers.
type Listener interface {
	// Accept blocks until a new session arrives or ctx is cancelled.
	Accept(ctx context.Context) (Session, error)

	// Addr returns the local address the listener is bound to.
	Addr() net.Addr

	// Close stops accepting new sessions and releases resources.
	Close() error
}

// ProxyDialer provides the underlying dialling mechanism used by a Transport.
// It abstracts over direct dialling, SOCKS5, and HTTP CONNECT proxies.
type ProxyDialer interface {
	// DialContext dials a stream connection (TCP or TLS) to addr.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)

	// DialPacket returns a packet-oriented connection for UDP proxying via
	// SOCKS5 UDP ASSOCIATE.  remoteHint is the first destination address
	// (used when the SOCKS5 server needs it for the ASSOCIATE request).
	// Returns ErrUDPNotSupported when the proxy cannot carry UDP.
	DialPacket(ctx context.Context, remoteHint string) (net.PacketConn, string, error)

	// SupportsHostname reports whether the proxy can forward hostname targets
	// without the caller performing local DNS resolution.  When true,
	// hostnames from WireGuard peer Endpoint fields are passed verbatim.
	SupportsHostname() bool
}

// PeerLookup is a function the engine provides to MultiTransportBind so it
// can query per-peer state without importing the engine package.
type PeerLookup func(identBytes []byte) PeerInfo

// PeerInfo contains transport-relevant runtime state for one WireGuard peer.
type PeerInfo struct {
	// PersistentKeepalive is the configured keepalive interval in seconds.
	// Zero means none.
	PersistentKeepalive int
	// HasBufferedPackets reports whether WireGuard has data queued for this
	// peer that it is waiting to encrypt and send.
	HasBufferedPackets bool
}

// EndpointResetFunc is called by MultiTransportBind when a connection-
// oriented session dies and the effective endpoint for a peer needs to be
// reset.  The engine uses this to update the WireGuard IPC state.
type EndpointResetFunc func(identBytes []byte, fallbackEndpoint string)
