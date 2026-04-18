// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// EndpointKind enumerates the three logical endpoint types.
type EndpointKind uint8

const (
	// KindNotConnOriented is a not-connection-oriented endpoint (UDP, TURN).
	// Packets can be sent at any time without prior connection setup.
	KindNotConnOriented EndpointKind = iota
	// KindDial is a static configuration endpoint.  It does not support
	// direct packet sends; MultiTransportBind dials a real connection and
	// promotes it to KindConnEstablished when a packet must be sent.
	KindDial
	// KindConnEstablished is a live connection-oriented session.  It is a
	// transient runtime object and is never persisted across restarts.
	KindConnEstablished
)

// TransportEndpoint extends conn.Endpoint with transport metadata.
type TransportEndpoint interface {
	conn.Endpoint
	// Kind returns the type of this endpoint.
	Kind() EndpointKind
	// TransportName returns the name of the transport that owns this endpoint.
	TransportName() string
	// IdentBytes returns a stable byte slice that WireGuard uses to match
	// this endpoint to a peer across multiple Endpoint instances.  All three
	// endpoint kinds for the same logical peer return the same bytes.
	IdentBytes() []byte
}

// --- NotConnOrientedEndpoint -----------------------------------------------

// NotConnOrientedEndpoint represents a UDP or TURN relay endpoint.
// Packets are sent directly without establishing a persistent connection.
type NotConnOrientedEndpoint struct {
	AP            netip.AddrPort
	TransportID   string
	ident         []byte
}

// NewNotConnOrientedEndpoint creates an endpoint for a not-connection-
// oriented transport such as UDP or TURN.
func NewNotConnOrientedEndpoint(transportName string, ap netip.AddrPort) *NotConnOrientedEndpoint {
	return &NotConnOrientedEndpoint{
		AP:          ap,
		TransportID: transportName,
		ident:       buildIdent(transportName, ap.String()),
	}
}

func (e *NotConnOrientedEndpoint) Kind() EndpointKind  { return KindNotConnOriented }
func (e *NotConnOrientedEndpoint) TransportName() string { return e.TransportID }
func (e *NotConnOrientedEndpoint) IdentBytes() []byte    { return e.ident }
func (e *NotConnOrientedEndpoint) ClearSrc()             {}
func (e *NotConnOrientedEndpoint) SrcToString() string   { return "" }
func (e *NotConnOrientedEndpoint) DstToString() string   { return e.AP.String() }
func (e *NotConnOrientedEndpoint) DstIP() netip.Addr     { return e.AP.Addr() }
func (e *NotConnOrientedEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e *NotConnOrientedEndpoint) DstToBytes() []byte    { return e.ident }

// --- DialEndpoint ----------------------------------------------------------

// DialEndpoint is a static configuration endpoint that represents "dial here
// when a packet must be sent".  MultiTransportBind sees this endpoint type
// and dials the transport before forwarding the packet, producing a
// ConnEstablishedEndpoint for subsequent sends.
type DialEndpoint struct {
	Target      string // host:port (may be a hostname)
	TransportID string
	ident       []byte
}

// NewDialEndpoint creates a dial endpoint for a connection-oriented transport.
func NewDialEndpoint(transportName, target string) *DialEndpoint {
	return &DialEndpoint{
		Target:      target,
		TransportID: transportName,
		ident:       buildIdent(transportName, target),
	}
}

func (e *DialEndpoint) Kind() EndpointKind   { return KindDial }
func (e *DialEndpoint) TransportName() string { return e.TransportID }
func (e *DialEndpoint) IdentBytes() []byte    { return e.ident }
func (e *DialEndpoint) ClearSrc()             {}
func (e *DialEndpoint) SrcToString() string   { return "" }
func (e *DialEndpoint) DstToString() string   { return fmt.Sprintf("%s@%s", e.TransportID, e.Target) }
func (e *DialEndpoint) DstIP() netip.Addr     { return parseAddrFromTarget(e.Target) }
func (e *DialEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e *DialEndpoint) DstToBytes() []byte    { return e.ident }

// --- ConnEstablishedEndpoint -----------------------------------------------

// ConnEstablishedEndpoint is a live connection-oriented session.  It is
// created at runtime when a connection is established and is discarded when
// the connection dies.
type ConnEstablishedEndpoint struct {
	session     Session
	remoteAddr  string
	TransportID string
	// peerIdent is the same bytes as the DialEndpoint for this peer,
	// ensuring WireGuard matches packets to the correct peer.
	peerIdent []byte
}

// NewConnEstablishedEndpoint creates an endpoint wrapping an active session.
// peerIdent must equal the IdentBytes() of the corresponding DialEndpoint
// so that WireGuard associates inbound and outbound packets correctly.
func NewConnEstablishedEndpoint(transportName, remoteAddr string, sess Session, peerIdent []byte) *ConnEstablishedEndpoint {
	return &ConnEstablishedEndpoint{
		session:     sess,
		remoteAddr:  remoteAddr,
		TransportID: transportName,
		peerIdent:   peerIdent,
	}
}

func (e *ConnEstablishedEndpoint) Kind() EndpointKind   { return KindConnEstablished }
func (e *ConnEstablishedEndpoint) TransportName() string { return e.TransportID }
func (e *ConnEstablishedEndpoint) IdentBytes() []byte    { return e.peerIdent }
func (e *ConnEstablishedEndpoint) Session() Session      { return e.session }
func (e *ConnEstablishedEndpoint) ClearSrc()             {}
func (e *ConnEstablishedEndpoint) SrcToString() string   { return "" }
func (e *ConnEstablishedEndpoint) DstToString() string   { return e.remoteAddr }
func (e *ConnEstablishedEndpoint) DstIP() netip.Addr     { return parseAddrFromTarget(e.remoteAddr) }
func (e *ConnEstablishedEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e *ConnEstablishedEndpoint) DstToBytes() []byte    { return e.peerIdent }

// --- helpers ---------------------------------------------------------------

// buildIdent creates a stable byte slice that encodes transportName and addr.
// The format is: [2-byte name length][name bytes][addr bytes].
func buildIdent(transportName, addr string) []byte {
	nb := []byte(transportName)
	ab := []byte(addr)
	buf := make([]byte, 2+len(nb)+len(ab))
	binary.BigEndian.PutUint16(buf, uint16(len(nb)))
	copy(buf[2:], nb)
	copy(buf[2+len(nb):], ab)
	return buf
}

func parseAddrFromTarget(target string) netip.Addr {
	if ap, err := netip.ParseAddrPort(target); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

// AsTransportEndpoint attempts to cast ep to TransportEndpoint.
// Returns nil when ep is not a transport endpoint.
func AsTransportEndpoint(ep conn.Endpoint) TransportEndpoint {
	te, _ := ep.(TransportEndpoint)
	return te
}
