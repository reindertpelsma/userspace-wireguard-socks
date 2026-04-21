// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// TLSTransport is a connection-oriented transport that wraps the TCP 2-byte
// length-prefix framing in TLS.  Server certificates are managed by
// CertManager (auto-generated or file-based with hot-reload).
type TLSTransport struct {
	name        string
	dialer      ProxyDialer
	listenAddrs []string
	certMgr     *CertManager
	tlsCfg      TLSConfig
}

// NewTLSTransport creates a TLSTransport.
func NewTLSTransport(name string, dialer ProxyDialer, listenAddrs []string, certMgr *CertManager, tlsCfg TLSConfig) *TLSTransport {
	return &TLSTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
	}
}

func (t *TLSTransport) Name() string               { return t.name }
func (t *TLSTransport) IsConnectionOriented() bool { return true }

// Dial opens a client-mode TLS session to target.
func (t *TLSTransport) Dial(ctx context.Context, target string) (Session, error) {
	tcpConn, err := t.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("tls transport %s: dial %s: %w", t.name, target, err)
	}
	clientCfg, err := buildTLSClientConfig(t.tlsCfg, t.certMgr, serverName(target), false)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls transport %s: client config: %w", t.name, err)
	}
	tlsConn := tls.Client(tcpConn, clientCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls transport %s: handshake %s: %w", t.name, target, err)
	}
	return newStreamSession(tlsConn, target, tcpIdleTimeout), nil
}

// Listen binds a TLS listener.
func (t *TLSTransport) Listen(_ context.Context, port int) (Listener, error) {
	serverCfg, err := buildTLSServerConfig(t.tlsCfg, t.certMgr)
	if err != nil {
		return nil, fmt.Errorf("tls transport %s: server config: %w", t.name, err)
	}
	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	var listeners []net.Listener
	chosen := port
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("tls transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			chosen = ln.Addr().(*net.TCPAddr).Port
		}
		listeners = append(listeners, ln)
	}
	return newStreamListener(listeners, t.name, tcpIdleTimeout, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		tlsConn := tls.Server(conn, serverCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tlsConn, nil
	}), nil
}
