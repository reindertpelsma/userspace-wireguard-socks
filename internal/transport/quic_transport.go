// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

// QUICTransport carries WireGuard packets over WebTransport datagrams on
// HTTP/3. This keeps the transport UDP-based while still looking like HTTPS.
type QUICTransport struct {
	name        string
	dialer      ProxyDialer
	listenAddrs []string
	certMgr     *CertManager
	tlsCfg      TLSConfig
	path        string
	// connectHost overrides the host used for DNS lookup and QUIC connection.
	// Empty means use the peer endpoint host.
	connectHost string
	// hostHeader sets the HTTP :authority / Host for domain fronting.
	// Empty means use the peer endpoint host.
	hostHeader string
}

// quicClientPacketConn intentionally hides SyscallConn / OOB-specific methods
// from quic-go. Some restricted sandboxes (notably gVisor) reject the DF /
// PMTU socket options quic-go probes when it can see the raw UDP socket.
type quicClientPacketConn struct {
	net.PacketConn
}

func NewQUICTransport(name string, dialer ProxyDialer, listenAddrs []string, certMgr *CertManager, tlsCfg TLSConfig, path, hostHeader, connectHost string) *QUICTransport {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &QUICTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
		path:        path,
		hostHeader:  hostHeader,
		connectHost: connectHost,
	}
}

func (t *QUICTransport) Name() string               { return t.name }
func (t *QUICTransport) IsConnectionOriented() bool { return true }

func (t *QUICTransport) Dial(ctx context.Context, target string) (Session, error) {
	// SNI is inferred from the peer endpoint host unless tls.server_sni is set.
	tlsCfg, err := buildTLSClientConfig(t.tlsCfg, t.certMgr, serverName(target), false)
	if err != nil {
		return nil, fmt.Errorf("quic transport %s: TLS config: %w", t.name, err)
	}

	// authority is the HTTP/3 :authority (Host header / domain fronting inner host).
	authority := target
	if t.hostHeader != "" {
		authority = t.hostHeader
	}
	urlStr := "https://" + authority + t.path

	// connectTarget is the actual UDP address to dial (domain fronting outer host).
	connectTarget := target
	if t.connectHost != "" {
		_, port, _ := net.SplitHostPort(target)
		connectTarget = net.JoinHostPort(t.connectHost, port)
	}

	var packetConn net.PacketConn
	d := webtransport.Dialer{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			DisablePathMTUDiscovery:          true,
		},
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			pc, err := t.openPacketConn(ctx, connectTarget)
			if err != nil {
				return nil, err
			}
			packetConn = pc
			remoteAddr, err := t.resolveRemoteUDPAddr(connectTarget)
			if err != nil {
				_ = pc.Close()
				packetConn = nil
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, pc, remoteAddr, tlsCfg, cfg)
			if err != nil {
				_ = pc.Close()
				packetConn = nil
				return nil, err
			}
			return conn, nil
		},
	}

	resp, sess, err := d.Dial(ctx, urlStr, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if packetConn != nil {
			_ = packetConn.Close()
		}
		_ = d.Close()
		return nil, fmt.Errorf("quic transport %s: dial %s: %w", t.name, target, err)
	}
	return &quicSession{
		sess: sess,
		closers: []func() error{
			d.Close,
			func() error {
				if packetConn == nil {
					return nil
				}
				return packetConn.Close()
			},
		},
	}, nil
}

func (t *QUICTransport) Listen(_ context.Context, port int) (Listener, error) {
	if t.certMgr == nil {
		return nil, fmt.Errorf("quic transport %s: server certificate manager is required", t.name)
	}

	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}

	acceptCh := make(chan quicAcceptResult, 64)
	closeCh := make(chan struct{})
	var (
		conns   []net.PacketConn
		servers []*webtransport.Server
	)
	chosen := port

	for _, addr := range addrs {
		serverTLS, err := buildTLSServerConfig(t.tlsCfg, t.certMgr)
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("quic transport %s: TLS server config: %w", t.name, err)
		}

		mux := http.NewServeMux()
		h3 := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(serverTLS),
			Handler:   mux,
		}
		server := &webtransport.Server{H3: h3}
		webtransport.ConfigureHTTP3Server(h3)

		mux.HandleFunc(t.path, func(w http.ResponseWriter, r *http.Request) {
			sess, err := server.Upgrade(w, r)
			if err != nil {
				return
			}
			select {
			case acceptCh <- quicAcceptResult{sess: sess}:
				<-sess.Context().Done()
			case <-closeCh:
				_ = sess.CloseWithError(0, "")
			}
		})

		pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("quic transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
				chosen = udpAddr.Port
			}
		}

		conns = append(conns, pc)
		servers = append(servers, server)
		go func(s *webtransport.Server, c net.PacketConn) {
			if err := s.Serve(c); err != nil && !errors.Is(err, net.ErrClosed) {
				select {
				case acceptCh <- quicAcceptResult{err: err}:
				case <-closeCh:
				}
			}
		}(server, pc)
	}

	return &quicListener{
		acceptCh: acceptCh,
		closeCh:  closeCh,
		conns:    conns,
		servers:  servers,
	}, nil
}

func (t *QUICTransport) openPacketConn(ctx context.Context, target string) (net.PacketConn, error) {
	pc, _, err := t.dialer.DialPacket(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("open packet conn: %w", err)
	}
	return quicClientPacketConn{PacketConn: pc}, nil
}

func (t *QUICTransport) resolveRemoteUDPAddr(target string) (net.Addr, error) {
	if d, ok := t.dialer.(*DirectDialer); ok && d.IPv6Translate {
		target = d.translateAddr(target)
	}
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

type quicSession struct {
	sess    *webtransport.Session
	closers []func() error
	closeMu sync.Once
}

func (s *quicSession) ReadPacket() ([]byte, error) {
	return s.sess.ReceiveDatagram(s.sess.Context())
}

func (s *quicSession) WritePacket(pkt []byte) error {
	return s.sess.SendDatagram(pkt)
}

func (s *quicSession) RemoteAddr() string {
	return s.sess.RemoteAddr().String()
}

func (s *quicSession) Close() error {
	var first error
	s.closeMu.Do(func() {
		if err := s.sess.CloseWithError(0, ""); err != nil && first == nil {
			first = err
		}
		for _, closeFn := range s.closers {
			if closeFn == nil {
				continue
			}
			if err := closeFn(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

type quicAcceptResult struct {
	sess *webtransport.Session
	err  error
}

type quicListener struct {
	acceptCh chan quicAcceptResult
	closeCh  chan struct{}
	conns    []net.PacketConn
	servers  []*webtransport.Server

	closeOnce sync.Once
}

func (l *quicListener) Accept(ctx context.Context) (Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closeCh:
		return nil, net.ErrClosed
	case res := <-l.acceptCh:
		if res.err != nil {
			return nil, res.err
		}
		if res.sess == nil {
			return nil, net.ErrClosed
		}
		return &quicSession{sess: res.sess}, nil
	}
}

func (l *quicListener) Addr() net.Addr {
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0].LocalAddr()
}

func (l *quicListener) Close() error {
	var first error
	l.closeOnce.Do(func() {
		close(l.closeCh)
		for _, s := range l.servers {
			if err := s.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, c := range l.conns {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}
