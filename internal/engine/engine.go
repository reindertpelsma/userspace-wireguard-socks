// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package engine wires WireGuard, the gVisor userspace netstack, host proxy
// listeners, transparent inbound forwarding, relay filtering, and the optional
// management API into one long-running runtime.
package engine

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/netstackex"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/wgbind"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Engine struct {
	cfg config.Config
	log *log.Logger

	tun tun.Device
	net *netstackex.Net
	dev *device.Device

	// Runtime API updates mutate peers and ACLs while proxy goroutines are
	// active, so config-derived hot paths use small dedicated locks instead of
	// a single coarse engine lock.
	cfgMu     sync.RWMutex
	allowedMu sync.RWMutex
	aclMu     sync.RWMutex
	allowed   []netip.Prefix
	inACL     acl.List
	outACL    acl.List
	relACL    acl.List

	relayMu        sync.Mutex
	relayFlows     map[relayFlowKey]*relayFlow
	relayLastSweep time.Time

	listenersMu sync.Mutex
	listeners   []net.Listener
	pconns      []net.PacketConn
	listenerMap map[string]net.Listener
	pconnMap    map[string]net.PacketConn
	addrs       map[string]string

	forwardMu    sync.Mutex
	forwardNext  int
	forwardNames map[string]forwardRuntime

	// connTable is the transparent inbound backpressure guard. It tracks only
	// connections that consume host-side sockets; SOCKS/HTTP client sessions are
	// controlled by listener backpressure and per-connection idle timers.
	connMu          sync.Mutex
	connTable       map[int64]*trackedConn
	connNext        int64
	connRejectUntil time.Time
	socketNext      uint64
	closed          chan struct{}

	fallbackDialer proxy.Dialer
	localAddrs     []netip.Addr
	localPrefixes  []netip.Prefix
	dnsSem         chan struct{}
	turnBind       *wgbind.TURNBind
}

type trackedConn struct {
	id      int64
	proto   string
	started time.Time
	close   func()
}

type forwardRuntime struct {
	reverse bool
	forward config.Forward
}

func New(cfg config.Config, logger *log.Logger) (*Engine, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	allowed, err := config.PeerAllowedPrefixes(cfg.WireGuard.Peers)
	if err != nil {
		return nil, err
	}
	localPrefixes, err := config.AddressPrefixes(cfg.WireGuard.Addresses)
	if err != nil {
		return nil, err
	}
	var fallback proxy.Dialer
	if cfg.Proxy.FallbackSOCKS5 != "" {
		fallback, err = proxy.SOCKS5("tcp", cfg.Proxy.FallbackSOCKS5, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
	}
	e := &Engine{
		cfg:            cfg,
		log:            logger,
		allowed:        allowed,
		inACL:          acl.List{Default: cfg.ACL.InboundDefault, Rules: cfg.ACL.Inbound},
		outACL:         acl.List{Default: cfg.ACL.OutboundDefault, Rules: cfg.ACL.Outbound},
		relACL:         acl.List{Default: cfg.ACL.RelayDefault, Rules: cfg.ACL.Relay},
		relayFlows:     make(map[relayFlowKey]*relayFlow),
		addrs:          make(map[string]string),
		listenerMap:    make(map[string]net.Listener),
		pconnMap:       make(map[string]net.PacketConn),
		forwardNames:   make(map[string]forwardRuntime),
		connTable:      make(map[int64]*trackedConn),
		closed:         make(chan struct{}),
		fallbackDialer: fallback,
		localPrefixes:  localPrefixes,
	}
	if cfg.DNSServer.MaxInflight > 0 {
		e.dnsSem = make(chan struct{}, cfg.DNSServer.MaxInflight)
	}
	return e, nil
}

// Start builds the userspace TUN/netstack, starts wireguard-go, then exposes
// the requested host and tunnel listeners. It intentionally does not require
// /dev/net/tun or root privileges.
func (e *Engine) Start() error {
	if err := e.validateWireGuard(); err != nil {
		return err
	}
	localAddrs, err := config.AddressAddrs(e.cfg.WireGuard.Addresses)
	if err != nil {
		return err
	}
	if len(localAddrs) == 0 {
		return errors.New("at least one WireGuard interface address is required")
	}
	dnsAddrs, ignoredDNS := config.DNSAddrs(e.cfg.WireGuard.DNS)
	for _, name := range ignoredDNS {
		e.log.Printf("warning: ignoring non-IP DNS value %q; this runtime only routes IP DNS servers", name)
	}
	var tunnelDNSAddrs []netip.Addr
	for _, dnsAddr := range dnsAddrs {
		if !e.allowedContains(dnsAddr) {
			e.log.Printf("warning: DNS server %s is outside WireGuard AllowedIPs; DNS queries to it will use direct host UDP/TCP, not the tunnel route", dnsAddr)
			continue
		}
		tunnelDNSAddrs = append(tunnelDNSAddrs, dnsAddr)
	}
	tdev, tnet, err := netstackex.CreateNetTUN(localAddrs, tunnelDNSAddrs, e.cfg.WireGuard.MTU)
	if err != nil {
		return err
	}
	e.tun, e.net = tdev, tnet
	if err := e.net.SetTCPReceiveBufferLimit(e.cfg.Inbound.TCPReceiveWindowBytes); err != nil {
		return fmt.Errorf("set TCP receive buffer limit: %w", err)
	}
	if e.cfg.Inbound.TCPMSSClamp != nil && *e.cfg.Inbound.TCPMSSClamp {
		if err := e.net.SetTCPMSSClamp(true); err != nil {
			return fmt.Errorf("set TCP MSS clamping: %w", err)
		}
	}
	e.localAddrs = localAddrs
	e.net.SetIngressPacketFilter(e.allowTunnelPacket)
	e.net.SetPacketFilter(e.allowEgressPacket)

	if e.needsPromiscuousNetstack() {
		if err := e.net.SetPromiscuous(true); err != nil {
			return fmt.Errorf("enable promiscuous netstack: %w", err)
		}
	}
	if e.needsSpoofingNetstack() {
		if err := e.net.SetSpoofing(true); err != nil {
			return fmt.Errorf("enable spoofing netstack: %w", err)
		}
	}
	if *e.cfg.Relay.Enabled {
		if *e.cfg.Inbound.Transparent {
			e.log.Printf("warning: relay and transparent inbound are both enabled; transparent inbound handles unmatched TCP/UDP locally before L3 relay")
		}
		if err := e.net.SetForwarding(true); err != nil {
			return fmt.Errorf("enable forwarding: %w", err)
		}
	}
	if *e.cfg.Inbound.Transparent {
		e.net.SetTCPForwarder(e.cfg.Inbound.TCPReceiveWindowBytes, e.tcpForwarderMaxInFlight(), e.handleTCPForward)
		e.net.SetUDPForwarder(e.handleUDPForward)
		e.net.SetICMPForwarder(e.handleICMPForward)
	}

	// With no ListenPort we avoid binding a UDP port at all. OutboundOnlyBind
	// opens one connected UDP socket per peer endpoint only when WireGuard has
	// traffic to send.
	var bind conn.Bind
	if e.cfg.TURN.Server != "" {
		turnBind := &wgbind.TURNBind{
			Server:       e.cfg.TURN.Server,
			Username:     e.cfg.TURN.Username,
			Password:     e.cfg.TURN.Password,
			Realm:        e.cfg.TURN.Realm,
			AllowedPeers: e.cfg.TURN.Permissions,
		}
		e.turnBind = turnBind
		e.updateTURNPermissions()
		bind = turnBind
	} else if e.cfg.WireGuard.ListenPort == nil {
		bind = wgbind.NewOutboundOnlyBind()
	} else if len(e.cfg.WireGuard.ListenAddresses) > 0 {
		bind = &wgbind.ResolverBind{Inner: &wgbind.ListenBind{Addresses: e.cfg.WireGuard.ListenAddresses}}
	} else {
		bind = &wgbind.ResolverBind{Inner: conn.NewStdNetBind()}
	}
	level := device.LogLevelError
	if e.cfg.Log.Verbose {
		level = device.LogLevelVerbose
	}
	e.dev = device.NewDevice(e.tun, bind, device.NewLogger(level, "uwg "))
	uapi, err := e.uapiConfig()
	if err != nil {
		return err
	}
	if err := e.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wireguard config: %w", err)
	}
	if err := e.dev.Up(); err != nil {
		return fmt.Errorf("wireguard up: %w", err)
	}
	go e.watchStaticEndpointFallback()
	if e.cfg.Scripts.Allow {
		for _, cmd := range e.cfg.WireGuard.PostUp {
			if err := runShell(cmd); err != nil {
				return fmt.Errorf("PostUp %q: %w", cmd, err)
			}
		}
	} else if len(e.cfg.WireGuard.PostUp) > 0 || len(e.cfg.WireGuard.PostDown) > 0 {
		e.log.Printf("warning: PostUp/PostDown are present but scripts.allow is false; commands were not executed")
	}

	if err := e.startProxies(); err != nil {
		return err
	}
	if err := e.startForwards(); err != nil {
		return err
	}
	if err := e.startReverseForwards(); err != nil {
		return err
	}
	if err := e.startDNSServer(); err != nil {
		return err
	}
	if err := e.startAPIServer(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) updateTURNPermissions() {
	if e.turnBind == nil {
		return
	}

	e.cfgMu.RLock()
	var ips []string = e.cfg.TURN.Permissions
	for _, p := range e.cfg.WireGuard.Peers {
		if p.Endpoint != "" {
			ips = append(ips, p.Endpoint)
		}
	}
	e.cfgMu.RUnlock()
	e.turnBind.UpdatePermissions(ips)
}

func (e *Engine) Close() error {
	select {
	case <-e.closed:
		return nil
	default:
		close(e.closed)
	}
	e.listenersMu.Lock()
	for _, l := range e.listeners {
		_ = l.Close()
	}
	for _, pc := range e.pconns {
		_ = pc.Close()
	}
	e.listenersMu.Unlock()
	if e.cfg.Scripts.Allow {
		for _, cmd := range e.cfg.WireGuard.PostDown {
			if err := runShell(cmd); err != nil {
				e.log.Printf("PostDown %q failed: %v", cmd, err)
			}
		}
	}
	if e.dev != nil {
		e.dev.Close()
	} else if e.tun != nil {
		_ = e.tun.Close()
	}
	return nil
}

func (e *Engine) Addr(name string) string {
	e.listenersMu.Lock()
	defer e.listenersMu.Unlock()
	return e.addrs[name]
}

func (e *Engine) uapiConfig() (string, error) {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return wireGuardUAPI(e.cfg.WireGuard)
}

func wireGuardUAPI(wg config.WireGuard) (string, error) {
	var b strings.Builder
	key, err := wgtypes.ParseKey(wg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(key[:]))
	if wg.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *wg.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for _, peer := range wg.Peers {
		pub, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
		if peer.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer preshared key: %w", err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(psk[:]))
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, allowed := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", allowed)
		}
	}
	return b.String(), nil
}

func (e *Engine) watchStaticEndpointFallback() {
	fallback := time.Duration(e.cfg.WireGuard.RoamFallbackSeconds) * time.Second
	if fallback <= 0 || !e.hasStaticPeerEndpoints() {
		return
	}
	interval := fallback / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case now := <-ticker.C:
			e.restoreStaticPeerEndpoints(now, fallback)
		}
	}
}

func (e *Engine) hasStaticPeerEndpoints() bool {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	for _, peer := range e.cfg.WireGuard.Peers {
		if peer.Endpoint != "" {
			return true
		}
	}
	return false
}

func (e *Engine) restoreStaticPeerEndpoints(now time.Time, fallback time.Duration) {
	if e.dev == nil || fallback <= 0 {
		return
	}
	status, err := e.Status()
	if err != nil {
		return
	}
	configured := e.Peers()
	byKey := make(map[string]config.Peer, len(configured))
	for _, peer := range configured {
		if peer.Endpoint != "" {
			byKey[peer.PublicKey] = peer
		}
	}
	for _, live := range status.Peers {
		configuredPeer, ok := byKey[live.PublicKey]
		if !ok || live.Endpoint == "" || live.Endpoint == configuredPeer.Endpoint {
			continue
		}
		if live.HasHandshake {
			last := time.Unix(live.LastHandshakeTimeSec, live.LastHandshakeTimeNsec)
			if now.Sub(last) < fallback {
				continue
			}
		}
		uapi, err := peerUAPI(configuredPeer, false)
		if err != nil {
			continue
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			e.log.Printf("wireguard roam fallback for peer %s failed: %v", live.PublicKey, err)
			continue
		}
		e.log.Printf("wireguard roam fallback restored peer %s endpoint from %s to %s", live.PublicKey, live.Endpoint, configuredPeer.Endpoint)
	}
}

// validateWireGuard catches key-shape errors before the device is created so
// failed starts do not leave partially initialized listeners around.
func (e *Engine) validateWireGuard() error {
	return validateWireGuardConfig(e.cfg.WireGuard)
}

func validateWireGuardConfig(wg config.WireGuard) error {
	if wg.PrivateKey == "" {
		return errors.New("wireguard private key is required")
	}
	if _, err := wgtypes.ParseKey(wg.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	for i, peer := range wg.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("peer %d public key is required", i)
		}
		if _, err := wgtypes.ParseKey(peer.PublicKey); err != nil {
			return fmt.Errorf("peer %d public key: %w", i, err)
		}
		if peer.PresharedKey != "" {
			if _, err := wgtypes.ParseKey(peer.PresharedKey); err != nil {
				return fmt.Errorf("peer %d preshared key: %w", i, err)
			}
		}
	}
	return nil
}

func (e *Engine) startProxies() error {
	if e.cfg.Proxy.SOCKS5 != "" {
		if err := e.startSOCKS("socks5", e.cfg.Proxy.SOCKS5); err != nil {
			return err
		}
	}
	if e.cfg.Proxy.HTTP != "" {
		if err := e.startHTTP("http", e.cfg.Proxy.HTTP); err != nil {
			return err
		}
	}
	for i, addr := range e.cfg.Proxy.HTTPListeners {
		name := fmt.Sprintf("http.%d", i)
		if e.cfg.Proxy.HTTP == "" && i == 0 {
			name = "http"
		}
		if err := e.startHTTP(name, addr); err != nil {
			return err
		}
	}
	if e.cfg.Proxy.Mixed != "" {
		if err := e.startMixed("mixed", e.cfg.Proxy.Mixed); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) needsPromiscuousNetstack() bool {
	if e.cfg.Inbound.Transparent != nil && *e.cfg.Inbound.Transparent {
		return true
	}
	return len(e.cfg.ReverseForwards) > 0
}

func (e *Engine) needsSpoofingNetstack() bool {
	if e.needsPromiscuousNetstack() {
		return true
	}
	for _, f := range e.cfg.Forwards {
		if f.ProxyProtocol != "" {
			return true
		}
	}
	return false
}

func (e *Engine) startSOCKS(name, addr string) error {
	ln, err := listenEndpoint(addr)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("%s proxy stopped: %v", name, err)
				}
				return
			}
			go e.serveSOCKSConn(c)
		}
	}()
	return nil
}

func (e *Engine) startHTTP(name, addr string) error {
	ln, err := listenEndpoint(addr)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	server := &http.Server{Handler: e.httpProxyHandler()}
	go func() {
		if err := server.Serve(ln); err != nil && !isClosedErr(err) {
			e.log.Printf("%s proxy stopped: %v", name, err)
		}
	}()
	return nil
}

func (e *Engine) startMixed(name, addr string) error {
	ln, err := listenEndpoint(addr)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	handler := e.httpProxyHandler()
	go e.serveMixed(ln, handler)
	return nil
}

func (e *Engine) serveMixed(ln net.Listener, handler http.Handler) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if !isClosedErr(err) {
				e.log.Printf("mixed proxy stopped: %v", err)
			}
			return
		}
		go func() {
			br := bufio.NewReader(c)
			b, err := br.Peek(1)
			if err != nil {
				_ = c.Close()
				return
			}
			bc := &bufferedConn{Conn: c, r: br}
			if b[0] == 0x05 {
				e.serveSOCKSConn(bc)
				return
			}
			_ = http.Serve(&oneConnListener{conn: bc}, handler)
		}()
	}
}

func (e *Engine) httpProxyHandler() http.Handler {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return e.proxyDial(ctx, network, addr)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.proxyHTTPAuthOK(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="uwgsocks"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		src := addrPortFromString(r.RemoteAddr)
		if r.URL.Path == "/uwg/socket" {
			e.handleSocketUpgrade(w, r, src)
			return
		}
		if r.Method == http.MethodConnect {
			e.handleHTTPConnect(w, r, src)
			return
		}
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
		if r.URL.Host == "" {
			r.URL.Host = r.Host
		}
		dst, err := e.resolveAddrPort(r.Context(), canonicalHostPort(r.URL.Host, "80"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if !e.outboundAllowed(src, dst, "tcp") {
			http.Error(w, "blocked by outbound ACL", http.StatusForbidden)
			return
		}
		outReq := r.Clone(r.Context())
		outReq.RequestURI = ""
		outReq.Header.Del("Proxy-Connection")
		resp, err := tr.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func (e *Engine) handleHTTPConnect(w http.ResponseWriter, r *http.Request, src netip.AddrPort) {
	dst, err := e.resolveAddrPort(r.Context(), canonicalHostPort(r.Host, "443"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if !e.outboundAllowed(src, dst, "tcp") {
		http.Error(w, "blocked by outbound ACL", http.StatusForbidden)
		return
	}
	target, err := e.proxyDial(r.Context(), "tcp", dst.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = target.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = target.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go proxyBothIdle(client, target, e.tcpIdleTimeout())
}

func (e *Engine) proxyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := e.proxyDialWithSource(ctx, network, addr, netip.AddrPort{}, false)
	return withTCPIdle(network, c, err, e.tcpIdleTimeout())
}

// dialTunnelOnly is used by local port forwards and library calls that must
// not escape to the host network. It enforces outbound ACLs and peer AllowedIPs.
func (e *Engine) dialTunnelOnly(ctx context.Context, network, addr string, src netip.AddrPort) (net.Conn, error) {
	return e.dialTunnelOnlyWithBind(ctx, network, addr, src, netip.AddrPort{})
}

func (e *Engine) dialTunnelOnlyWithBind(ctx context.Context, network, addr string, aclSrc, bindSrc netip.AddrPort) (net.Conn, error) {
	candidates, err := e.resolveAddrPortCandidates(ctx, network, addr, strings.HasPrefix(network, "udp"))
	if err != nil {
		return nil, err
	}
	var last error
	for _, dst := range candidates {
		if !e.outboundAllowed(aclSrc, dst, network) {
			last = errProxyACL
			continue
		}
		if !e.allowedContains(dst.Addr()) {
			last = fmt.Errorf("%s does not match any WireGuard AllowedIPs", dst.Addr())
			continue
		}
		c, err := e.dialNetstack(ctx, network, bindSrc, dst)
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("no destination matches any WireGuard AllowedIPs")
	}
	return nil, last
}

func (e *Engine) dialNetstack(ctx context.Context, network string, bindSrc, dst netip.AddrPort) (net.Conn, error) {
	switch networkBase(network) {
	case "udp":
		if bindSrc.IsValid() {
			return e.net.DialUDPAddrPort(bindSrc, dst)
		}
		return e.net.DialUDPAddrPort(netip.AddrPort{}, dst)
	default:
		if bindSrc.IsValid() {
			return e.net.DialContextTCPAddrPortWithBind(ctx, bindSrc, dst)
		}
		return e.net.DialContext(ctx, network, dst.String())
	}
}

func (e *Engine) resolveAddrPort(ctx context.Context, addr string) (netip.AddrPort, error) {
	candidates, err := e.resolveAddrPortCandidates(ctx, "tcp", addr, false)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(candidates) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no usable addresses for %s", addr)
	}
	return candidates[0], nil
}

func (e *Engine) lookupHost(ctx context.Context, host string) ([]string, error) {
	dnsAddrs, _ := config.DNSAddrs(e.cfg.WireGuard.DNS)
	if len(dnsAddrs) > 0 {
		var tunnelDNS, directDNS []netip.Addr
		for _, addr := range dnsAddrs {
			if e.allowedContains(addr) {
				tunnelDNS = append(tunnelDNS, addr)
			} else {
				directDNS = append(directDNS, addr)
			}
		}
		if len(tunnelDNS) > 0 {
			addrs, err := e.net.LookupContextHost(ctx, host)
			if err == nil {
				return addrs, nil
			}
			if len(directDNS) == 0 {
				return nil, err
			}
			e.log.Printf("warning: tunnel DNS lookup for %s failed, trying configured direct DNS servers: %v", host, err)
		}
		if len(directDNS) > 0 {
			return lookupHostWithDNSServers(ctx, host, directDNS)
		}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return out, nil
}

// lookupHostWithDNSServers uses configured DNS servers that are outside
// WireGuard AllowedIPs. It is still not a system resolver fallback: the caller
// provided these servers explicitly through DNS=.
func lookupHostWithDNSServers(ctx context.Context, host string, servers []netip.Addr) ([]string, error) {
	if len(servers) == 0 {
		return nil, errors.New("no configured DNS servers")
	}
	name := dns.Fqdn(host)
	seen := make(map[string]struct{})
	var out []string
	var last error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, server := range servers {
			resp, err := exchangeConfiguredDNS(ctx, server, name, qtype, false)
			if err != nil || resp.Truncated {
				resp, err = exchangeConfiguredDNS(ctx, server, name, qtype, true)
			}
			if err != nil {
				last = err
				continue
			}
			if resp.Rcode == dns.RcodeNameError {
				continue
			}
			if resp.Rcode != dns.RcodeSuccess {
				last = fmt.Errorf("dns server %s rcode %s", server, dns.RcodeToString[resp.Rcode])
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					ip, ok := netip.AddrFromSlice(v.A)
					if !ok {
						continue
					}
					s := ip.Unmap().String()
					if _, ok := seen[s]; !ok {
						seen[s] = struct{}{}
						out = append(out, s)
					}
				case *dns.AAAA:
					ip, ok := netip.AddrFromSlice(v.AAAA)
					if !ok {
						continue
					}
					s := ip.Unmap().String()
					if _, ok := seen[s]; !ok {
						seen[s] = struct{}{}
						out = append(out, s)
					}
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("no addresses for %s", host)
}

// exchangeConfiguredDNS tracks DNS transaction IDs explicitly because this path
// crosses the hostile host network instead of the WireGuard netstack resolver.
func exchangeConfiguredDNS(ctx context.Context, server netip.Addr, name string, qtype uint16, tcp bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.RecursionDesired = true
	netw := "udp"
	if tcp {
		netw = "tcp"
	}
	client := &dns.Client{Net: netw, Timeout: 5 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
		if timeout < client.Timeout {
			client.Timeout = timeout
		}
	}
	done := make(chan struct {
		resp *dns.Msg
		err  error
	}, 1)
	go func() {
		resp, _, err := client.Exchange(req, net.JoinHostPort(server.String(), "53"))
		done <- struct {
			resp *dns.Msg
			err  error
		}{resp: resp, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		if res.resp == nil || res.resp.Id != req.Id || !res.resp.Response {
			return nil, errors.New("invalid DNS response transaction")
		}
		return res.resp, nil
	}
}

// handleTCPForward terminates an inbound TCP flow from the WireGuard netstack
// and creates a fresh host TCP connection to the original destination.
func (e *Engine) handleTCPForward(req *gtcp.ForwarderRequest) {
	id := req.ID()
	src, dst, ok := idAddrs(id)
	if !ok || !e.inboundAllowed(src, dst, "tcp") || e.rejectTransparentDestination(dst) {
		req.Complete(true)
		return
	}
	connID, acquired := e.acquireConn("tcp")
	if !acquired {
		req.Complete(true)
		return
	}
	defer e.releaseConn(connID)
	host, err := e.dialHostForInbound(context.Background(), "tcp", dst, src.Port())
	if err != nil {
		e.log.Printf("tcp forward host dial %s failed: %v", dst, err)
		req.Complete(true)
		return
	}
	defer host.Close()
	tconn, err := netstackex.NewTCPConnFromForwarder(req)
	if err != nil {
		e.log.Printf("tcp forward endpoint failed: %v", err)
		req.Complete(true)
		return
	}
	req.Complete(false)
	defer tconn.Close()
	e.setConnCloser(connID, func() {
		_ = tconn.Close()
		_ = host.Close()
	})
	proxyBothIdle(tconn, host, e.tcpIdleTimeout())
}

// handleUDPForward does the same transparent termination for UDP. Empty
// datagrams count as activity because some protocols use them as keepalives or
// probes.
func (e *Engine) handleUDPForward(req *gudp.ForwarderRequest) {
	id := req.ID()
	src, dst, ok := idAddrs(id)
	if !ok || !e.inboundAllowed(src, dst, "udp") || e.rejectTransparentDestination(dst) {
		if ok {
			e.sendUDPUnreachable(src, dst)
		}
		return
	}
	connID, acquired := e.acquireConn("udp")
	if !acquired {
		e.sendUDPUnreachable(src, dst)
		return
	}
	uconn, err := netstackex.NewUDPConnFromForwarder(req)
	if err != nil {
		e.sendUDPUnreachable(src, dst)
		e.releaseConn(connID)
		return
	}
	host, err := e.dialHostForInbound(context.Background(), "udp", dst, src.Port())
	if err != nil {
		e.sendUDPUnreachable(src, dst)
		_ = uconn.Close()
		e.releaseConn(connID)
		return
	}
	timeout := e.udpIdleTimeout()
	e.setConnCloser(connID, func() {
		_ = uconn.Close()
		_ = host.Close()
	})
	go func() {
		defer e.releaseConn(connID)
		defer uconn.Close()
		defer host.Close()
		proxyUDP(uconn, host, timeout)
	}()
}

// dialHostForInbound implements ConsistentPort. Strict mode fails if the
// source port cannot be preserved, loose mode falls back to an ephemeral port,
// and disabled mode always lets the kernel pick the host source port.
func (e *Engine) dialHostForInbound(ctx context.Context, network string, dst netip.AddrPort, srcPort uint16) (net.Conn, error) {
	if rewritten, ok, err := e.inboundHostForwardTarget(dst); err != nil {
		return nil, err
	} else if ok {
		dst = rewritten
	}
	if c, matched, err := e.dialOutboundProxy(ctx, network, dst, outboundRoleInbound); matched || err != nil {
		return c, err
	}
	mode := e.cfg.Inbound.ConsistentPort
	usePort := mode != "disabled"
	if *e.cfg.Inbound.DisableLowPorts && srcPort < 1024 {
		usePort = false
		if mode == "strict" {
			return nil, fmt.Errorf("strict source-port binding rejected privileged port %d", srcPort)
		}
	}
	dialOnce := func(bind bool) (net.Conn, error) {
		if e.cfg.Inbound.HostDialProxySOCKS5 != "" && strings.HasPrefix(network, "tcp") {
			if bind && mode == "strict" {
				return nil, errors.New("strict source-port binding is incompatible with host_dial_proxy_socks5")
			}
			d, err := proxy.SOCKS5("tcp", e.cfg.Inbound.HostDialProxySOCKS5, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, dst.String())
			}
			return d.Dial(network, dst.String())
		}
		d := net.Dialer{}
		var bindIP net.IP
		if e.cfg.Inbound.HostDialBindAddress != "" {
			if ip, err := netip.ParseAddr(e.cfg.Inbound.HostDialBindAddress); err == nil {
				bindIP = net.IP(ip.AsSlice())
			}
		}
		if bind {
			if strings.HasPrefix(network, "tcp") {
				d.LocalAddr = &net.TCPAddr{IP: bindIP, Port: int(srcPort)}
			} else {
				d.LocalAddr = &net.UDPAddr{IP: bindIP, Port: int(srcPort)}
			}
		} else if bindIP != nil {
			if strings.HasPrefix(network, "tcp") {
				d.LocalAddr = &net.TCPAddr{IP: bindIP}
			} else {
				d.LocalAddr = &net.UDPAddr{IP: bindIP}
			}
		}
		return d.DialContext(ctx, network, dst.String())
	}
	if usePort {
		c, err := dialOnce(true)
		if err == nil || mode == "strict" {
			return c, err
		}
	}
	return dialOnce(false)
}

func (e *Engine) tcpIdleTimeout() time.Duration {
	if e.cfg.Inbound.TCPIdleTimeoutSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(e.cfg.Inbound.TCPIdleTimeoutSeconds) * time.Second
}

func (e *Engine) udpIdleTimeout() time.Duration {
	if e.cfg.Inbound.UDPIdleTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(e.cfg.Inbound.UDPIdleTimeoutSeconds) * time.Second
}

func (e *Engine) tcpForwarderMaxInFlight() int {
	limit := e.tcpMemoryConnectionLimit()
	if e.cfg.Inbound.MaxConnections > 0 {
		limit = minPositive(limit, e.cfg.Inbound.MaxConnections)
	}
	if limit <= 0 {
		return 1024
	}
	return limit
}

func (e *Engine) tcpMemoryConnectionLimit() int {
	maxBuffered := e.cfg.Inbound.TCPMaxBufferedBytes
	if maxBuffered <= 0 {
		return 0
	}
	perConn := e.cfg.Inbound.TCPReceiveWindowBytes
	if perConn <= 0 {
		perConn = 1 << 20
	}
	return max(1, maxBuffered/perConn)
}

// acquireConn enforces the transparent inbound connection table limit. When
// the table is full it reaps the oldest TCP connection older than the grace
// window; UDP is intentionally never reaped here because UDP sessions already
// expire after the much shorter UDP idle timeout.
func (e *Engine) acquireConn(proto string) (int64, bool) {
	grace := time.Duration(e.cfg.Inbound.ConnectionTableGraceSeconds) * time.Second
	now := time.Now()
	var closeVictims []func()

	e.connMu.Lock()
	if e.cfg.Inbound.MaxConnections > 0 && len(e.connTable) >= e.cfg.Inbound.MaxConnections {
		var victim *trackedConn
		for _, c := range e.connTable {
			if c.proto != "tcp" || now.Sub(c.started) < grace {
				continue
			}
			if victim == nil || c.started.Before(victim.started) {
				victim = c
			}
		}
		if victim == nil {
			if e.connRejectUntil.IsZero() || now.After(e.connRejectUntil) {
				e.connRejectUntil = now.Add(grace)
			}
			e.connMu.Unlock()
			return 0, false
		}
		delete(e.connTable, victim.id)
		if victim.close != nil {
			closeVictims = append(closeVictims, victim.close)
		}
	}
	if proto == "tcp" {
		tcpLimit := e.tcpMemoryConnectionLimit()
		if tcpLimit > 0 && e.trackedProtoCountLocked("tcp") >= tcpLimit {
			var victim *trackedConn
			for _, c := range e.connTable {
				if c.proto != "tcp" || now.Sub(c.started) < grace {
					continue
				}
				if victim == nil || c.started.Before(victim.started) {
					victim = c
				}
			}
			if victim == nil {
				if e.connRejectUntil.IsZero() || now.After(e.connRejectUntil) {
					e.connRejectUntil = now.Add(grace)
				}
				e.connMu.Unlock()
				return 0, false
			}
			delete(e.connTable, victim.id)
			if victim.close != nil {
				closeVictims = append(closeVictims, victim.close)
			}
		}
	}
	e.connNext++
	id := e.connNext
	e.connTable[id] = &trackedConn{
		id:      id,
		proto:   proto,
		started: now,
	}
	e.connMu.Unlock()

	for _, closeVictim := range closeVictims {
		go closeVictim()
	}
	return id, true
}

func (e *Engine) trackedProtoCountLocked(proto string) int {
	count := 0
	for _, c := range e.connTable {
		if c.proto == proto {
			count++
		}
	}
	return count
}

func (e *Engine) setConnCloser(id int64, closeFn func()) {
	if id == 0 || closeFn == nil {
		return
	}
	e.connMu.Lock()
	if c := e.connTable[id]; c != nil {
		c.close = closeFn
	}
	e.connMu.Unlock()
}

func (e *Engine) releaseConn(id int64) {
	if id == 0 {
		return
	}
	e.connMu.Lock()
	delete(e.connTable, id)
	e.connMu.Unlock()
}

func (e *Engine) startForwards() error {
	for i, f := range e.cfg.Forwards {
		name := fmt.Sprintf("forward.%d", i)
		switch f.Proto {
		case "tcp":
			if err := e.startTCPForward(name, f); err != nil {
				return err
			}
		case "udp":
			if err := e.startUDPForward(name, f); err != nil {
				return err
			}
		}
		e.registerForwardRuntime(name, false, f)
	}
	return nil
}

func (e *Engine) startReverseForwards() error {
	for i, f := range e.cfg.ReverseForwards {
		name := fmt.Sprintf("reverse_forward.%d", i)
		switch f.Proto {
		case "tcp":
			if err := e.startTCPReverseForward(name, f); err != nil {
				return err
			}
		case "udp":
			if err := e.startUDPReverseForward(name, f); err != nil {
				return err
			}
		}
		e.registerForwardRuntime(name, true, f)
	}
	return nil
}

func (e *Engine) registerForwardRuntime(name string, reverse bool, f config.Forward) {
	e.forwardMu.Lock()
	defer e.forwardMu.Unlock()
	e.forwardNames[name] = forwardRuntime{reverse: reverse, forward: f}
}

func (e *Engine) startForwardRuntime(name string, reverse bool, f config.Forward) error {
	if reverse {
		switch f.Proto {
		case "tcp":
			return e.startTCPReverseForward(name, f)
		case "udp":
			return e.startUDPReverseForward(name, f)
		}
	} else {
		switch f.Proto {
		case "tcp":
			return e.startTCPForward(name, f)
		case "udp":
			return e.startUDPForward(name, f)
		}
	}
	return fmt.Errorf("unsupported forward proto %q", f.Proto)
}

func (e *Engine) startTCPForward(name string, f config.Forward) error {
	ln, err := net.Listen("tcp", f.Listen)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("tcp forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			go func() {
				defer c.Close()
				aclSrc := addrPortFromNetAddr(c.RemoteAddr())
				bindSrc := netip.AddrPort{}
				srcConn := net.Conn(c)
				if f.ProxyProtocol != "" {
					_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
					wrapped, pp, err := parseProxyProtocolConn(c, f.ProxyProtocol)
					_ = c.SetReadDeadline(time.Time{})
					if err != nil {
						e.log.Printf("tcp forward %s PROXY header failed: %v", f.Listen, err)
						return
					}
					srcConn = wrapped
					if pp.Source.IsValid() {
						aclSrc = pp.Source
						bindSrc = pp.Source
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				dst, err := e.dialTunnelOnlyWithBind(ctx, "tcp", f.Target, aclSrc, bindSrc)
				if err != nil {
					e.log.Printf("tcp forward %s -> %s failed: %v", f.Listen, f.Target, err)
					return
				}
				defer dst.Close()
				proxyBothIdle(srcConn, dst, e.tcpIdleTimeout())
			}()
		}
	}()
	return nil
}

func (e *Engine) startUDPForward(name string, f config.Forward) error {
	pc, err := net.ListenPacket("udp", f.Listen)
	if err != nil {
		return err
	}
	e.addPacketConn(name, pc)
	go e.serveUDPForward(pc, f)
	return nil
}

func (e *Engine) serveUDPForward(pc net.PacketConn, f config.Forward) {
	type session struct {
		conn  net.Conn
		timer *time.Timer
	}
	var mu sync.Mutex
	sessions := make(map[string]*session)
	timeout := e.udpIdleTimeout()
	expire := func(k string, sess *session) {
		_ = sess.conn.Close()
		mu.Lock()
		if sessions[k] == sess {
			delete(sessions, k)
		}
		mu.Unlock()
	}
	touch := func(sess *session) {
		if timeout > 0 && sess.timer != nil {
			sess.timer.Reset(timeout)
		}
	}
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if !isClosedErr(err) {
				e.log.Printf("udp forward %s stopped: %v", f.Listen, err)
			}
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		source := addrPortFromNetAddr(addr)
		bindSrc := netip.AddrPort{}
		if f.ProxyProtocol != "" {
			stripped, pp, err := stripProxyProtocolDatagram(payload, f.ProxyProtocol)
			if err != nil {
				e.log.Printf("udp forward %s PROXY header failed: %v", f.Listen, err)
				continue
			}
			payload = stripped
			if pp.Source.IsValid() {
				source = pp.Source
				bindSrc = pp.Source
			}
		}
		key := source.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			c, err := e.dialTunnelOnlyWithBind(ctx, "udp", f.Target, source, bindSrc)
			cancel()
			if err != nil {
				e.log.Printf("udp forward %s -> %s failed: %v", f.Listen, f.Target, err)
				mu.Unlock()
				continue
			}
			s = &session{conn: c}
			if timeout > 0 {
				s.timer = time.AfterFunc(timeout, func() { expire(key, s) })
			}
			sessions[key] = s
			clientAddr := addr
			go func(k string, sess *session) {
				defer sess.conn.Close()
				defer func() {
					if sess.timer != nil {
						sess.timer.Stop()
					}
				}()
				rb := make([]byte, 64*1024)
				for {
					n, err := sess.conn.Read(rb)
					if err != nil {
						mu.Lock()
						if sessions[k] == sess {
							delete(sessions, k)
						}
						mu.Unlock()
						return
					}
					touch(sess)
					_, _ = pc.WriteTo(rb[:n], clientAddr)
					touch(sess)
				}
			}(key, s)
		}
		touch(s)
		mu.Unlock()
		_, _ = s.conn.Write(payload)
		touch(s)
	}
}

func (e *Engine) startTCPReverseForward(name string, f config.Forward) error {
	listen, err := netip.ParseAddrPort(f.Listen)
	if err != nil {
		return fmt.Errorf("%s listen: %w", name, err)
	}
	ln, err := e.net.ListenTCPAddrPort(listen)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("tcp reverse forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			go e.handleTCPReverseForwardConn(c, f)
		}
	}()
	return nil
}

func (e *Engine) handleTCPReverseForwardConn(tunnel net.Conn, f config.Forward) {
	defer tunnel.Close()
	src := addrPortFromNetAddr(tunnel.RemoteAddr())
	dst := addrPortFromNetAddr(tunnel.LocalAddr())
	if src.IsValid() && dst.IsValid() && !e.inboundAllowed(src, dst, "tcp") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var d net.Dialer
	host, err := d.DialContext(ctx, "tcp", f.Target)
	if err != nil {
		e.log.Printf("tcp reverse forward %s -> %s failed: %v", f.Listen, f.Target, err)
		return
	}
	defer host.Close()
	if f.ProxyProtocol != "" {
		header, err := proxyProtocolBytes(f.ProxyProtocol, "tcp", src, dst)
		if err != nil {
			e.log.Printf("tcp reverse forward %s PROXY header failed: %v", f.Listen, err)
			return
		}
		if len(header) > 0 {
			if _, err := host.Write(header); err != nil {
				e.log.Printf("tcp reverse forward %s PROXY header write failed: %v", f.Listen, err)
				return
			}
		}
	}
	proxyBothIdle(tunnel, host, e.tcpIdleTimeout())
}

func (e *Engine) startUDPReverseForward(name string, f config.Forward) error {
	listen, err := netip.ParseAddrPort(f.Listen)
	if err != nil {
		return fmt.Errorf("%s listen: %w", name, err)
	}
	pc, err := e.net.ListenUDPAddrPort(listen)
	if err != nil {
		return err
	}
	e.addPacketConn(name, pc)
	go e.serveUDPReverseForward(pc, f)
	return nil
}

func (e *Engine) serveUDPReverseForward(pc net.PacketConn, f config.Forward) {
	type session struct {
		conn  net.Conn
		timer *time.Timer
	}
	var mu sync.Mutex
	sessions := make(map[string]*session)
	timeout := e.udpIdleTimeout()
	expire := func(k string, sess *session) {
		_ = sess.conn.Close()
		mu.Lock()
		if sessions[k] == sess {
			delete(sessions, k)
		}
		mu.Unlock()
	}
	touch := func(sess *session) {
		if timeout > 0 && sess.timer != nil {
			sess.timer.Reset(timeout)
		}
	}
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if !isClosedErr(err) {
				e.log.Printf("udp reverse forward %s stopped: %v", f.Listen, err)
			}
			return
		}
		src := addrPortFromNetAddr(addr)
		dst := addrPortFromNetAddr(pc.LocalAddr())
		if src.IsValid() && dst.IsValid() && !e.inboundAllowed(src, dst, "udp") {
			continue
		}
		key := src.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var d net.Dialer
			c, err := d.DialContext(ctx, "udp", f.Target)
			cancel()
			if err != nil {
				e.log.Printf("udp reverse forward %s -> %s failed: %v", f.Listen, f.Target, err)
				mu.Unlock()
				continue
			}
			s = &session{conn: c}
			if timeout > 0 {
				s.timer = time.AfterFunc(timeout, func() { expire(key, s) })
			}
			sessions[key] = s
			clientAddr := addr
			go func(k string, sess *session) {
				defer sess.conn.Close()
				defer func() {
					if sess.timer != nil {
						sess.timer.Stop()
					}
				}()
				rb := make([]byte, 64*1024)
				for {
					n, err := sess.conn.Read(rb)
					if err != nil {
						mu.Lock()
						if sessions[k] == sess {
							delete(sessions, k)
						}
						mu.Unlock()
						return
					}
					touch(sess)
					_, _ = pc.WriteTo(rb[:n], clientAddr)
					touch(sess)
				}
			}(key, s)
		}
		touch(s)
		mu.Unlock()
		payload := buf[:n]
		if f.ProxyProtocol != "" {
			header, err := proxyProtocolBytes(f.ProxyProtocol, "udp", src, dst)
			if err != nil {
				e.log.Printf("udp reverse forward %s PROXY header failed: %v", f.Listen, err)
				continue
			}
			packet := make([]byte, 0, len(header)+n)
			packet = append(packet, header...)
			packet = append(packet, payload...)
			payload = packet
		}
		_, _ = s.conn.Write(payload)
		touch(s)
	}
}

// startDNSServer binds a DNS server inside the userspace tunnel, not on the
// host network. It lets this peer act as the DNS egress for other WireGuard
// peers without exposing a host-side UDP/TCP 53 listener.
func (e *Engine) startDNSServer() error {
	if e.cfg.DNSServer.Listen == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(e.cfg.DNSServer.Listen)
	if err != nil {
		return err
	}
	u, err := e.net.ListenUDPAddrPort(addr)
	if err != nil {
		return fmt.Errorf("dns udp listen: %w", err)
	}
	t, err := e.net.ListenTCPAddrPort(addr)
	if err != nil {
		_ = u.Close()
		return fmt.Errorf("dns tcp listen: %w", err)
	}
	go e.serveTunnelDNSUDP(u)
	go e.serveTunnelDNSTCP(t)
	return nil
}

// serveTunnelDNSUDP preserves the client transaction ID by forwarding the
// original dns.Msg to the host resolver and writing the matching response back
// to the same tunnel source address.
func (e *Engine) serveTunnelDNSUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !e.acquireDNSTransaction() {
			resp := new(dns.Msg)
			resp.SetRcode(&msg, dns.RcodeRefused)
			if packed, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(packed, addr)
			}
			continue
		}
		go func(req dns.Msg, addr net.Addr) {
			defer e.releaseDNSTransaction()
			resp, err := systemDNSExchange(&req, false)
			if err != nil {
				resp = new(dns.Msg)
				resp.SetRcode(&req, dns.RcodeServerFailure)
			}
			packed, err := resp.Pack()
			if err == nil {
				_, _ = pc.WriteTo(packed, addr)
			}
		}(msg, addr)
	}
}

func (e *Engine) serveTunnelDNSTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			dc := &dns.Conn{Conn: c}
			for {
				req, err := dc.ReadMsg()
				if err != nil {
					return
				}
				if !e.acquireDNSTransaction() {
					resp := new(dns.Msg)
					resp.SetRcode(req, dns.RcodeRefused)
					if err := dc.WriteMsg(resp); err != nil {
						return
					}
					continue
				}
				resp, err := systemDNSExchange(req, true)
				e.releaseDNSTransaction()
				if err != nil {
					resp = new(dns.Msg)
					resp.SetRcode(req, dns.RcodeServerFailure)
				}
				if err := dc.WriteMsg(resp); err != nil {
					return
				}
			}
		}()
	}
}

func (e *Engine) acquireDNSTransaction() bool {
	if e.dnsSem == nil {
		return true
	}
	select {
	case e.dnsSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (e *Engine) releaseDNSTransaction() {
	if e.dnsSem == nil {
		return
	}
	select {
	case <-e.dnsSem:
	default:
	}
}

var systemDNSExchange = exchangeSystemDNS

// exchangeSystemDNS is the production DNS egress hook for the tunnel-hosted DNS
// server. Tests replace systemDNSExchange so they can assert transaction
// behavior without relying on public DNS.
func exchangeSystemDNS(req *dns.Msg, tcp bool) (*dns.Msg, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil, errors.New("no system DNS servers")
	}
	netw := "udp"
	if tcp {
		netw = "tcp"
	}
	client := &dns.Client{Net: netw, Timeout: 5 * time.Second}
	var last error
	for _, s := range cfg.Servers {
		resp, _, err := client.Exchange(req, net.JoinHostPort(s, cfg.Port))
		if err == nil && resp != nil && resp.Id == req.Id && resp.Response {
			return resp, nil
		}
		if err == nil {
			err = errors.New("invalid DNS response transaction")
		}
		last = err
	}
	return nil, last
}

// exchangeSystemDNSAuto is used when the application needs a complete DNS
// answer rather than faithfully proxying a single UDP DNS transaction. It tries
// UDP first, then retries over TCP when UDP fails or returns a truncated
// response.
func exchangeSystemDNSAuto(req *dns.Msg) (*dns.Msg, error) {
	resp, err := systemDNSExchange(req, false)
	if err == nil && resp != nil && !resp.Truncated {
		return resp, nil
	}
	tcpResp, tcpErr := systemDNSExchange(req, true)
	if tcpErr == nil {
		return tcpResp, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, tcpErr
}

func (e *Engine) addListener(name string, ln net.Listener) {
	e.listenersMu.Lock()
	defer e.listenersMu.Unlock()
	e.listeners = append(e.listeners, ln)
	e.listenerMap[name] = ln
	e.addrs[name] = ln.Addr().String()
	e.log.Printf("%s listening on %s", name, ln.Addr())
}

func (e *Engine) addPacketConn(name string, pc net.PacketConn) {
	e.listenersMu.Lock()
	defer e.listenersMu.Unlock()
	e.pconns = append(e.pconns, pc)
	e.pconnMap[name] = pc
	e.addrs[name] = pc.LocalAddr().String()
	e.log.Printf("%s listening on %s", name, pc.LocalAddr())
}

func (e *Engine) closeListenerName(name string) bool {
	e.listenersMu.Lock()
	ln := e.listenerMap[name]
	pc := e.pconnMap[name]
	delete(e.listenerMap, name)
	delete(e.pconnMap, name)
	delete(e.addrs, name)
	e.listenersMu.Unlock()
	closed := false
	if ln != nil {
		_ = ln.Close()
		closed = true
	}
	if pc != nil {
		_ = pc.Close()
		closed = true
	}
	return closed
}

func (e *Engine) allowedContains(ip netip.Addr) bool {
	_, ok := e.allowedBestPrefix(ip)
	return ok
}

func (e *Engine) allowedBestPrefix(ip netip.Addr) (netip.Prefix, bool) {
	ip = ip.Unmap()
	e.allowedMu.RLock()
	defer e.allowedMu.RUnlock()
	var (
		best netip.Prefix
		ok   bool
	)
	for _, p := range e.allowed {
		if p.Contains(ip) {
			if !ok || p.Bits() > best.Bits() {
				best = p
				ok = true
			}
		}
	}
	return best, ok
}

func (e *Engine) inboundAllowed(src, dst netip.AddrPort, network string) bool {
	e.aclMu.RLock()
	defer e.aclMu.RUnlock()
	return e.inACL.Allowed(src, dst, network)
}

func (e *Engine) outboundAllowed(src, dst netip.AddrPort, network string) bool {
	e.aclMu.RLock()
	defer e.aclMu.RUnlock()
	return e.outACL.Allowed(src, dst, network)
}

func (e *Engine) relayAllowed(src, dst netip.AddrPort, network string) bool {
	e.aclMu.RLock()
	defer e.aclMu.RUnlock()
	return e.relACL.Allowed(src, dst, network)
}

func (e *Engine) localAddrContains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, local := range e.localAddrs {
		if local == ip {
			return true
		}
	}
	return false
}

func (e *Engine) localPrefixContainsUnrouted(ip netip.Addr) bool {
	if e.cfg.Routing.EnforceAddressSubnets == nil || !*e.cfg.Routing.EnforceAddressSubnets {
		return false
	}
	ip = ip.Unmap()
	if e.localAddrContains(ip) || e.allowedContains(ip) {
		return false
	}
	for _, p := range e.localPrefixes {
		maxBits := 128
		if p.Addr().Is4() {
			maxBits = 32
		}
		if p.Bits() == maxBits {
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) allowEgressPacket(packet []byte) bool {
	if !e.allowTunnelPacket(packet) {
		return false
	}
	if *e.cfg.Relay.Enabled {
		return e.allowRelayPacket(packet)
	}
	return true
}

func (e *Engine) allowTunnelPacket(packet []byte) bool {
	_, src, dst, ok := packetAddrPorts(packet)
	if !ok {
		return true
	}
	if src.Addr() == dst.Addr() {
		return false
	}
	return !e.tunnelAddrBlocked(src.Addr()) && !e.tunnelAddrBlocked(dst.Addr())
}

func (e *Engine) tunnelAddrBlocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() {
		return e.cfg.Filtering.DropIPv6LinkLocalMulticast != nil &&
			*e.cfg.Filtering.DropIPv6LinkLocalMulticast &&
			(ip.IsLinkLocalUnicast() || ip.IsMulticast())
	}
	if !ip.Is4() || e.cfg.Filtering.DropIPv4Invalid == nil || !*e.cfg.Filtering.DropIPv4Invalid {
		return false
	}
	return ipv4InvalidTunnelAddr(ip)
}

func (e *Engine) rejectTransparentDestination(dst netip.AddrPort) bool {
	ip := dst.Addr().Unmap()
	if e.tunnelAddrBlocked(ip) {
		return true
	}
	return e.localPrefixContainsUnrouted(ip)
}

func (e *Engine) inboundHostForwardTarget(dst netip.AddrPort) (netip.AddrPort, bool, error) {
	ip := dst.Addr().Unmap()
	if !e.localAddrContains(ip) {
		return dst, false, nil
	}
	return e.hostForwardTarget(dst, e.cfg.HostForward.Inbound, "inbound")
}

func (e *Engine) proxyHostForwardTarget(dst netip.AddrPort) (netip.AddrPort, bool, error) {
	ip := dst.Addr().Unmap()
	if !e.localAddrContains(ip) && !(ip.Is4() && netip.MustParsePrefix("127.0.0.0/8").Contains(ip)) {
		return dst, false, nil
	}
	return e.hostForwardTarget(dst, e.cfg.HostForward.Proxy, "proxy")
}

func (e *Engine) hostForwardTarget(dst netip.AddrPort, rule config.HostForwardEndpoint, scope string) (netip.AddrPort, bool, error) {
	if rule.Enabled == nil || !*rule.Enabled {
		return dst, true, fmt.Errorf("%s host forwarding is disabled", scope)
	}
	var ip netip.Addr
	if rule.RedirectIP != "" {
		var err error
		ip, err = netip.ParseAddr(rule.RedirectIP)
		if err != nil {
			return dst, true, err
		}
	} else if dst.Addr().Is6() {
		ip = netip.IPv6Loopback()
	} else {
		ip = netip.MustParseAddr("127.0.0.1")
	}
	return netip.AddrPortFrom(ip, dst.Port()), true, nil
}

func ipv4InvalidTunnelAddr(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if ip == netip.MustParseAddr("255.255.255.255") {
		return true
	}
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
	} {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) allowRelayPacket(packet []byte) bool {
	meta, ok := parseRelayPacket(packet)
	if !ok || e.localAddrContains(meta.src.Addr()) {
		return true
	}
	if e.localPrefixContainsUnrouted(meta.dst.Addr()) {
		return false
	}
	if e.cfg.Relay.Conntrack == nil || *e.cfg.Relay.Conntrack {
		return e.allowRelayTracked(meta, time.Now())
	}
	return e.relayAllowed(meta.src, meta.dst, meta.network)
}

// packetAddrPorts extracts enough L3/L4 metadata for relay ACLs. Unknown or
// malformed packets are treated as non-relay so gVisor can continue applying
// its own protocol validation.
func packetAddrPorts(packet []byte) (byte, netip.AddrPort, netip.AddrPort, bool) {
	meta, ok := parseRelayPacket(packet)
	if !ok {
		return 0, netip.AddrPort{}, netip.AddrPort{}, false
	}
	return meta.proto, meta.src, meta.dst, true
}

func packetPorts(proto byte, transport []byte) (uint16, uint16) {
	if proto != 6 && proto != 17 || len(transport) < 4 {
		return 0, 0
	}
	return uint16(transport[0])<<8 | uint16(transport[1]), uint16(transport[2])<<8 | uint16(transport[3])
}

func idAddrs(id stack.TransportEndpointID) (src, dst netip.AddrPort, ok bool) {
	dst, ok = netstackex.AddrPortFromEndpointIDLocal(id)
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	src, ok = netstackex.AddrPortFromEndpointIDRemote(id)
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	return src, dst, true
}

func withTCPIdle(network string, c net.Conn, err error, idle time.Duration) (net.Conn, error) {
	if err != nil || c == nil || idle <= 0 || !strings.HasPrefix(network, "tcp") {
		return c, err
	}
	return newActivityConn(c, idle), nil
}

// activityConn wraps outbound SOCKS/HTTP dial targets. The SOCKS library owns
// its copy loops, so wrapping the target connection is the narrow point where
// we can still close idle sessions without forking that dependency.
type activityConn struct {
	net.Conn
	idle  time.Duration
	mu    sync.Mutex
	timer *time.Timer
}

func newActivityConn(c net.Conn, idle time.Duration) net.Conn {
	ac := &activityConn{Conn: c, idle: idle}
	ac.timer = time.AfterFunc(idle, func() {
		_ = c.Close()
	})
	return ac
}

func (c *activityConn) touch() {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Reset(c.idle)
	}
	c.mu.Unlock()
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 || err == nil {
		c.touch()
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 || err == nil {
		c.touch()
	}
	return n, err
}

func (c *activityConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// proxyBothIdle copies bytes in both directions and resets a shared idle timer
// on either read or write. TCP keepalive packets are not surfaced by net.Conn,
// so this timer is based on userspace-visible activity.
func proxyBothIdle(a, b net.Conn, idle time.Duration) {
	var (
		timer *time.Timer
		mu    sync.Mutex
	)
	touch := func() {
		if idle <= 0 {
			return
		}
		mu.Lock()
		if timer != nil {
			timer.Reset(idle)
		}
		mu.Unlock()
	}
	if idle > 0 {
		timer = time.AfterFunc(idle, func() {
			_ = a.Close()
			_ = b.Close()
		})
		defer timer.Stop()
	}
	errc := make(chan struct{}, 2)
	go copyConn(a, b, touch, errc)
	go copyConn(b, a, touch, errc)
	<-errc
}

func copyConn(dst, src net.Conn, touch func(), errc chan<- struct{}) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 || err == nil {
			touch()
		}
		if n > 0 {
			if err := writeFull(dst, buf[:n]); err != nil {
				break
			}
			touch()
		}
		if err != nil {
			break
		}
	}
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
	errc <- struct{}{}
}

func writeFull(w net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// proxyUDP is the UDP equivalent of proxyBothIdle. A zero-length UDP datagram
// still resets the timer because it is a real packet at the UDP layer.
func proxyUDP(a, b net.Conn, idle time.Duration) {
	var (
		timer *time.Timer
		mu    sync.Mutex
	)
	touch := func() {
		if idle <= 0 {
			return
		}
		mu.Lock()
		if timer != nil {
			timer.Reset(idle)
		}
		mu.Unlock()
	}
	if idle > 0 {
		timer = time.AfterFunc(idle, func() {
			_ = a.Close()
			_ = b.Close()
		})
		defer timer.Stop()
	}
	done := make(chan struct{}, 2)
	copyLoop := func(dst, src net.Conn) {
		buf := make([]byte, 64*1024)
		for {
			n, err := src.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			touch()
			if _, err := dst.Write(buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
			touch()
		}
	}
	go copyLoop(a, b)
	go copyLoop(b, a)
	<-done
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type oneConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c == nil {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *oneConnListener) Close() error { return nil }

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func addrPortFromNetAddr(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok {
			return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
		}
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok {
			return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
		}
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err == nil {
		return ap
	}
	return netip.AddrPort{}
}

func addrFromNetAddr(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	switch a := addr.(type) {
	case interface{ Addr() netip.Addr }:
		return a.Addr()
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok {
			return ip.Unmap()
		}
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok {
			return ip.Unmap()
		}
	}
	if ip, err := netip.ParseAddr(addr.String()); err == nil {
		return ip.Unmap()
	}
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

func addrPortFromString(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err == nil {
		return ap
	}
	return netip.AddrPort{}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func canonicalHostPort(hostport, defaultPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	if strings.Contains(hostport, ":") && !strings.HasPrefix(hostport, "[") {
		if ip, err := netip.ParseAddr(hostport); err == nil && ip.Is6() {
			return net.JoinHostPort(hostport, defaultPort)
		}
	}
	return net.JoinHostPort(hostport, defaultPort)
}

func listenEndpoint(addr string) (net.Listener, error) {
	if isUnixEndpoint(addr) {
		return net.Listen("unix", unixEndpointPath(addr))
	}
	return net.Listen("tcp", addr)
}

func isUnixEndpoint(addr string) bool {
	return strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "unix://")
}

func unixEndpointPath(addr string) string {
	if strings.HasPrefix(addr, "unix://") {
		return strings.TrimPrefix(addr, "unix://")
	}
	return strings.TrimPrefix(addr, "unix:")
}

func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

func runShell(command string) error {
	cmd := exec.Command("/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minPositive(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
