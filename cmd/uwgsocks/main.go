// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
)

type listFlag []string

func (f *listFlag) String() string { return strings.Join(*f, ",") }

func (f *listFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

type optionalBool struct {
	set   bool
	value bool
}

func (b *optionalBool) String() string {
	if !b.set {
		return ""
	}
	if b.value {
		return "true"
	}
	return "false"
}

func (b *optionalBool) Set(v string) error {
	switch strings.ToLower(v) {
	case "1", "t", "true", "yes", "y", "on":
		b.value = true
	case "0", "f", "false", "no", "n", "off":
		b.value = false
	default:
		return fmt.Errorf("invalid bool %q", v)
	}
	b.set = true
	return nil
}

func (b *optionalBool) IsBoolFlag() bool { return true }

func main() {
	if handled, err := runAPICommand(os.Args[1:]); handled {
		if err != nil {
			fatal(err)
		}
		return
	}

	var (
		configPath            string
		wgConfigPath          string
		wgInline              string
		privateKey            string
		listenPort            int
		mtu                   int
		addresses             listFlag
		listenAddrs           listFlag
		dnsServers            listFlag
		peers                 listFlag
		forwards              listFlag
		reverseForwards       listFlag
		outboundProxies       listFlag
		inRules               listFlag
		outRules              listFlag
		relayRules            listFlag
		inDefault             string
		outDefault            string
		relayDefault          string
		socksAddr             string
		httpAddr              string
		mixedAddr             string
		proxyUsername         string
		proxyPassword         string
		fallbackSOCKS         string
		dnsListen             string
		apiListen             string
		apiToken              string
		apiAllowUnixNoToken   bool
		consistent            string
		maxConns              int
		connGrace             int
		tcpWindow             int
		tcpMaxBuffered        int
		tcpIdle               int
		udpIdle               int
		dnsMaxInflight        int
		roamFallback          int
		checkOnly             bool
		allowScripts          bool
		verbose               bool
		fallback              optionalBool
		honorProxyEnv         optionalBool
		transparent           optionalBool
		relay                 optionalBool
		disableLow            optionalBool
		proxyIPv6             optionalBool
		socksUDP              optionalBool
		socksBind             optionalBool
		preferUDP6            optionalBool
		proxyHostForward      optionalBool
		inboundHostForward    optionalBool
		dropIPv4Invalid       optionalBool
		dropIPv6LLMulticast   optionalBool
		enforceAddressSubnets optionalBool
		proxyHostRedirect     string
		inboundHostRedirect   string
		hostDialBindAddress   string
	)
	flag.StringVar(&configPath, "config", "", "YAML config file")
	flag.StringVar(&wgConfigPath, "wg-config", "", "WireGuard wg-quick config file")
	flag.StringVar(&wgInline, "wg-inline", "", "inline WireGuard wg-quick config")
	flag.StringVar(&privateKey, "private-key", "", "WireGuard private key, base64")
	flag.IntVar(&listenPort, "listen-port", -1, "WireGuard UDP listen port; omit for outbound-only client sockets")
	flag.Var(&listenAddrs, "listen-address", "local IP address for server-mode WireGuard UDP listen sockets; repeatable, default all IPv4 and IPv6")
	flag.IntVar(&mtu, "mtu", 0, "WireGuard MTU, default 1420")
	flag.IntVar(&roamFallback, "roam-fallback", 0, "seconds before restoring a configured static peer endpoint after stale roaming; default 120")
	flag.Var(&addresses, "address", "WireGuard interface address/prefix; repeatable")
	flag.Var(&dnsServers, "dns", "WireGuard DNS server IP; repeatable")
	flag.Var(&peers, "peer", "peer fields: public_key=...,allowed_ips=10.0.0.0/24,endpoint=host:51820,persistent_keepalive=25; repeatable")
	flag.StringVar(&socksAddr, "socks5", "", "host SOCKS5 listen address, for example 127.0.0.1:1080")
	flag.StringVar(&httpAddr, "http", "", "host HTTP proxy listen address")
	flag.StringVar(&mixedAddr, "mixed", "", "host mixed SOCKS5/HTTP proxy listen address")
	flag.StringVar(&proxyUsername, "proxy-username", "", "username required by SOCKS5/HTTP proxy authentication")
	flag.StringVar(&proxyPassword, "proxy-password", "", "password required by SOCKS5/HTTP proxy authentication")
	flag.Var(&fallback, "fallback-direct", "for SOCKS/HTTP proxy, connect directly when destination is outside WireGuard AllowedIPs")
	flag.StringVar(&fallbackSOCKS, "fallback-socks5", "", "SOCKS5 proxy used for direct fallback TCP connections")
	flag.Var(&outboundProxies, "outbound-proxy", "outbound proxy rule, e.g. socks5://127.0.0.1:1081;roles=socks,inbound;subnets=0.0.0.0/0; repeatable")
	flag.Var(&honorProxyEnv, "honor-proxy-env", "use HTTP_PROXY/HTTPS_PROXY/ALL_PROXY as outbound proxy fallbacks")
	flag.Var(&proxyIPv6, "proxy-ipv6", "enable IPv6 address selection for SOCKS/HTTP hostname targets")
	flag.Var(&socksUDP, "socks5-udp-associate", "enable SOCKS5 UDP ASSOCIATE")
	flag.Var(&socksBind, "socks5-bind", "enable SOCKS5 BIND into the userspace WireGuard netstack")
	flag.Var(&preferUDP6, "prefer-ipv6-for-udp-over-socks", "prefer IPv6 for remotely-resolved SOCKS5 UDP ASSOCIATE hostnames")
	flag.Var(&proxyHostForward, "proxy-host-forward", "allow SOCKS5/HTTP requests to this peer's tunnel IPs, localhost, and 127.0.0.0/8 to reach a host address")
	flag.StringVar(&proxyHostRedirect, "proxy-host-forward-redirect", "", "host IP used for proxy host forwarding; default is loopback")
	flag.Var(&inboundHostForward, "inbound-host-forward", "allow WireGuard packets to this peer's tunnel IPs to reach a host address when no tunnel listener owns the port")
	flag.StringVar(&inboundHostRedirect, "inbound-host-forward-redirect", "", "host IP used for inbound host forwarding; default is loopback")
	flag.StringVar(&hostDialBindAddress, "host-dial-bind-address", "", "local host IP to bind for transparent inbound egress dials, e.g. 192.0.2.10 or 0.0.0.0")
	flag.Var(&dropIPv4Invalid, "drop-ipv4-invalid", "drop tunnel packets with 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, or 255.255.255.255")
	flag.Var(&dropIPv6LLMulticast, "drop-ipv6-link-local-multicast", "drop tunnel packets with IPv6 link-local or multicast addresses")
	flag.Var(&enforceAddressSubnets, "enforce-address-subnets", "reject destinations inside Address= subnets unless routed by peer AllowedIPs")
	flag.Var(&forwards, "forward", "local forward: tcp://127.0.0.1:8080=10.0.0.2:80 or udp://127.0.0.1:5353=10.0.0.53:53; repeatable")
	flag.Var(&reverseForwards, "reverse-forward", "tunnel reverse forward: tcp://100.64.1.1:8443=127.0.0.1:443 or udp://100.64.1.1:5353=127.0.0.1:53; repeatable")
	flag.Var(&inRules, "acl-inbound", "inbound ACL rule, e.g. 'allow src=10.0.0.0/24 dst=0.0.0.0/0 dport=80-443'; repeatable")
	flag.Var(&outRules, "acl-outbound", "outbound ACL rule; repeatable")
	flag.Var(&relayRules, "acl-relay", "relay ACL rule; repeatable")
	flag.StringVar(&inDefault, "acl-inbound-default", "", "allow or deny")
	flag.StringVar(&outDefault, "acl-outbound-default", "", "allow or deny")
	flag.StringVar(&relayDefault, "acl-relay-default", "", "allow or deny")
	flag.Var(&transparent, "inbound-transparent", "enable transparent inbound TCP/UDP host proxying")
	flag.Var(&relay, "relay", "enable WireGuard L3 relay forwarding")
	flag.StringVar(&consistent, "consistent-port", "", "strict, loose, or disabled")
	flag.Var(&disableLow, "disable-low-ports", "do not bind host source ports below 1024 for inbound proxying")
	flag.IntVar(&maxConns, "max-connections", 0, "maximum inbound transparent connection table size; 0 is unlimited")
	flag.IntVar(&connGrace, "connection-table-grace", 0, "seconds to reject new connections after table overflow before reaping old TCP entries; default 30")
	flag.IntVar(&tcpWindow, "tcp-receive-window", 0, "TCP forwarder receive window bytes; default 1048576")
	flag.IntVar(&tcpMaxBuffered, "tcp-max-buffered", 0, "aggregate transparent TCP receive-buffer budget in bytes; default 268435456")
	flag.IntVar(&tcpIdle, "tcp-idle-timeout", 0, "TCP idle timeout in seconds; default 900")
	flag.IntVar(&udpIdle, "udp-idle-timeout", 0, "UDP idle timeout in seconds; default 30")
	flag.StringVar(&dnsListen, "dns-listen", "", "serve DNS inside the tunnel at address:port, usually tunnel_ip:53")
	flag.IntVar(&dnsMaxInflight, "dns-max-inflight", 0, "maximum tunnel-hosted DNS transactions in flight; default 1024")
	flag.StringVar(&apiListen, "api-listen", "", "optional management API listen address, or unix:///path/to/socket")
	flag.StringVar(&apiToken, "api-token", "", "bearer token for the management API")
	flag.BoolVar(&apiAllowUnixNoToken, "api-allow-unauthenticated-unix", true, "allow API requests without a bearer token when api-listen is a Unix socket")
	flag.BoolVar(&allowScripts, "allow-scripts", false, "run wg-quick PostUp/PostDown commands from config")
	flag.BoolVar(&verbose, "verbose", false, "verbose WireGuard logging")
	flag.BoolVar(&checkOnly, "check", false, "start, then immediately stop after successful initialization")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		fatal(err)
	}
	if wgConfigPath != "" {
		if err := config.MergeWGQuickFile(&cfg.WireGuard, wgConfigPath); err != nil {
			fatal(err)
		}
	}
	if wgInline != "" {
		if err := config.MergeWGQuick(&cfg.WireGuard, wgInline); err != nil {
			fatal(err)
		}
	}
	if privateKey != "" {
		cfg.WireGuard.PrivateKey = privateKey
	}
	if listenPort >= 0 {
		lp := listenPort
		cfg.WireGuard.ListenPort = &lp
	}
	if mtu > 0 {
		cfg.WireGuard.MTU = mtu
	}
	if roamFallback != 0 {
		cfg.WireGuard.RoamFallbackSeconds = roamFallback
	}
	cfg.WireGuard.Addresses = append(cfg.WireGuard.Addresses, addresses...)
	cfg.WireGuard.ListenAddresses = append(cfg.WireGuard.ListenAddresses, listenAddrs...)
	cfg.WireGuard.DNS = append(cfg.WireGuard.DNS, dnsServers...)
	for _, p := range peers {
		peer, err := config.ParsePeerArg(p)
		if err != nil {
			fatal(err)
		}
		cfg.WireGuard.Peers = append(cfg.WireGuard.Peers, peer)
	}
	for _, f := range forwards {
		forward, err := config.ParseForwardArg(f)
		if err != nil {
			fatal(err)
		}
		cfg.Forwards = append(cfg.Forwards, forward)
	}
	for _, f := range reverseForwards {
		forward, err := config.ParseForwardArg(f)
		if err != nil {
			fatal(err)
		}
		cfg.ReverseForwards = append(cfg.ReverseForwards, forward)
	}
	for _, p := range outboundProxies {
		outbound, err := config.ParseOutboundProxyArg(p)
		if err != nil {
			fatal(err)
		}
		cfg.Proxy.OutboundProxies = append(cfg.Proxy.OutboundProxies, outbound)
	}
	for _, r := range inRules {
		rule, err := acl.ParseRule(r)
		if err != nil {
			fatal(err)
		}
		cfg.ACL.Inbound = append(cfg.ACL.Inbound, rule)
	}
	for _, r := range outRules {
		rule, err := acl.ParseRule(r)
		if err != nil {
			fatal(err)
		}
		cfg.ACL.Outbound = append(cfg.ACL.Outbound, rule)
	}
	for _, r := range relayRules {
		rule, err := acl.ParseRule(r)
		if err != nil {
			fatal(err)
		}
		cfg.ACL.Relay = append(cfg.ACL.Relay, rule)
	}
	if inDefault != "" {
		cfg.ACL.InboundDefault = acl.Action(strings.ToLower(inDefault))
	}
	if outDefault != "" {
		cfg.ACL.OutboundDefault = acl.Action(strings.ToLower(outDefault))
	}
	if relayDefault != "" {
		cfg.ACL.RelayDefault = acl.Action(strings.ToLower(relayDefault))
	}
	if socksAddr != "" {
		cfg.Proxy.SOCKS5 = socksAddr
	}
	if httpAddr != "" {
		cfg.Proxy.HTTP = httpAddr
	}
	if mixedAddr != "" {
		cfg.Proxy.Mixed = mixedAddr
	}
	if proxyUsername != "" {
		cfg.Proxy.Username = proxyUsername
	}
	if proxyPassword != "" {
		cfg.Proxy.Password = proxyPassword
	}
	if fallback.set {
		v := fallback.value
		cfg.Proxy.FallbackDirect = &v
	}
	if fallbackSOCKS != "" {
		cfg.Proxy.FallbackSOCKS5 = fallbackSOCKS
	}
	if honorProxyEnv.set {
		v := honorProxyEnv.value
		cfg.Proxy.HonorEnvironment = &v
	}
	if proxyIPv6.set {
		v := proxyIPv6.value
		cfg.Proxy.IPv6 = &v
	}
	if socksUDP.set {
		v := socksUDP.value
		cfg.Proxy.UDPAssociate = &v
	}
	if socksBind.set {
		v := socksBind.value
		cfg.Proxy.Bind = &v
	}
	if preferUDP6.set {
		v := preferUDP6.value
		cfg.Proxy.PreferIPv6ForUDPOverSOCKS = &v
	}
	if proxyHostForward.set {
		v := proxyHostForward.value
		cfg.HostForward.Proxy.Enabled = &v
	}
	if proxyHostRedirect != "" {
		cfg.HostForward.Proxy.RedirectIP = proxyHostRedirect
	}
	if inboundHostForward.set {
		v := inboundHostForward.value
		cfg.HostForward.Inbound.Enabled = &v
	}
	if inboundHostRedirect != "" {
		cfg.HostForward.Inbound.RedirectIP = inboundHostRedirect
	}
	if hostDialBindAddress != "" {
		cfg.Inbound.HostDialBindAddress = hostDialBindAddress
	}
	if dropIPv4Invalid.set {
		v := dropIPv4Invalid.value
		cfg.Filtering.DropIPv4Invalid = &v
	}
	if dropIPv6LLMulticast.set {
		v := dropIPv6LLMulticast.value
		cfg.Filtering.DropIPv6LinkLocalMulticast = &v
	}
	if enforceAddressSubnets.set {
		v := enforceAddressSubnets.value
		cfg.Routing.EnforceAddressSubnets = &v
	}
	if transparent.set {
		v := transparent.value
		cfg.Inbound.Transparent = &v
	}
	if relay.set {
		v := relay.value
		cfg.Relay.Enabled = &v
	}
	if disableLow.set {
		v := disableLow.value
		cfg.Inbound.DisableLowPorts = &v
	}
	if consistent != "" {
		cfg.Inbound.ConsistentPort = consistent
	}
	if maxConns != 0 {
		cfg.Inbound.MaxConnections = maxConns
	}
	if connGrace != 0 {
		cfg.Inbound.ConnectionTableGraceSeconds = connGrace
	}
	if tcpWindow != 0 {
		cfg.Inbound.TCPReceiveWindowBytes = tcpWindow
	}
	if tcpMaxBuffered != 0 {
		cfg.Inbound.TCPMaxBufferedBytes = tcpMaxBuffered
	}
	if tcpIdle != 0 {
		cfg.Inbound.TCPIdleTimeoutSeconds = tcpIdle
	}
	if udpIdle != 0 {
		cfg.Inbound.UDPIdleTimeoutSeconds = udpIdle
	}
	if dnsListen != "" {
		cfg.DNSServer.Listen = dnsListen
	}
	if dnsMaxInflight != 0 {
		cfg.DNSServer.MaxInflight = dnsMaxInflight
	}
	if apiListen != "" {
		cfg.API.Listen = apiListen
	}
	if apiToken != "" {
		cfg.API.Token = apiToken
	}
	cfg.API.AllowUnauthenticatedUnix = cfg.API.AllowUnauthenticatedUnix || apiAllowUnixNoToken
	cfg.Scripts.Allow = cfg.Scripts.Allow || allowScripts
	cfg.Log.Verbose = cfg.Log.Verbose || verbose
	if err := cfg.Normalize(); err != nil {
		fatal(err)
	}

	logger := log.New(os.Stderr, "uwg: ", log.LstdFlags)
	eng, err := engine.New(cfg, logger)
	if err != nil {
		fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		fatal(err)
	}
	defer eng.Close()
	if checkOnly {
		fmt.Fprintln(os.Stderr, "uwg: check ok")
		return
	}
	waitForSignal()
}

func waitForSignal() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "uwg: %v\n", err)
	os.Exit(1)
}
