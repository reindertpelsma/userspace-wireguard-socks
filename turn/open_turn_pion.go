package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	piondtls "github.com/pion/dtls/v3"
	turn "github.com/pion/turn/v4"
	yaml "gopkg.in/yaml.v3"
)

type Behavior int

type Config struct {
	Realm              string               `yaml:"realm"`
	Software           string               `yaml:"software"`
	AllocationTTL      string               `yaml:"allocation_ttl"`
	NonceTTL           string               `yaml:"nonce_ttl"`
	PreopenSinglePorts bool                 `yaml:"preopen_single_ports"`
	Listen             ListenConfig         `yaml:"listen"`
	API                APIConfig            `yaml:"api"`
	Listeners          []TURNListenerConfig `yaml:"listeners"`
	Users              []UserConfig         `yaml:"users"`
	PortRanges         []RangeConfig        `yaml:"port_ranges"`
	MaxSessions        int                  `yaml:"max_sessions"`
}

type RangeConfig struct {
	Start              int               `yaml:"start"`
	End                int               `yaml:"end"`
	Password           string            `yaml:"password"`
	PermissionBehavior string            `yaml:"permission_behavior"`
	SourceNetworks     []string          `yaml:"source_networks"`
	MappedRange        MappedRangeConfig `yaml:"mapped_range"`
	WireguardPublicKey string            `yaml:"wireguard_public_key"`
	WireguardMode      string            `yaml:"wireguard_mode"` // disabled, server-only, default-with-overwrite, required-in-username
	MaxSessions        int               `yaml:"max_sessions"`
	OutboundOnly       bool              `yaml:"outbound_only"`
	InternalOnly       bool              `yaml:"internal_only"`
}

type MappedRangeConfig struct {
	IP        string `yaml:"ip"`
	StartPort int    `yaml:"start_port"`
}

type UserConfig struct {
	Username           string            `yaml:"username"`
	Password           string            `yaml:"password"`
	Port               int               `yaml:"port"`
	PortRangeStart     int               `yaml:"port_range_start"`
	PortRangeEnd       int               `yaml:"port_range_end"`
	PermissionBehavior string            `yaml:"permission_behavior"`
	SourceNetworks     []string          `yaml:"source_networks"`
	MappedAddress      string            `yaml:"mapped_address"`
	MappedRange        MappedRangeConfig `yaml:"mapped_range"`
	WireguardPublicKey string            `yaml:"wireguard_public_key"`
	WireguardMode      string            `yaml:"wireguard_mode"`
	MaxSessions        int               `yaml:"max_sessions"`
	OutboundOnly       bool              `yaml:"outbound_only"`
	InternalOnly       bool              `yaml:"internal_only"`
}

type ListenConfig struct {
	TurnListen string `yaml:"turn_listen"`
	RelayIP    string `yaml:"relay_ip"`
}

type TURNListenerConfig struct {
	Type           string `yaml:"type"`
	Listen         string `yaml:"listen"`
	Path           string `yaml:"path,omitempty"`
	AdvertiseHTTP3 bool   `yaml:"advertise_http3,omitempty"`
	CertFile       string `yaml:"cert_file,omitempty"`
	KeyFile        string `yaml:"key_file,omitempty"`
	VerifyPeer     bool   `yaml:"verify_peer,omitempty"`
	ReloadInterval string `yaml:"reload_interval,omitempty"`
	CAFile         string `yaml:"ca_file,omitempty"`
}

type turnAuthRule struct {
	Username         string
	Password         string
	RequestedPort    int
	PortRangeStart   int
	PortRangeEnd     int
	Behavior         Behavior
	SourceNetworks   []*net.IPNet
	MappedAddr       *net.UDPAddr
	MappedRangeIP    net.IP
	MappedRangeStart int
	WGGuard          *WireguardGuard
	WGMode           string
	MaxSessions      int
	OutboundOnly     bool
	InternalOnly     bool
}

type turnRangeRule struct {
	Start          int
	End            int
	Password       string
	Behavior       Behavior
	SourceNetworks []*net.IPNet
	MappedIP       net.IP
	MappedStart    int
	WGGuard        *WireguardGuard
	WGMode         string
	MaxSessions    int
	OutboundOnly   bool
	InternalOnly   bool
}

type authLookup struct {
	Password         string
	RequestedPort    int
	PortRangeStart   int
	PortRangeEnd     int
	Behavior         Behavior
	SourceNetworks   []*net.IPNet
	MappedAddr       *net.UDPAddr
	MappedRangeIP    net.IP
	MappedRangeStart int
	WGGuard          *WireguardGuard
	WGMode           string
	MaxSessions      int
	OutboundOnly     bool
	InternalOnly     bool
}

const (
	BehaviorAllow Behavior = iota
	BehaviorAllowIfNoPermissions
	BehaviorRejectUnlessPermitted
)

type relayReservation struct {
	AuthUsername     string
	Username         string
	ClientAddr       string
	RequestedPort    int
	AllocatedPort    int
	PortRangeStart   int
	PortRangeEnd     int
	Behavior         Behavior
	Sources          []*net.IPNet
	MappedAddr       *net.UDPAddr
	MappedRangeIP    net.IP
	MappedRangeStart int
	WGGuard          *WireguardGuard
	OutboundOnly     bool
	InternalOnly     bool
}

type relayDatagram struct {
	data []byte
	addr *net.UDPAddr
}

type relayPacketConn struct {
	base        net.PacketConn
	wrapper     *openRelayPion
	reservation *relayReservation
	publicAddr  *net.UDPAddr
	actualAddr  *net.UDPAddr

	readCh   chan relayDatagram
	closedCh chan struct{}

	closeOnce sync.Once

	deadlineMu   sync.RWMutex
	readDeadline time.Time

	seenMu        sync.RWMutex
	outboundPeers map[string]struct{}
}

type openRelayPion struct {
	cfg        Config
	userRules  map[string]*turnAuthRule
	rangeRules []turnRangeRule

	mu                  sync.RWMutex
	reservations        map[string]*relayReservation
	clientReservations  map[string]*relayReservation
	pendingAllocations  []*relayReservation
	activeRelays        map[string]*relayPacketConn
	reservedPublicAddrs map[string]struct{}
	servers             []*turn.Server
	listenAddr          *net.UDPAddr
	boundListeners      []boundListener
	certManagers        []*turnCertManager

	globalSessions  int64
	internalPackets int64
	externalPackets int64
}

type boundListener struct {
	Type string
	Addr net.Addr
}

func loadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Listen.RelayIP == "" {
		cfg.Listen.RelayIP = "0.0.0.0"
	}
	if cfg.Realm == "" {
		cfg.Realm = "open-relay.local"
	}
	if cfg.Software == "" {
		cfg.Software = "go-open-turn"
	}
	if cfg.AllocationTTL == "" {
		cfg.AllocationTTL = "10m"
	}
	if cfg.NonceTTL == "" {
		cfg.NonceTTL = "10m"
	}
	listeners, err := normalizedTURNListeners(cfg)
	if err != nil {
		return Config{}, err
	}
	cfg.Listeners = listeners
	return cfg, nil
}

func normalizedTURNListeners(cfg Config) ([]TURNListenerConfig, error) {
	listeners := append([]TURNListenerConfig(nil), cfg.Listeners...)
	if len(listeners) == 0 && strings.TrimSpace(cfg.Listen.TurnListen) != "" {
		listeners = append(listeners, TURNListenerConfig{
			Type:   "udp",
			Listen: cfg.Listen.TurnListen,
		})
	}
	if len(listeners) == 0 {
		return nil, errors.New("at least one TURN listener must be configured")
	}
	for i := range listeners {
		listeners[i].Type = strings.ToLower(strings.TrimSpace(listeners[i].Type))
		if listeners[i].Type == "" {
			listeners[i].Type = "udp"
		}
		listeners[i].Listen = strings.TrimSpace(listeners[i].Listen)
		if listeners[i].Listen == "" {
			return nil, fmt.Errorf("listener %d: listen is required", i)
		}
		switch listeners[i].Type {
		case "udp", "tcp", "tls", "dtls", "http", "https", "quic":
		default:
			return nil, fmt.Errorf("listener %d: unknown type %q", i, listeners[i].Type)
		}
		if listeners[i].Path == "" && (listeners[i].Type == "http" || listeners[i].Type == "https" || listeners[i].Type == "quic") {
			listeners[i].Path = "/turn"
		}
	}
	return listeners, nil
}

func newOpenRelayPion(cfg Config) (*openRelayPion, error) {
	userRules, rangeRules, err := buildAuthState(cfg)
	if err != nil {
		return nil, err
	}
	o := &openRelayPion{
		cfg:                 cfg,
		userRules:           userRules,
		rangeRules:          rangeRules,
		reservations:        map[string]*relayReservation{},
		clientReservations:  map[string]*relayReservation{},
		activeRelays:        map[string]*relayPacketConn{},
		reservedPublicAddrs: map[string]struct{}{},
	}
	return o, nil
}

func buildAuthState(cfg Config) (map[string]*turnAuthRule, []turnRangeRule, error) {
	userRules := map[string]*turnAuthRule{}
	for _, u := range cfg.Users {
		if err := validateUserConfig(u); err != nil {
			return nil, nil, fmt.Errorf("user %q: %w", u.Username, err)
		}
		nets, err := parseCIDRs(u.SourceNetworks)
		if err != nil {
			return nil, nil, fmt.Errorf("user %q source_networks: %w", u.Username, err)
		}
		mapped, err := parseMappedAddress(u.MappedAddress)
		if err != nil {
			return nil, nil, fmt.Errorf("user %q mapped_address: %w", u.Username, err)
		}
		mappedIP, mappedStart, err := parseMappedRange(u.MappedRange, u.PortRangeEnd-u.PortRangeStart)
		if err != nil {
			return nil, nil, fmt.Errorf("user %q mapped_range: %w", u.Username, err)
		}
		var guard *WireguardGuard
		if u.WireguardPublicKey != "" {
			pk, err := decodePublicKey(u.WireguardPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("user %q wireguard_public_key: %w", u.Username, err)
			}
			guard = NewWireguardGuard(pk)
			guard.MaxSessions = u.MaxSessions
		}
		userRules[u.Username] = &turnAuthRule{
			Username:         u.Username,
			Password:         u.Password,
			RequestedPort:    u.Port,
			PortRangeStart:   u.PortRangeStart,
			PortRangeEnd:     u.PortRangeEnd,
			Behavior:         parseBehavior(u.PermissionBehavior),
			SourceNetworks:   nets,
			MappedAddr:       mapped,
			MappedRangeIP:    mappedIP,
			MappedRangeStart: mappedStart,
			WGGuard:          guard,
			WGMode:           u.WireguardMode,
			MaxSessions:      u.MaxSessions,
			OutboundOnly:     u.OutboundOnly,
			InternalOnly:     u.InternalOnly,
		}
	}

	rangeRules := make([]turnRangeRule, 0, len(cfg.PortRanges))
	for _, r := range cfg.PortRanges {
		if err := validateRangeConfig(r); err != nil {
			return nil, nil, fmt.Errorf("range %d-%d: %w", r.Start, r.End, err)
		}
		nets, err := parseCIDRs(r.SourceNetworks)
		if err != nil {
			return nil, nil, fmt.Errorf("range %d-%d source_networks: %w", r.Start, r.End, err)
		}
		mappedIP, mappedStart, err := parseMappedRange(r.MappedRange, r.End-r.Start)
		if err != nil {
			return nil, nil, fmt.Errorf("range %d-%d mapped_range: %w", r.Start, r.End, err)
		}
		var guard *WireguardGuard
		if r.WireguardPublicKey != "" {
			pk, err := decodePublicKey(r.WireguardPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("range %d-%d wireguard_public_key: %w", r.Start, r.End, err)
			}
			guard = NewWireguardGuard(pk)
			guard.MaxSessions = r.MaxSessions
		}
		rangeRules = append(rangeRules, turnRangeRule{
			Start:          r.Start,
			End:            r.End,
			Password:       r.Password,
			Behavior:       parseBehavior(r.PermissionBehavior),
			SourceNetworks: nets,
			MappedIP:       mappedIP,
			MappedStart:    mappedStart,
			WGGuard:        guard,
			WGMode:         r.WireguardMode,
			MaxSessions:    r.MaxSessions,
			OutboundOnly:   r.OutboundOnly,
			InternalOnly:   r.InternalOnly,
		})
	}
	sort.Slice(rangeRules, func(i, j int) bool { return rangeRules[i].Start < rangeRules[j].Start })
	return userRules, rangeRules, nil
}

func validateUserConfig(cfg UserConfig) error {
	if cfg.Port != 0 && (cfg.PortRangeStart != 0 || cfg.PortRangeEnd != 0) {
		return errors.New("port and port_range_* are mutually exclusive")
	}
	if (cfg.PortRangeStart == 0) != (cfg.PortRangeEnd == 0) {
		return errors.New("port_range_start and port_range_end must both be set")
	}
	if cfg.PortRangeStart < 0 || cfg.PortRangeEnd < 0 {
		return errors.New("ports must be non-negative")
	}
	if cfg.PortRangeStart != 0 && cfg.PortRangeEnd < cfg.PortRangeStart {
		return errors.New("invalid user port range")
	}
	if strings.TrimSpace(cfg.MappedAddress) != "" && strings.TrimSpace(cfg.MappedRange.IP) != "" {
		return errors.New("mapped_address and mapped_range are mutually exclusive")
	}
	if strings.TrimSpace(cfg.MappedAddress) != "" && cfg.Port == 0 {
		return errors.New("mapped_address requires a fixed port")
	}
	if strings.TrimSpace(cfg.MappedRange.IP) != "" && cfg.PortRangeStart == 0 {
		return errors.New("mapped_range requires a user port range")
	}
	return nil
}

func validateRangeConfig(cfg RangeConfig) error {
	if cfg.Start <= 0 || cfg.End <= 0 || cfg.End < cfg.Start {
		return errors.New("invalid port range")
	}
	return nil
}

func (o *openRelayPion) usersSnapshot() []UserConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]UserConfig(nil), o.cfg.Users...)
}

func (o *openRelayPion) portRangesSnapshot() []RangeConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]RangeConfig(nil), o.cfg.PortRanges...)
}

func (o *openRelayPion) replaceAuthState(users []UserConfig, ranges []RangeConfig) error {
	nextCfg := o.cfg
	nextCfg.Users = append([]UserConfig(nil), users...)
	nextCfg.PortRanges = append([]RangeConfig(nil), ranges...)
	userRules, rangeRules, err := buildAuthState(nextCfg)
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.cfg.Users = nextCfg.Users
	o.cfg.PortRanges = nextCfg.PortRanges
	o.userRules = userRules
	o.rangeRules = rangeRules
	o.mu.Unlock()
	return nil
}

func (o *openRelayPion) upsertUser(user UserConfig) error {
	users := o.usersSnapshot()
	for i := range users {
		if users[i].Username == user.Username {
			users[i] = user
			return o.replaceAuthState(users, o.portRangesSnapshot())
		}
	}
	users = append(users, user)
	return o.replaceAuthState(users, o.portRangesSnapshot())
}

func (o *openRelayPion) deleteUser(username string) error {
	users := o.usersSnapshot()
	out := users[:0]
	found := false
	for _, user := range users {
		if user.Username == username {
			found = true
			continue
		}
		out = append(out, user)
	}
	if !found {
		return fmt.Errorf("user %q not found", username)
	}
	return o.replaceAuthState(out, o.portRangesSnapshot())
}

func (o *openRelayPion) upsertPortRange(r RangeConfig) error {
	ranges := o.portRangesSnapshot()
	for i := range ranges {
		if ranges[i].Start == r.Start && ranges[i].End == r.End {
			ranges[i] = r
			return o.replaceAuthState(o.usersSnapshot(), ranges)
		}
	}
	ranges = append(ranges, r)
	return o.replaceAuthState(o.usersSnapshot(), ranges)
}

func (o *openRelayPion) deletePortRange(start, end int) error {
	ranges := o.portRangesSnapshot()
	out := ranges[:0]
	found := false
	for _, current := range ranges {
		if current.Start == start && current.End == end {
			found = true
			continue
		}
		out = append(out, current)
	}
	if !found {
		return fmt.Errorf("port range %d-%d not found", start, end)
	}
	return o.replaceAuthState(o.usersSnapshot(), out)
}

func (o *openRelayPion) authHandler(username, realm string, srcAddr net.Addr) ([]byte, bool) {
	srcIP, ok := addrIP(srcAddr)
	if !ok {
		return nil, false
	}

	baseUsername := username
	var encryptedPK string
	if idx := strings.LastIndex(username, "---"); idx != -1 {
		baseUsername = username[:idx]
		encryptedPK = username[idx+3:]
	}

	rule, err := o.lookup(baseUsername)
	if err != nil {
		return nil, false
	}
	if !sourceAllowed(srcIP, rule.SourceNetworks) {
		return nil, false
	}

	finalGuard := rule.WGGuard
	if rule.WGMode != "disabled" {
		if encryptedPK != "" && (rule.WGMode == "default-with-overwrite" || rule.WGMode == "required-in-username" || rule.WGMode == "") {
			pk, err := decryptPublicKey(encryptedPK, rule.Password)
			if err == nil {
				finalGuard = NewWireguardGuard(pk)
				finalGuard.MaxSessions = rule.MaxSessions
			} else if rule.WGMode == "required-in-username" {
				return nil, false
			}
		} else if rule.WGMode == "required-in-username" && encryptedPK == "" {
			return nil, false
		}
	} else {
		finalGuard = nil
	}

	res := &relayReservation{
		AuthUsername:     username,
		Username:         baseUsername,
		ClientAddr:       srcAddr.String(),
		RequestedPort:    rule.RequestedPort,
		PortRangeStart:   rule.PortRangeStart,
		PortRangeEnd:     rule.PortRangeEnd,
		Behavior:         rule.Behavior,
		Sources:          cloneIPNets(rule.SourceNetworks),
		MappedAddr:       cloneUDPAddr(rule.MappedAddr),
		MappedRangeIP:    cloneIP(rule.MappedRangeIP),
		MappedRangeStart: rule.MappedRangeStart,
		WGGuard:          finalGuard,
		OutboundOnly:     rule.OutboundOnly,
		InternalOnly:     rule.InternalOnly,
	}

	o.mu.Lock()
	o.reservations[o.reservationKey(username, srcAddr)] = res
	o.clientReservations[srcAddr.String()] = res
	o.mu.Unlock()

	key := turn.GenerateAuthKey(baseUsername, realm, rule.Password)
	return key, true
}

func (o *openRelayPion) lookup(username string) (*authLookup, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if u := o.userRules[username]; u != nil {
		return &authLookup{
			Password:         u.Password,
			RequestedPort:    u.RequestedPort,
			PortRangeStart:   u.PortRangeStart,
			PortRangeEnd:     u.PortRangeEnd,
			Behavior:         u.Behavior,
			SourceNetworks:   u.SourceNetworks,
			MappedAddr:       u.MappedAddr,
			MappedRangeIP:    u.MappedRangeIP,
			MappedRangeStart: u.MappedRangeStart,
			WGGuard:          u.WGGuard,
			WGMode:           u.WGMode,
			MaxSessions:      u.MaxSessions,
			OutboundOnly:     u.OutboundOnly,
			InternalOnly:     u.InternalOnly,
		}, nil
	}
	p, err := strconv.Atoi(username)
	if err != nil {
		return nil, fmt.Errorf("username not found")
	}
	for _, r := range o.rangeRules {
		if p >= r.Start && p <= r.End {
			var mapped *net.UDPAddr
			if r.MappedIP != nil && r.MappedStart != 0 {
				mapped = &net.UDPAddr{IP: cloneIP(r.MappedIP), Port: r.MappedStart + (p - r.Start)}
			}
			return &authLookup{
				Password:       r.Password,
				RequestedPort:  p,
				Behavior:       r.Behavior,
				SourceNetworks: r.SourceNetworks,
				MappedAddr:     mapped,
				WGGuard:        r.WGGuard,
				WGMode:         r.WGMode,
				MaxSessions:    r.MaxSessions,
				OutboundOnly:   r.OutboundOnly,
				InternalOnly:   r.InternalOnly,
			}, nil
		}
	}
	return nil, fmt.Errorf("username not found")
}

func (o *openRelayPion) reservation(username string, src net.Addr) *relayReservation {
	if src == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.reservations[o.reservationKey(username, src)]
}

func (o *openRelayPion) reservationKey(username string, src net.Addr) string {
	return username + "|" + src.String()
}

func (o *openRelayPion) clientReservation(src net.Addr) *relayReservation {
	if src == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.clientReservations[src.String()]
}

func (o *openRelayPion) onAuth(srcAddr, dstAddr net.Addr, protocol, username, realm string, method string, verdict bool) {
	if !verdict || !strings.EqualFold(method, "Allocate") {
		return
	}
	res := o.reservation(username, srcAddr)
	if res == nil {
		return
	}
	o.mu.Lock()
	o.pendingAllocations = append(o.pendingAllocations, res)
	o.mu.Unlock()
}

func (o *openRelayPion) consumePendingAllocation() *relayReservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.pendingAllocations) == 0 {
		return nil
	}
	res := o.pendingAllocations[0]
	o.pendingAllocations = append(o.pendingAllocations[:0], o.pendingAllocations[1:]...)
	return res
}

func (o *openRelayPion) allowPeer(clientAddr net.Addr, peerIP net.IP) bool {
	res := o.clientReservation(clientAddr)
	if res == nil {
		return false
	}
	return sourceAllowed(peerIP, res.Sources)
}

func newRelayPacketConn(base net.PacketConn, wrapper *openRelayPion, res *relayReservation, publicAddr net.Addr, preReserved bool) (*relayPacketConn, error) {
	actualUDP, ok := base.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("relay packet conn requires UDP local address")
	}
	publicUDP, ok := publicAddr.(*net.UDPAddr)
	if !ok {
		return nil, errors.New("relay packet conn requires UDP public address")
	}
	c := &relayPacketConn{
		base:          base,
		wrapper:       wrapper,
		reservation:   res,
		publicAddr:    cloneUDPAddr(publicUDP),
		actualAddr:    cloneUDPAddr(actualUDP),
		readCh:        make(chan relayDatagram, 256),
		closedCh:      make(chan struct{}),
		outboundPeers: map[string]struct{}{},
	}
	if err := wrapper.registerRelay(c, preReserved); err != nil {
		if preReserved {
			wrapper.releaseReservedPublicAddr(c.publicAddr)
		}
		return nil, err
	}
	go c.pumpReads()
	return c, nil
}

func (c *relayPacketConn) pumpReads() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := c.base.ReadFrom(buf)
		if err != nil {
			_ = c.Close()
			return
		}
		udpAddr, ok := normalizeUDPAddr(addr)
		if !ok || !c.shouldAcceptInbound(udpAddr, false) {
			continue
		}
		packet := relayDatagram{
			data: append([]byte(nil), buf[:n]...),
			addr: udpAddr,
		}
		select {
		case c.readCh <- packet:
		default:
		}
	}
}

func (c *relayPacketConn) shouldAcceptInbound(addr *net.UDPAddr, internal bool) bool {
	if c.reservation == nil {
		return true
	}
	if c.reservation.InternalOnly && !internal {
		return false
	}
	if c.reservation.OutboundOnly && !c.hasOutboundPeer(addr) {
		return false
	}
	return true
}

func (c *relayPacketConn) hasOutboundPeer(addr *net.UDPAddr) bool {
	c.seenMu.RLock()
	defer c.seenMu.RUnlock()
	_, ok := c.outboundPeers[addr.String()]
	return ok
}

func (c *relayPacketConn) rememberOutboundPeer(addr *net.UDPAddr) {
	c.seenMu.Lock()
	c.outboundPeers[addr.String()] = struct{}{}
	c.seenMu.Unlock()
}

func (c *relayPacketConn) deliverInternal(data []byte, from *net.UDPAddr) error {
	if !c.shouldAcceptInbound(from, true) {
		return nil
	}
	packet := relayDatagram{
		data: append([]byte(nil), data...),
		addr: cloneUDPAddr(from),
	}
	select {
	case <-c.closedCh:
		return net.ErrClosed
	case c.readCh <- packet:
		return nil
	default:
		return errors.New("relay receive queue full")
	}
}

func (c *relayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		deadline := c.readDeadlineValue()
		if deadline.IsZero() {
			select {
			case packet := <-c.readCh:
				return copyPacket(p, packet)
			case <-c.closedCh:
				return 0, nil, net.ErrClosed
			}
		}

		timer := time.NewTimer(time.Until(deadline))
		select {
		case packet := <-c.readCh:
			if !timer.Stop() {
				<-timer.C
			}
			return copyPacket(p, packet)
		case <-timer.C:
			return 0, nil, &net.OpError{
				Op:   "read",
				Net:  c.publicAddr.Network(),
				Addr: c.publicAddr,
				Err:  os.ErrDeadlineExceeded,
			}
		case <-c.closedCh:
			if !timer.Stop() {
				<-timer.C
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func copyPacket(p []byte, packet relayDatagram) (int, net.Addr, error) {
	n := copy(p, packet.data)
	if n < len(packet.data) {
		return 0, nil, errors.New("short buffer")
	}
	return n, cloneUDPAddr(packet.addr), nil
}

func (c *relayPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := normalizeUDPAddr(addr)
	if !ok {
		return 0, fmt.Errorf("non-UDP peer address %T", addr)
	}
	c.rememberOutboundPeer(udpAddr)

	if peer := c.wrapper.findRelay(udpAddr); peer != nil {
		atomic.AddInt64(&c.wrapper.internalPackets, 1)
		if err := peer.deliverInternal(p, c.publicAddr); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	if c.reservation != nil && c.reservation.InternalOnly {
		return len(p), nil
	}
	atomic.AddInt64(&c.wrapper.externalPackets, 1)
	return c.base.WriteTo(p, udpAddr)
}

func (c *relayPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closedCh)
		c.wrapper.unregisterRelay(c)
		atomic.AddInt64(&c.wrapper.globalSessions, -1)
		err = c.base.Close()
	})
	return err
}

func (c *relayPacketConn) LocalAddr() net.Addr {
	return cloneUDPAddr(c.publicAddr)
}

func (c *relayPacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *relayPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *relayPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *relayPacketConn) readDeadlineValue() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (o *openRelayPion) registerRelay(conn *relayPacketConn, preReserved bool) error {
	key := conn.publicAddr.String()
	o.mu.Lock()
	defer o.mu.Unlock()
	if current, ok := o.activeRelays[key]; ok && current != nil && current != conn {
		return fmt.Errorf("relay address %s already active", key)
	}
	_, reserved := o.reservedPublicAddrs[key]
	if preReserved {
		if !reserved {
			return fmt.Errorf("relay address %s was not reserved", key)
		}
	} else if reserved {
		return fmt.Errorf("relay address %s already reserved", key)
	}
	o.reservedPublicAddrs[key] = struct{}{}
	o.activeRelays[key] = conn
	return nil
}

func (o *openRelayPion) unregisterRelay(conn *relayPacketConn) {
	key := conn.publicAddr.String()
	o.mu.Lock()
	if current := o.activeRelays[key]; current == conn {
		delete(o.activeRelays, key)
		delete(o.reservedPublicAddrs, key)
	}
	o.mu.Unlock()
}

func (o *openRelayPion) reservePublicAddr(addr *net.UDPAddr) error {
	key := addr.String()
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.activeRelays[key]; ok {
		return fmt.Errorf("relay address %s already active", key)
	}
	if _, ok := o.reservedPublicAddrs[key]; ok {
		return fmt.Errorf("relay address %s already reserved", key)
	}
	o.reservedPublicAddrs[key] = struct{}{}
	return nil
}

func (o *openRelayPion) releaseReservedPublicAddr(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	o.mu.Lock()
	delete(o.reservedPublicAddrs, addr.String())
	o.mu.Unlock()
}

func (o *openRelayPion) findRelay(addr *net.UDPAddr) *relayPacketConn {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.activeRelays[addr.String()]
}

type guardedRelayAddressGenerator struct {
	turn.RelayAddressGenerator
	wrapper *openRelayPion
}

func (g *guardedRelayAddressGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	if g.wrapper.cfg.MaxSessions > 0 {
		if atomic.LoadInt64(&g.wrapper.globalSessions) >= int64(g.wrapper.cfg.MaxSessions) {
			return nil, nil, errors.New("global session limit reached")
		}
	}

	res := g.wrapper.consumePendingAllocation()
	conn, relayAddr, preReserved, err := g.allocatePacketConn(network, requestedPort, res)
	if err != nil {
		return nil, nil, err
	}

	if res != nil {
		if actual, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			res.AllocatedPort = actual.Port
			if basePublic, ok := relayAddr.(*net.UDPAddr); ok {
				relayAddr = res.publicRelayAddr(basePublic, actual)
			}
		}
	}

	wrapped, err := newRelayPacketConn(conn, g.wrapper, res, relayAddr, preReserved)
	if err != nil {
		if preReserved {
			if udpAddr, ok := relayAddr.(*net.UDPAddr); ok {
				g.wrapper.releaseReservedPublicAddr(udpAddr)
			}
		}
		_ = conn.Close()
		return nil, nil, err
	}

	atomic.AddInt64(&g.wrapper.globalSessions, 1)

	if res != nil && res.WGGuard != nil {
		return &GuardPacketConn{PacketConn: wrapped, Guard: res.WGGuard, RelayPort: wrapped.actualAddr.Port}, relayAddr, nil
	}
	return wrapped, relayAddr, nil
}

func (g *guardedRelayAddressGenerator) allocatePacketConn(network string, requestedPort int, res *relayReservation) (net.PacketConn, net.Addr, bool, error) {
	if res != nil && res.InternalOnly {
		return g.allocateInternalOnlyPacketConn(network, requestedPort, res)
	}
	switch {
	case res != nil && res.PortRangeStart > 0 && res.PortRangeEnd >= res.PortRangeStart:
		base, ok := g.RelayAddressGenerator.(*turn.RelayAddressGeneratorPortRange)
		if !ok {
			return nil, nil, false, errors.New("user port ranges require RelayAddressGeneratorPortRange")
		}
		conn, relayAddr, err := allocateFromPortRange(base, network, res.PortRangeStart, res.PortRangeEnd)
		return conn, relayAddr, false, err
	case res != nil && res.RequestedPort > 0:
		conn, relayAddr, err := g.RelayAddressGenerator.AllocatePacketConn(network, res.RequestedPort)
		return conn, relayAddr, false, err
	case requestedPort > 0:
		conn, relayAddr, err := g.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
		return conn, relayAddr, false, err
	default:
		conn, relayAddr, err := g.RelayAddressGenerator.AllocatePacketConn(network, 0)
		return conn, relayAddr, false, err
	}
}

func (g *guardedRelayAddressGenerator) allocateInternalOnlyPacketConn(network string, requestedPort int, res *relayReservation) (net.PacketConn, net.Addr, bool, error) {
	conn, relayAddr, err := g.RelayAddressGenerator.AllocatePacketConn(network, 0)
	if err != nil {
		return nil, nil, false, err
	}

	actual, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, nil, false, errors.New("relay listen did not return UDP address")
	}
	basePublic, ok := relayAddr.(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, nil, false, errors.New("relay allocation did not return UDP address")
	}

	publicPort, err := g.chooseInternalOnlyPublicPort(res, requestedPort, basePublic)
	if err != nil {
		_ = conn.Close()
		return nil, nil, false, err
	}
	if publicPort == 0 {
		publicPort = actual.Port
	}
	publicAddr := res.publicRelayAddrWithPort(basePublic, actual, publicPort)
	publicUDP, ok := publicAddr.(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, nil, false, errors.New("internal-only public relay address was not UDP")
	}
	if err := g.wrapper.reservePublicAddr(publicUDP); err != nil {
		_ = conn.Close()
		return nil, nil, false, err
	}
	return conn, publicUDP, true, nil
}

func (g *guardedRelayAddressGenerator) chooseInternalOnlyPublicPort(res *relayReservation, requestedPort int, basePublic *net.UDPAddr) (int, error) {
	switch {
	case res.RequestedPort > 0:
		return res.RequestedPort, nil
	case res.PortRangeStart > 0 && res.PortRangeEnd >= res.PortRangeStart:
		ports := rand.New(rand.NewSource(time.Now().UnixNano())).Perm(res.PortRangeEnd - res.PortRangeStart + 1)
		for _, offset := range ports {
			port := res.PortRangeStart + offset
			addr := &net.UDPAddr{IP: res.publicRelayIP(basePublic.IP), Port: port}
			if err := g.wrapper.reservePublicAddr(addr); err == nil {
				g.wrapper.releaseReservedPublicAddr(addr)
				return port, nil
			}
		}
		return 0, errors.New("failed to allocate internal-only relay port from range")
	case requestedPort > 0:
		return requestedPort, nil
	default:
		return 0, nil
	}
}

func allocateFromPortRange(base *turn.RelayAddressGeneratorPortRange, network string, start, end int) (net.PacketConn, net.Addr, error) {
	if err := base.Validate(); err != nil {
		return nil, nil, err
	}
	if start <= 0 || end < start || end > 65535 {
		return nil, nil, errors.New("invalid port range")
	}
	ports := rand.New(rand.NewSource(time.Now().UnixNano())).Perm(end - start + 1)
	for _, offset := range ports {
		port := start + offset
		conn, err := base.Net.ListenPacket(network, fmt.Sprintf("%s:%d", base.Address, port)) //nolint:noctx
		if err != nil {
			continue
		}
		udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			_ = conn.Close()
			return nil, nil, errors.New("relay listen did not return UDP address")
		}
		return conn, &net.UDPAddr{IP: cloneIP(base.RelayAddress), Port: udpAddr.Port}, nil
	}
	return nil, nil, errors.New("failed to allocate user port from range")
}

func (g *guardedRelayAddressGenerator) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	return g.RelayAddressGenerator.AllocateConn(network, requestedPort)
}

func (g *guardedRelayAddressGenerator) Validate() error {
	return g.RelayAddressGenerator.Validate()
}

func buildPionServer(cfg Config) (*openRelayPion, error) {
	wrapper, err := newOpenRelayPion(cfg)
	if err != nil {
		return nil, err
	}
	listeners, err := normalizedTURNListeners(cfg)
	if err != nil {
		return nil, err
	}
	relayIP := cfg.Listen.RelayIP
	if strings.TrimSpace(relayIP) == "" {
		relayIP = "0.0.0.0"
	}
	var packetConnConfigs []turn.PacketConnConfig
	var listenerConfigs []turn.ListenerConfig
	cleanup := func() {
		for _, cfg := range packetConnConfigs {
			_ = cfg.PacketConn.Close()
		}
		for _, cfg := range listenerConfigs {
			_ = cfg.Listener.Close()
		}
		for _, certMgr := range wrapper.certManagers {
			certMgr.Close()
		}
	}
	for _, listener := range listeners {
		relayGen, err := newRelayAddressGenerator(relayIP, listener.Listen, wrapper)
		if err != nil {
			cleanup()
			return nil, err
		}
		permissionHandler := func(clientAddr net.Addr, peerIP net.IP) bool {
			return wrapper.allowPeer(clientAddr, peerIP)
		}
		switch listener.Type {
		case "udp":
			listenAddr, err := net.ResolveUDPAddr("udp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			pc, err := net.ListenUDP("udp", listenAddr)
			if err != nil {
				cleanup()
				return nil, err
			}
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            pc,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, pc.LocalAddr())
		case "tcp":
			ln, err := net.Listen("tcp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              ln,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, ln.Addr())
		case "tls":
			certMgr, err := newTurnCertManager(listener)
			if err != nil {
				cleanup()
				return nil, err
			}
			wrapper.certManagers = append(wrapper.certManagers, certMgr)
			rawListener, err := net.Listen("tcp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			tlsCfg, err := buildTurnTLSServerConfig(listener, certMgr)
			if err != nil {
				cleanup()
				return nil, err
			}
			ln := tls.NewListener(rawListener, tlsCfg)
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              ln,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, ln.Addr())
		case "dtls":
			certMgr, err := newTurnCertManager(listener)
			if err != nil {
				cleanup()
				return nil, err
			}
			wrapper.certManagers = append(wrapper.certManagers, certMgr)
			udpAddr, err := net.ResolveUDPAddr("udp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			dtlsCfg, err := buildTurnDTLSServerConfig(listener, certMgr)
			if err != nil {
				cleanup()
				return nil, err
			}
			ln, err := piondtls.Listen("udp", udpAddr, dtlsCfg)
			if err != nil {
				cleanup()
				return nil, err
			}
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              ln,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, ln.Addr())
		case "http":
			rawListener, err := net.Listen("tcp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			httpServer, err := newTurnHTTPServer(rawListener, listener.Path, "")
			if err != nil {
				cleanup()
				return nil, err
			}
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            httpServer.PacketConn,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              httpServer.Listener,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, httpServer.Addr())
		case "https":
			certMgr, err := newTurnCertManager(listener)
			if err != nil {
				cleanup()
				return nil, err
			}
			wrapper.certManagers = append(wrapper.certManagers, certMgr)
			rawListener, err := net.Listen("tcp", listener.Listen)
			if err != nil {
				cleanup()
				return nil, err
			}
			serverTLS, err := buildTurnTLSServerConfig(listener, certMgr)
			if err != nil {
				cleanup()
				return nil, err
			}
			altSvc := ""
			if listener.AdvertiseHTTP3 {
				if tcpAddr, ok := rawListener.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
					altSvc = formatHTTP3AltSvc(tcpAddr.Port)
				}
			}
			httpServer, err := newTurnHTTPServer(tls.NewListener(rawListener, serverTLS), listener.Path, altSvc)
			if err != nil {
				cleanup()
				return nil, err
			}
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            httpServer.PacketConn,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              httpServer.Listener,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, httpServer.Addr())
		case "quic":
			certMgr, err := newTurnCertManager(listener)
			if err != nil {
				cleanup()
				return nil, err
			}
			wrapper.certManagers = append(wrapper.certManagers, certMgr)
			server, err := newTurnQUICServer(listener, certMgr)
			if err != nil {
				cleanup()
				return nil, err
			}
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            server.PacketConn,
				RelayAddressGenerator: relayGen,
				PermissionHandler:     permissionHandler,
			})
			wrapper.recordListener(listener.Type, server.Addr())
		}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			return wrapper.authHandler(username, realm, srcAddr)
		},
		EventHandler: turn.EventHandler{
			OnAuth: wrapper.onAuth,
		},
		PacketConnConfigs: packetConnConfigs,
		ListenerConfigs:   listenerConfigs,
	})
	if err != nil {
		cleanup()
		return nil, err
	}
	wrapper.servers = append(wrapper.servers, server)
	return wrapper, nil
}

func (o *openRelayPion) Close() error {
	var first error
	for _, s := range o.servers {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, certMgr := range o.certManagers {
		certMgr.Close()
	}
	return first
}

func newRelayAddressGenerator(relayIP, listenAddr string, wrapper *openRelayPion) (*guardedRelayAddressGenerator, error) {
	bindIP, err := listenerHost(listenAddr)
	if err != nil {
		return nil, err
	}
	return &guardedRelayAddressGenerator{
		RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
			RelayAddress: net.ParseIP(relayIP),
			Address:      bindIP,
			MinPort:      1,
			MaxPort:      65535,
		},
		wrapper: wrapper,
	}, nil
}

func listenerHost(listenAddr string) (string, error) {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "0.0.0.0", nil
	}
	return host, nil
}

func (o *openRelayPion) recordListener(listenerType string, addr net.Addr) {
	o.boundListeners = append(o.boundListeners, boundListener{
		Type: listenerType,
		Addr: addr,
	})
	if listenerType == "udp" {
		if udpAddr, ok := addr.(*net.UDPAddr); ok && o.listenAddr == nil {
			o.listenAddr = cloneUDPAddr(udpAddr)
		}
	}
}

func (o *openRelayPion) listenerAddrByType(listenerType string) net.Addr {
	for _, listener := range o.boundListeners {
		if listener.Type == listenerType {
			return listener.Addr
		}
	}
	return nil
}

func (r *relayReservation) publicRelayAddr(basePublic, actual *net.UDPAddr) net.Addr {
	return r.publicRelayAddrWithPort(basePublic, actual, 0)
}

func (r *relayReservation) publicRelayAddrWithPort(basePublic, actual *net.UDPAddr, publicPort int) net.Addr {
	switch {
	case r == nil:
		return cloneUDPAddr(basePublic)
	case r.MappedAddr != nil:
		return cloneUDPAddr(r.MappedAddr)
	case r.MappedRangeIP != nil && r.MappedRangeStart > 0 && r.PortRangeStart > 0 && r.PortRangeEnd >= r.PortRangeStart:
		if publicPort == 0 {
			publicPort = actual.Port
		}
		return &net.UDPAddr{
			IP:   cloneIP(r.MappedRangeIP),
			Port: r.MappedRangeStart + (publicPort - r.PortRangeStart),
		}
	default:
		if publicPort == 0 {
			return cloneUDPAddr(basePublic)
		}
		return &net.UDPAddr{
			IP:   r.publicRelayIP(basePublic.IP),
			Port: publicPort,
		}
	}
}

func (r *relayReservation) publicRelayIP(fallback net.IP) net.IP {
	switch {
	case r == nil:
		return cloneIP(fallback)
	case r.MappedAddr != nil:
		return cloneIP(r.MappedAddr.IP)
	case r.MappedRangeIP != nil:
		return cloneIP(r.MappedRangeIP)
	default:
		return cloneIP(fallback)
	}
}

func parseCIDRs(items []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range items {
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func parseMappedAddress(s string) (*net.UDPAddr, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	if addr.IP == nil || addr.Port <= 0 {
		return nil, errors.New("must include IP and port")
	}
	return addr, nil
}

func parseBehavior(s string) Behavior {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "allow":
		return BehaviorAllow
	case "allow-if-no-permissions":
		return BehaviorAllowIfNoPermissions
	case "reject-unless-permitted":
		return BehaviorRejectUnlessPermitted
	default:
		return BehaviorAllow
	}
}

func parseMappedRange(cfg MappedRangeConfig, size int) (net.IP, int, error) {
	if strings.TrimSpace(cfg.IP) == "" && cfg.StartPort == 0 {
		return nil, 0, nil
	}
	ip := net.ParseIP(cfg.IP)
	if ip == nil {
		return nil, 0, errors.New("invalid mapped_range.ip")
	}
	if cfg.StartPort <= 0 || cfg.StartPort+size > 65535 {
		return nil, 0, errors.New("invalid mapped_range.start_port")
	}
	return ip, cfg.StartPort, nil
}

func sourceAllowed(ip net.IP, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return true
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func decodePublicKey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, errors.New("invalid public key length")
	}
	copy(out[:], b)
	return out, nil
}

func decryptPublicKey(s string, password string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}

	key := make([]byte, 32)
	copy(key, password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return out, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(b) < nonceSize {
		return out, errors.New("ciphertext too short")
	}

	nonce, ciphertext := b[:nonceSize], b[nonceSize:]
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return out, err
	}
	if len(decrypted) != 32 {
		return out, errors.New("invalid decrypted public key length")
	}
	copy(out[:], decrypted)
	return out, nil
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   cloneIP(addr.IP),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func cloneIPNets(in []*net.IPNet) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, n := range in {
		if n == nil {
			continue
		}
		out = append(out, &net.IPNet{
			IP:   cloneIP(n.IP),
			Mask: append(net.IPMask(nil), n.Mask...),
		})
	}
	return out
}

func normalizeUDPAddr(addr net.Addr) (*net.UDPAddr, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.IP == nil {
		return nil, false
	}
	return cloneUDPAddr(udpAddr), true
}

func addrIP(addr net.Addr) (net.IP, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil || a.IP == nil {
			return nil, false
		}
		return cloneIP(a.IP), true
	case *net.TCPAddr:
		if a == nil || a.IP == nil {
			return nil, false
		}
		return cloneIP(a.IP), true
	default:
		return nil, false
	}
}

func main() {
	configPath := flag.String("config", "turn-open-relay.yaml", "Path to YAML config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	srv, err := buildPionServer(cfg)
	if err != nil {
		log.Fatalf("build Pion TURN server: %v", err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("close server: %v", err)
		}
	}()

	apiServer, err := startAPIServer(cfg.API, srv)
	if err != nil {
		log.Fatalf("start TURN API: %v", err)
	}
	if apiServer != nil {
		defer func() {
			if err := apiServer.Close(); err != nil {
				log.Printf("close TURN API: %v", err)
			}
		}()
		log.Printf("TURN API listening on %s", apiServer.Addr())
	}

	log.Printf("TURN server listening on %s with relay IP %s and realm %s", cfg.Listen.TurnListen, cfg.Listen.RelayIP, cfg.Realm)
	select {}
}
