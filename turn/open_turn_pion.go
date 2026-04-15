package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	turn "github.com/pion/turn/v4"
	yaml "gopkg.in/yaml.v3"
)

type Behavior int

type Config struct {
	Realm              string        `yaml:"realm"`
	Software           string        `yaml:"software"`
	AllocationTTL      string        `yaml:"allocation_ttl"`
	NonceTTL           string        `yaml:"nonce_ttl"`
	PreopenSinglePorts bool          `yaml:"preopen_single_ports"`
	Listen             ListenConfig  `yaml:"listen"`
	Users              []UserConfig  `yaml:"users"`
	PortRanges         []RangeConfig `yaml:"port_ranges"`
	MaxSessions        int           `yaml:"max_sessions"`
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
}

type MappedRangeConfig struct {
	IP        string `yaml:"ip"`
	StartPort int    `yaml:"start_port"`
}

type UserConfig struct {
	Username           string   `yaml:"username"`
	Password           string   `yaml:"password"`
	Port               int      `yaml:"port"`
	PermissionBehavior string   `yaml:"permission_behavior"`
	SourceNetworks     []string `yaml:"source_networks"`
	MappedAddress      string   `yaml:"mapped_address"`
	WireguardPublicKey string   `yaml:"wireguard_public_key"`
	WireguardMode      string   `yaml:"wireguard_mode"`
	MaxSessions        int      `yaml:"max_sessions"`
}

type ListenConfig struct {
	TurnListen string `yaml:"turn_listen"`
	RelayIP    string `yaml:"relay_ip"`
}

type turnAuthRule struct {
	Username       string
	Password       string
	Port           int
	Behavior       Behavior
	SourceNetworks []*net.IPNet
	MappedAddr     *net.UDPAddr
	WGGuard        *WireguardGuard
	WGMode         string
	MaxSessions    int
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
}

const (
	BehaviorAllow Behavior = iota
	BehaviorAllowIfNoPermissions
	BehaviorRejectUnlessPermitted
)

type relayReservation struct {
	Username   string
	ClientIP   string
	Port       int
	MappedAddr *net.UDPAddr
	Behavior   Behavior
	Sources    []*net.IPNet
	WGGuard    *WireguardGuard
}

type openRelayPion struct {
	cfg        Config
	userRules  map[string]*turnAuthRule
	rangeRules []turnRangeRule

	mu           sync.RWMutex
	reservations map[string]*relayReservation
	servers      []*turn.Server

	globalSessions int64
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
	if cfg.Listen.TurnListen == "" {
		cfg.Listen.TurnListen = "0.0.0.0:3478"
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
	return cfg, nil
}

func newOpenRelayPion(cfg Config) (*openRelayPion, error) {
	o := &openRelayPion{
		cfg:          cfg,
		userRules:    map[string]*turnAuthRule{},
		reservations: map[string]*relayReservation{},
	}
	for _, u := range cfg.Users {
		nets, err := parseCIDRs(u.SourceNetworks)
		if err != nil {
			return nil, fmt.Errorf("user %q source_networks: %w", u.Username, err)
		}
		mapped, err := parseMappedAddress(u.MappedAddress)
		if err != nil {
			return nil, fmt.Errorf("user %q mapped_address: %w", u.Username, err)
		}
		var guard *WireguardGuard
		if u.WireguardPublicKey != "" {
			pk, err := decodePublicKey(u.WireguardPublicKey)
			if err != nil {
				return nil, fmt.Errorf("user %q wireguard_public_key: %w", u.Username, err)
			}
			guard = NewWireguardGuard(pk)
			guard.MaxSessions = u.MaxSessions
		}
		o.userRules[u.Username] = &turnAuthRule{
			Username:       u.Username,
			Password:       u.Password,
			Port:           u.Port,
			Behavior:       parseBehavior(u.PermissionBehavior),
			SourceNetworks: nets,
			MappedAddr:     mapped,
			WGGuard:        guard,
			WGMode:         u.WireguardMode,
			MaxSessions:    u.MaxSessions,
		}
	}
	for _, r := range cfg.PortRanges {
		nets, err := parseCIDRs(r.SourceNetworks)
		if err != nil {
			return nil, fmt.Errorf("range %d-%d source_networks: %w", r.Start, r.End, err)
		}
		mappedIP, mappedStart, err := parseMappedRange(r.MappedRange, r.End-r.Start)
		if err != nil {
			return nil, fmt.Errorf("range %d-%d mapped_range: %w", r.Start, r.End, err)
		}
		var guard *WireguardGuard
		if r.WireguardPublicKey != "" {
			pk, err := decodePublicKey(r.WireguardPublicKey)
			if err != nil {
				return nil, fmt.Errorf("range %d-%d wireguard_public_key: %w", r.Start, r.End, err)
			}
			guard = NewWireguardGuard(pk)
			guard.MaxSessions = r.MaxSessions
		}
		o.rangeRules = append(o.rangeRules, turnRangeRule{
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
		})
	}
	sort.Slice(o.rangeRules, func(i, j int) bool { return o.rangeRules[i].Start < o.rangeRules[j].Start })
	return o, nil
}

func (o *openRelayPion) authHandler(username, realm string, srcAddr net.Addr) ([]byte, bool) {
	udpSrc, ok := srcAddr.(*net.UDPAddr)
	if !ok {
		return nil, false
	}
	
	// Split dynamic username: ORIGINAL_USERNAME---BASE64_ENCRYPTED_PK
	baseUsername := username
	var encryptedPK string
	if idx := strings.LastIndex(username, "---"); idx != -1 {
		baseUsername = username[:idx]
		encryptedPK = username[idx+3:]
	}

	rule, password, port, behavior, srcNets, mapped, guard, wgMode, maxSess, err := o.lookup(baseUsername)
	if err != nil {
		_ = rule
		return nil, false
	}
	if !sourceAllowed(udpSrc.IP, srcNets) {
		return nil, false
	}

	finalGuard := guard
	if wgMode != "disabled" {
		if encryptedPK != "" && (wgMode == "default-with-overwrite" || wgMode == "required-in-username" || wgMode == "") {
			pk, err := decryptPublicKey(encryptedPK, password)
			if err == nil {
				finalGuard = NewWireguardGuard(pk)
				finalGuard.MaxSessions = maxSess
			} else if wgMode == "required-in-username" {
				return nil, false
			}
		} else if wgMode == "required-in-username" && encryptedPK == "" {
			return nil, false
		}
	} else {
		finalGuard = nil
	}

	res := &relayReservation{
		Username:   baseUsername,
		ClientIP:   udpSrc.IP.String(),
		Port:       port,
		MappedAddr: mapped,
		Behavior:   behavior,
		Sources:    srcNets,
		WGGuard:    finalGuard,
	}
	o.mu.Lock()
	o.reservations[username+"|"+udpSrc.IP.String()] = res
	o.mu.Unlock()
	key := turn.GenerateAuthKey(baseUsername, realm, password)
	return key, true
}

func (o *openRelayPion) lookup(username string) (*turnAuthRule, string, int, Behavior, []*net.IPNet, *net.UDPAddr, *WireguardGuard, string, int, error) {
	if u := o.userRules[username]; u != nil {
		return u, u.Password, u.Port, u.Behavior, u.SourceNetworks, u.MappedAddr, u.WGGuard, u.WGMode, u.MaxSessions, nil
	}
	p, err := strconv.Atoi(username)
	if err != nil {
		return nil, "", 0, 0, nil, nil, nil, "", 0, fmt.Errorf("username not found")
	}
	for _, r := range o.rangeRules {
		if p >= r.Start && p <= r.End {
			var mapped *net.UDPAddr
			if r.MappedIP != nil && r.MappedStart != 0 {
				mapped = &net.UDPAddr{IP: append(net.IP(nil), r.MappedIP...), Port: r.MappedStart + (p - r.Start)}
			}
			return nil, r.Password, p, r.Behavior, r.SourceNetworks, mapped, r.WGGuard, r.WGMode, r.MaxSessions, nil
		}
	}
	return nil, "", 0, 0, nil, nil, nil, "", 0, fmt.Errorf("username not found")
}

func (o *openRelayPion) reservation(username string, src net.Addr) *relayReservation {
	udpSrc, ok := src.(*net.UDPAddr)
	if !ok {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.reservations[username+"|"+udpSrc.IP.String()]
}

func (o *openRelayPion) allowPeer(clientAddr net.Addr, peerIP net.IP) bool {
	udpSrc, ok := clientAddr.(*net.UDPAddr)
	if !ok {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for k, r := range o.reservations {
		parts := strings.Split(k, "|")
		if parts[1] != udpSrc.IP.String() {
			continue
		}
		if !sourceAllowed(peerIP, r.Sources) {
			return false
		}
		return true
	}
	return false
}

type globalLimitedPacketConn struct {
	net.PacketConn
	wrapper *openRelayPion
}

func (c *globalLimitedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	return n, addr, err
}

func (c *globalLimitedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(p, addr)
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

	conn, addr, err := g.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}
	udpAddr := addr.(*net.UDPAddr)

	atomic.AddInt64(&g.wrapper.globalSessions, 1)

	g.wrapper.mu.RLock()
	var guard *WireguardGuard
	for _, res := range g.wrapper.reservations {
		if res.Port == udpAddr.Port {
			guard = res.WGGuard
			break
		}
	}
	g.wrapper.mu.RUnlock()

	wrapped := &sessionCountingPacketConn{PacketConn: conn, wrapper: g.wrapper}

	if guard != nil {
		return &GuardPacketConn{PacketConn: wrapped, Guard: guard, RelayPort: udpAddr.Port}, addr, nil
	}
	return wrapped, addr, nil
}

type sessionCountingPacketConn struct {
	net.PacketConn
	wrapper *openRelayPion
	once    sync.Once
}

func (c *sessionCountingPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(func() {
		atomic.AddInt64(&c.wrapper.globalSessions, -1)
	})
	return err
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
	listenAddr, err := net.ResolveUDPAddr("udp", cfg.Listen.TurnListen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	relayIP := cfg.Listen.RelayIP
	if strings.TrimSpace(relayIP) == "" {
		relayIP = "0.0.0.0"
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			return wrapper.authHandler(username, realm, srcAddr)
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &guardedRelayAddressGenerator{
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: net.ParseIP(relayIP),
					Address:      relayIP,
					MinPort:      1,
					MaxPort:      65535,
				},
				wrapper: wrapper,
			},
			PermissionHandler: func(clientAddr net.Addr, peerIP net.IP) bool {
				return wrapper.allowPeer(clientAddr, peerIP)
			},
		}},
	})
	if err != nil {
		_ = pc.Close()
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
	return first
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

	log.Printf("TURN server listening on %s with relay IP %s and realm %s", cfg.Listen.TurnListen, cfg.Listen.RelayIP, cfg.Realm)
	select {}
}
