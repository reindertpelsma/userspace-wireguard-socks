// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	ErrPeerNotFound    = errors.New("peer not found")
	ErrForwardNotFound = errors.New("forward not found")
)

type apiPeer struct {
	PublicKey           string               `json:"public_key"`
	PresharedKey        string               `json:"preshared_key,omitempty"`
	Endpoint            string               `json:"endpoint,omitempty"`
	AllowedIPs          []string             `json:"allowed_ips"`
	PersistentKeepalive int                  `json:"persistent_keepalive,omitempty"`
	TrafficShaper       config.TrafficShaper `json:"traffic_shaper,omitempty"`
	ControlURL          string               `json:"control_url,omitempty"`
	MeshEnabled         bool                 `json:"mesh_enabled,omitempty"`
	MeshAcceptACLs      bool                 `json:"mesh_accept_acls,omitempty"`
	MeshTrust           config.MeshTrust     `json:"mesh_trust,omitempty"`
}

type apiACL struct {
	InboundDefault  acl.Action `json:"inbound_default"`
	OutboundDefault acl.Action `json:"outbound_default"`
	RelayDefault    acl.Action `json:"relay_default"`
	Inbound         []acl.Rule `json:"inbound"`
	Outbound        []acl.Rule `json:"outbound"`
	Relay           []acl.Rule `json:"relay"`
}

type apiForward struct {
	Name          string `json:"name,omitempty"`
	Reverse       bool   `json:"reverse,omitempty"`
	Proto         string `json:"proto,omitempty"`
	Listen        string `json:"listen"`
	Target        string `json:"target"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"`
}

func (e *Engine) startAPIServer() error {
	if e.cfg.API.Listen == "" {
		return nil
	}
	if e.cfg.API.Token == "" && apiListenRequiresToken(e.cfg.API.Listen, e.cfg.API.AllowUnauthenticatedUnix) {
		return fmt.Errorf("api.token is required when api.listen is not a loopback address")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/peers", e.handleAPIPeers)
	mux.HandleFunc("/v1/peers/", e.handleAPIPeer)
	mux.HandleFunc("/v1/acls", e.handleAPIACLs)
	mux.HandleFunc("/v1/acls/", e.handleAPIACLList)
	mux.HandleFunc("/v1/acl", e.handleAPIACLs)
	mux.HandleFunc("/v1/forwards", e.handleAPIForwards)
	mux.HandleFunc("/v1/wireguard/config", e.handleAPIWireGuardConfig)
	mux.HandleFunc("/v1/interface_ips", e.handleAPIInterfaceIPs)
	mux.HandleFunc("/v1/socket", e.handleAPISocket)
	mux.HandleFunc("/v1/status", e.handleAPIStatus)
	mux.HandleFunc("/v1/ping", e.handleAPIPing)
	mux.HandleFunc("/v1/transports", e.handleAPITransports)
	mux.HandleFunc("/v1/transports/", e.handleAPITransport)

	if isUnixEndpoint(e.cfg.API.Listen) {
		_ = os.Remove(unixEndpointPath(e.cfg.API.Listen))
	}

	ln, err := listenEndpoint(e.cfg.API.Listen)
	if err != nil {
		return err
	}
	e.addListener("api", ln)
	server := &http.Server{
		Handler:           e.apiAuth(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		if err := server.Serve(ln); err != nil && !isClosedErr(err) {
			e.log.Printf("api stopped: %v", err)
		}
	}()
	return nil
}

type apiWireGuardConfigRequest struct {
	Config string `json:"config"`
}

func (e *Engine) handleAPIWireGuardConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		text, err := readAPIWireGuardConfigBody(r)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := e.SetWireGuardConfigText(text); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func readAPIWireGuardConfigBody(r *http.Request) (string, error) {
	const maxWireGuardConfigBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWireGuardConfigBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxWireGuardConfigBytes {
		return "", fmt.Errorf("wireguard config body is larger than %d bytes", maxWireGuardConfigBytes)
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req apiWireGuardConfigRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return "", err
		}
		if strings.TrimSpace(req.Config) == "" {
			return "", errors.New("config is required")
		}
		return req.Config, nil
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", errors.New("wireguard config body is required")
	}
	return string(body), nil
}

func (e *Engine) handleAPIInterfaceIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeAPIJSON(w, http.StatusOK, e.InterfaceIPs())
}

func (e *Engine) handleAPIACLList(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/acls/"), "/")
	if name != "inbound" && name != "outbound" && name != "relay" {
		writeAPIError(w, http.StatusNotFound, "unknown ACL list")
		return
	}
	switch r.Method {
	case http.MethodGet:
		c := e.ACL()
		writeAPIJSON(w, http.StatusOK, aclRulesByName(c, name))
	case http.MethodPost:
		var rule acl.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		c := e.ACL()
		appendACLRuleByName(&c, name, rule)
		if err := e.SetACL(c); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		var rules []acl.Rule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		c := e.ACL()
		setACLRulesByName(&c, name, rules)
		if err := e.SetACL(c); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		raw := r.URL.Query().Get("index")
		if raw == "" {
			writeAPIError(w, http.StatusBadRequest, "index query parameter is required")
			return
		}
		idx, err := strconv.Atoi(raw)
		if err != nil || idx < 0 {
			writeAPIError(w, http.StatusBadRequest, "index must be a non-negative integer")
			return
		}
		c := e.ACL()
		if !deleteACLRuleByName(&c, name, idx) {
			writeAPIError(w, http.StatusNotFound, "ACL rule index not found")
			return
		}
		if err := e.SetACL(c); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (e *Engine) handleAPIForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, e.apiForwards())
	case http.MethodPost:
		var req apiForward
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		name, f, err := e.AddForward(req.Reverse, forwardFromAPI(req))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp := forwardToAPI(name, req.Reverse, f)
		writeAPIJSON(w, http.StatusCreated, resp)
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			writeAPIError(w, http.StatusBadRequest, "name query parameter is required")
			return
		}
		if err := e.RemoveForward(name); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrForwardNotFound) {
				status = http.StatusNotFound
			}
			writeAPIError(w, status, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func apiListenRequiresToken(addr string, allowUnauthenticatedUnix bool) bool {
	if isUnixEndpoint(addr) {
		return !allowUnauthenticatedUnix
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func (e *Engine) apiAuth(next http.Handler) http.Handler {
	token := e.cfg.API.Token
	allowUnix := e.cfg.API.AllowUnauthenticatedUnix
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isUnix := r.RemoteAddr == "@" || r.RemoteAddr == "" || strings.HasPrefix(r.RemoteAddr, "/")
		if isUnix && allowUnix {
			next.ServeHTTP(w, r)
			return
		}
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got == "" {
				got = r.Header.Get("Authorization") // Support raw token as well
			}
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				writeAPIError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (e *Engine) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status, err := e.Status()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAPIJSON(w, http.StatusOK, status)
}

func (e *Engine) handleAPIPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		target = q.Get("host")
	}
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, "target query parameter is required")
		return
	}
	count := 4
	if raw := q.Get("count"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeAPIError(w, http.StatusBadRequest, "count must be a positive integer")
			return
		}
		count = n
	}
	timeout := time.Second
	if raw := q.Get("timeout_ms"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeAPIError(w, http.StatusBadRequest, "timeout_ms must be a positive integer")
			return
		}
		timeout = time.Duration(n) * time.Millisecond
	}
	result, err := e.Ping(r.Context(), target, count, timeout)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeAPIJSON(w, http.StatusOK, result)
}

// handleAPIPeers supports collection-style peer operations:
// GET/POST/PUT /v1/peers and DELETE /v1/peers?public_key=...
func (e *Engine) handleAPIPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if pub := r.URL.Query().Get("public_key"); pub != "" {
			peer, err := e.Peer(pub)
			if err != nil {
				writeAPIError(w, http.StatusNotFound, err.Error())
				return
			}
			writeAPIJSON(w, http.StatusOK, peerToAPI(peer))
			return
		}
		peers := e.Peers()
		out := make([]apiPeer, 0, len(peers))
		for _, p := range peers {
			out = append(out, peerToAPI(p))
		}
		writeAPIJSON(w, http.StatusOK, out)
	case http.MethodPost, http.MethodPut:
		var req apiPeer
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := e.AddPeer(peerFromAPI(req)); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		pub := r.URL.Query().Get("public_key")
		if pub == "" {
			writeAPIError(w, http.StatusBadRequest, "public_key query parameter is required")
			return
		}
		if err := e.RemovePeer(pub); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrPeerNotFound) {
				status = http.StatusNotFound
			}
			writeAPIError(w, status, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAPIPeer supports item-style peer operations where the public key is in
// the path. It is convenient for scripts that URL-escape the key once.
func (e *Engine) handleAPIPeer(w http.ResponseWriter, r *http.Request) {
	pub, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/v1/peers/"))
	if err != nil || pub == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid peer public key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		peer, err := e.Peer(pub)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, err.Error())
			return
		}
		writeAPIJSON(w, http.StatusOK, peerToAPI(peer))
	case http.MethodDelete:
		if err := e.RemovePeer(pub); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrPeerNotFound) {
				status = http.StatusNotFound
			}
			writeAPIError(w, status, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAPIACLs swaps the in-memory ACL lists atomically after validation. The
// WireGuard device itself is not touched because ACLs are enforced by engine
// proxy and relay hooks.
func (e *Engine) handleAPIACLs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeAPIJSON(w, http.StatusOK, aclToAPI(e.ACL()))
	case http.MethodPut, http.MethodPost:
		var req apiACL
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := e.SetACL(aclFromAPI(req)); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Peers returns a snapshot of the configured peers safe for API/library callers
// to inspect without holding engine locks.
func (e *Engine) Peers() []config.Peer {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
}

func (e *Engine) Peer(publicKey string) (config.Peer, error) {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	for _, p := range e.cfg.WireGuard.Peers {
		if p.PublicKey == publicKey {
			return p, nil
		}
	}
	return config.Peer{}, ErrPeerNotFound
}

// AddPeer updates both the live wireguard-go device and the engine's AllowedIPs
// cache. Adding a peer with an existing public key replaces that peer.
func (e *Engine) AddPeer(peer config.Peer) error {
	e.cfgMu.RLock()
	transports := e.cfg.Transports
	defTName := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	globalTraffic := e.cfg.TrafficShaper
	e.cfgMu.RUnlock()

	if _, err := peerUAPI(peer, false, transports, defTName); err != nil {
		return err
	}
	if _, _, _, err := buildPeerTrafficState([]config.Peer{peer}, globalTraffic); err != nil {
		return err
	}

	e.cfgMu.Lock()
	next := append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
	replaced := false
	for i := range next {
		if next[i].PublicKey == peer.PublicKey {
			next[i] = peer
			replaced = true
			break
		}
	}
	if !replaced {
		next = append(next, peer)
	}
	if e.dev != nil {
		uapi, err := peerUAPI(peer, false, e.cfg.Transports, transport.ResolveDefaultTransportName(e.cfg.Transports, e.cfg.WireGuard.DefaultTransport))
		if err != nil {
			e.cfgMu.Unlock()
			return err
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			e.cfgMu.Unlock()
			return err
		}
	}
	e.cfg.WireGuard.Peers = next
	e.cfgMu.Unlock()
	if err := e.applyPeerTrafficState(next); err != nil {
		return err
	}
	e.reconcileDynamicPeersWithStatic()
	e.updateTURNPermissions()
	return nil
}

// RemovePeer removes a live peer from wireguard-go and refreshes the AllowedIPs
// cache used by proxy routing decisions.
func (e *Engine) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	e.cfgMu.Lock()
	next := make([]config.Peer, 0, len(e.cfg.WireGuard.Peers))
	found := false
	for _, p := range e.cfg.WireGuard.Peers {
		if p.PublicKey == publicKey {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		e.cfgMu.Unlock()
		return ErrPeerNotFound
	}
	if e.dev != nil {
		uapi := fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(key[:]))
		if err := e.dev.IpcSet(uapi); err != nil {
			e.cfgMu.Unlock()
			return err
		}
	}
	e.cfg.WireGuard.Peers = next
	e.cfgMu.Unlock()
	if err := e.applyPeerTrafficState(next); err != nil {
		return err
	}
	e.reconcileDynamicPeersWithStatic()
	e.updateTURNPermissions()
	return nil
}

// SetWireGuardConfigText applies a wg-quick-style WireGuard device config at
// runtime without executing or retaining PreUp/PostUp/PreDown/PostDown. It replaces the live WireGuard
// private key/listen port/peer set, while rejecting Address/DNS/MTU changes
// because those require rebuilding the userspace netstack.
func (e *Engine) SetWireGuardConfigText(text string) error {
	var wg config.WireGuard
	if err := config.MergeWGQuick(&wg, text); err != nil {
		return err
	}
	return e.SetWireGuardConfig(wg)
}

func (e *Engine) SetWireGuardConfig(wg config.WireGuard) error {
	e.cfgMu.RLock()
	next := e.cfg.WireGuard
	e.cfgMu.RUnlock()
	if err := rejectRuntimeInterfaceChange(next, wg); err != nil {
		return err
	}
	if wg.PrivateKey == "" {
		return errors.New("wireguard config must include PrivateKey")
	}
	next.PrivateKey = wg.PrivateKey
	if wg.ListenPort != nil {
		next.ListenPort = wg.ListenPort
	}
	next.Peers = append([]config.Peer(nil), wg.Peers...)
	next.PreUp = nil
	next.PostUp = nil
	next.PreDown = nil
	next.PostDown = nil

	if err := validateWireGuardConfig(next); err != nil {
		return err
	}
	e.cfgMu.RLock()
	transports := e.cfg.Transports
	e.cfgMu.RUnlock()
	uapi, err := wireGuardUAPI(next, transports)
	if err != nil {
		return err
	}
	if e.dev != nil {
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	e.cfgMu.Lock()
	e.cfg.WireGuard = next
	e.cfgMu.Unlock()
	if err := e.applyPeerTrafficState(next.Peers); err != nil {
		return err
	}
	e.reconcileDynamicPeersWithStatic()
	e.updateTURNPermissions()
	return nil
}

func rejectRuntimeInterfaceChange(current, requested config.WireGuard) error {
	if len(requested.Addresses) > 0 && strings.Join(requested.Addresses, ",") != strings.Join(current.Addresses, ",") {
		return errors.New("runtime WireGuard config cannot change Address; restart the engine to rebuild the userspace netstack")
	}
	if len(requested.DNS) > 0 && strings.Join(requested.DNS, ",") != strings.Join(current.DNS, ",") {
		return errors.New("runtime WireGuard config cannot change DNS; restart the engine to rebuild tunnel DNS routes")
	}
	if requested.MTU != 0 && requested.MTU != current.MTU {
		return errors.New("runtime WireGuard config cannot change MTU; restart the engine to rebuild the userspace netstack")
	}
	return nil
}

func (e *Engine) InterfaceIPs() []string {
	out := make([]string, 0, len(e.localAddrs))
	for _, ip := range e.localAddrs {
		out = append(out, ip.String())
	}
	return out
}

func (e *Engine) ACL() config.ACL {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.cfg.ACL
}

// SetACL validates and swaps all three ACL lists together so callers cannot
// observe a partial inbound/outbound/relay update.
func (e *Engine) SetACL(next config.ACL) error {
	normalized, in, out, rel, err := normalizeACLConfig(next)
	if err != nil {
		return err
	}
	e.cfgMu.Lock()
	e.cfg.ACL = normalized
	e.cfgMu.Unlock()
	e.aclMu.Lock()
	e.inACL = in
	e.outACL = out
	e.relACL = rel
	e.aclMu.Unlock()
	return nil
}

func (e *Engine) apiForwards() []apiForward {
	e.forwardMu.Lock()
	defer e.forwardMu.Unlock()
	out := make([]apiForward, 0, len(e.forwardNames))
	for name, rt := range e.forwardNames {
		out = append(out, forwardToAPI(name, rt.reverse, rt.forward))
	}
	return out
}

func (e *Engine) AddForward(reverse bool, f config.Forward) (string, config.Forward, error) {
	normalized, err := normalizeRuntimeForward(reverse, f)
	if err != nil {
		return "", config.Forward{}, err
	}
	if e.net != nil {
		if reverse {
			if err := e.net.SetPromiscuous(true); err != nil {
				return "", config.Forward{}, fmt.Errorf("enable promiscuous netstack: %w", err)
			}
			if err := e.net.SetSpoofing(true); err != nil {
				return "", config.Forward{}, fmt.Errorf("enable spoofing netstack: %w", err)
			}
		} else if normalized.ProxyProtocol != "" {
			if err := e.net.SetSpoofing(true); err != nil {
				return "", config.Forward{}, fmt.Errorf("enable spoofing netstack: %w", err)
			}
		}
	}

	e.forwardMu.Lock()
	name := fmt.Sprintf("forward.dynamic.%d", e.forwardNext)
	if reverse {
		name = fmt.Sprintf("reverse_forward.dynamic.%d", e.forwardNext)
	}
	e.forwardNext++
	e.forwardMu.Unlock()

	if err := e.startForwardRuntime(name, reverse, normalized); err != nil {
		return "", config.Forward{}, err
	}
	e.registerForwardRuntime(name, reverse, normalized)

	e.cfgMu.Lock()
	if reverse {
		e.cfg.ReverseForwards = append(e.cfg.ReverseForwards, normalized)
	} else {
		e.cfg.Forwards = append(e.cfg.Forwards, normalized)
	}
	e.cfgMu.Unlock()
	return name, normalized, nil
}

func (e *Engine) RemoveForward(name string) error {
	e.forwardMu.Lock()
	rt, ok := e.forwardNames[name]
	if ok {
		delete(e.forwardNames, name)
	}
	e.forwardMu.Unlock()
	if !ok {
		return ErrForwardNotFound
	}
	e.closeListenerName(name)
	e.cfgMu.Lock()
	if rt.reverse {
		e.cfg.ReverseForwards = removeForwardConfig(e.cfg.ReverseForwards, rt.forward)
	} else {
		e.cfg.Forwards = removeForwardConfig(e.cfg.Forwards, rt.forward)
	}
	e.cfgMu.Unlock()
	return nil
}

func normalizeRuntimeForward(reverse bool, f config.Forward) (config.Forward, error) {
	cfg := config.Default()
	if reverse {
		cfg.ReverseForwards = []config.Forward{f}
	} else {
		cfg.Forwards = []config.Forward{f}
	}
	if err := cfg.Normalize(); err != nil {
		return config.Forward{}, err
	}
	if reverse {
		return cfg.ReverseForwards[0], nil
	}
	return cfg.Forwards[0], nil
}

func removeForwardConfig(in []config.Forward, f config.Forward) []config.Forward {
	for i := range in {
		if in[i] == f {
			return append(in[:i], in[i+1:]...)
		}
	}
	return in
}

// peerUAPI renders the minimal WireGuard userspace API stanza for one peer.
// The caller is responsible for deciding whether this is an add/update/remove.
// transports and defaultTransportName are used to prepend the transport prefix
// to the endpoint so that ParseEndpoint creates the correct endpoint type.
// When transports is empty the endpoint is written as-is (legacy UDP path).
func peerUAPI(peer config.Peer, remove bool, transports []transport.Config, defaultTransportName string) (string, error) {
	pub, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
	if remove {
		b.WriteString("remove=true\n")
		return b.String(), nil
	}
	if peer.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared_key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(psk[:]))
	}
	if peer.Endpoint != "" {
		ep := peer.Endpoint
		if len(transports) > 0 {
			tName := peer.Transport
			if tName == "" {
				tName = defaultTransportName
			}
			if tName != "" {
				ep = tName + "@" + peer.Endpoint
			}
		}
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
	}
	if peer.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, allowed := range peer.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", allowed)
	}
	return b.String(), nil
}

func normalizeACLConfig(c config.ACL) (config.ACL, acl.List, acl.List, acl.List, error) {
	in := acl.List{Default: c.InboundDefault, Rules: c.Inbound}
	if err := in.Normalize(); err != nil {
		return config.ACL{}, acl.List{}, acl.List{}, acl.List{}, fmt.Errorf("inbound ACL: %w", err)
	}
	out := acl.List{Default: c.OutboundDefault, Rules: c.Outbound}
	if err := out.Normalize(); err != nil {
		return config.ACL{}, acl.List{}, acl.List{}, acl.List{}, fmt.Errorf("outbound ACL: %w", err)
	}
	rel := acl.List{Default: c.RelayDefault, Rules: c.Relay}
	if err := rel.Normalize(); err != nil {
		return config.ACL{}, acl.List{}, acl.List{}, acl.List{}, fmt.Errorf("relay ACL: %w", err)
	}
	c.InboundDefault, c.Inbound = in.Default, in.Rules
	c.OutboundDefault, c.Outbound = out.Default, out.Rules
	c.RelayDefault, c.Relay = rel.Default, rel.Rules
	return c, in, out, rel, nil
}

func peerToAPI(p config.Peer) apiPeer {
	return apiPeer{
		PublicKey:           p.PublicKey,
		Endpoint:            p.Endpoint,
		AllowedIPs:          append([]string(nil), p.AllowedIPs...),
		PersistentKeepalive: p.PersistentKeepalive,
		TrafficShaper:       p.TrafficShaper,
		ControlURL:          p.ControlURL,
		MeshEnabled:         p.MeshEnabled,
		MeshAcceptACLs:      p.MeshAcceptACLs,
		MeshTrust:           p.MeshTrust,
	}
}

func peerFromAPI(p apiPeer) config.Peer {
	return config.Peer{
		PublicKey:           p.PublicKey,
		PresharedKey:        p.PresharedKey,
		Endpoint:            p.Endpoint,
		AllowedIPs:          append([]string(nil), p.AllowedIPs...),
		PersistentKeepalive: p.PersistentKeepalive,
		TrafficShaper:       p.TrafficShaper,
		ControlURL:          p.ControlURL,
		MeshEnabled:         p.MeshEnabled,
		MeshAcceptACLs:      p.MeshAcceptACLs,
		MeshTrust:           p.MeshTrust,
	}
}

func aclToAPI(c config.ACL) apiACL {
	return apiACL{
		InboundDefault:  c.InboundDefault,
		OutboundDefault: c.OutboundDefault,
		RelayDefault:    c.RelayDefault,
		Inbound:         append([]acl.Rule(nil), c.Inbound...),
		Outbound:        append([]acl.Rule(nil), c.Outbound...),
		Relay:           append([]acl.Rule(nil), c.Relay...),
	}
}

func aclFromAPI(c apiACL) config.ACL {
	return config.ACL{
		InboundDefault:  c.InboundDefault,
		OutboundDefault: c.OutboundDefault,
		RelayDefault:    c.RelayDefault,
		Inbound:         append([]acl.Rule(nil), c.Inbound...),
		Outbound:        append([]acl.Rule(nil), c.Outbound...),
		Relay:           append([]acl.Rule(nil), c.Relay...),
	}
}

func aclRulesByName(c config.ACL, name string) []acl.Rule {
	switch name {
	case "inbound":
		return append([]acl.Rule(nil), c.Inbound...)
	case "outbound":
		return append([]acl.Rule(nil), c.Outbound...)
	case "relay":
		return append([]acl.Rule(nil), c.Relay...)
	default:
		return nil
	}
}

func appendACLRuleByName(c *config.ACL, name string, rule acl.Rule) {
	switch name {
	case "inbound":
		c.Inbound = append(c.Inbound, rule)
	case "outbound":
		c.Outbound = append(c.Outbound, rule)
	case "relay":
		c.Relay = append(c.Relay, rule)
	}
}

func setACLRulesByName(c *config.ACL, name string, rules []acl.Rule) {
	next := append([]acl.Rule(nil), rules...)
	switch name {
	case "inbound":
		c.Inbound = next
	case "outbound":
		c.Outbound = next
	case "relay":
		c.Relay = next
	}
}

func deleteACLRuleByName(c *config.ACL, name string, idx int) bool {
	switch name {
	case "inbound":
		if idx >= len(c.Inbound) {
			return false
		}
		c.Inbound = append(c.Inbound[:idx], c.Inbound[idx+1:]...)
	case "outbound":
		if idx >= len(c.Outbound) {
			return false
		}
		c.Outbound = append(c.Outbound[:idx], c.Outbound[idx+1:]...)
	case "relay":
		if idx >= len(c.Relay) {
			return false
		}
		c.Relay = append(c.Relay[:idx], c.Relay[idx+1:]...)
	default:
		return false
	}
	return true
}

func forwardToAPI(name string, reverse bool, f config.Forward) apiForward {
	return apiForward{
		Name:          name,
		Reverse:       reverse,
		Proto:         f.Proto,
		Listen:        f.Listen,
		Target:        f.Target,
		ProxyProtocol: f.ProxyProtocol,
	}
}

func forwardFromAPI(f apiForward) config.Forward {
	return config.Forward{
		Proto:         f.Proto,
		Listen:        f.Listen,
		Target:        f.Target,
		ProxyProtocol: f.ProxyProtocol,
	}
}

func writeAPIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeAPIJSON(w, status, map[string]string{"error": message})
}

// --- /v1/transports --------------------------------------------------------

type apiTransport struct {
	Name              string                `json:"name"`
	Base              string                `json:"base"`
	Listen            bool                  `json:"listen"`
	ListenPort        *int                  `json:"listen_port,omitempty"`
	ListenAddresses   []string              `json:"listen_addresses,omitempty"`
	TLS               transport.TLSConfig   `json:"tls,omitempty"`
	TURN              transport.TURNConfig  `json:"turn,omitempty"`
	Proxy             transport.ProxyConfig `json:"proxy,omitempty"`
	IPv6Translate     bool                  `json:"ipv6_translate,omitempty"`
	IPv6Prefix        string                `json:"ipv6_prefix,omitempty"`
	ActiveSessions    int                   `json:"active_sessions"`
	Connected         bool                  `json:"connected,omitempty"`
	CarrierProtocol   string                `json:"carrier_protocol,omitempty"`
	CarrierLocalAddr  string                `json:"carrier_local_addr,omitempty"`
	CarrierRemoteAddr string                `json:"carrier_remote_addr,omitempty"`
	RelayAddr         string                `json:"relay_addr,omitempty"`
}

// handleAPITransports handles GET /v1/transports and POST /v1/transports.
func (e *Engine) handleAPITransports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		e.cfgMu.RLock()
		cfgs := append([]transport.Config(nil), e.cfg.Transports...)
		e.cfgMu.RUnlock()

		out := make([]apiTransport, 0, len(cfgs))
		for _, tc := range cfgs {
			tc = transport.NormalizeConfig(tc)
			at := apiTransport{
				Name:            tc.Name,
				Base:            tc.Base,
				Listen:          tc.Listen,
				ListenPort:      tc.ListenPort,
				ListenAddresses: tc.ListenAddresses,
				TLS:             tc.TLS,
				TURN:            tc.TURN,
				Proxy:           tc.Proxy,
				IPv6Translate:   tc.IPv6Translate,
				IPv6Prefix:      tc.IPv6Prefix,
			}
			for _, ts := range e.GetTransportStatus() {
				if ts.Name != tc.Name {
					continue
				}
				at.ActiveSessions = ts.ActiveSessions
				at.Connected = ts.Connected
				at.CarrierProtocol = ts.CarrierProtocol
				at.CarrierLocalAddr = ts.CarrierLocalAddr
				at.CarrierRemoteAddr = ts.CarrierRemoteAddr
				at.RelayAddr = ts.RelayAddr
				break
			}
			out = append(out, at)
		}
		writeAPIJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var tc transport.Config
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := json.Unmarshal(body, &tc); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if tc.Name == "" {
			writeAPIError(w, http.StatusBadRequest, "name is required")
			return
		}
		tc = transport.NormalizeConfig(tc)
		if err := transport.ValidateBase(tc.Base); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := e.AddTransportConfig(tc); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		e.cfgMu.Lock()
		e.cfg.Transports = append(e.cfg.Transports, tc)
		e.cfgMu.Unlock()
		writeAPIJSON(w, http.StatusCreated, map[string]string{"name": tc.Name})

	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAPITransport handles DELETE /v1/transports/{name}.
func (e *Engine) handleAPITransport(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transports/")
	if name == "" {
		writeAPIError(w, http.StatusBadRequest, "transport name required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		e.cfgMu.RLock()
		var found *transport.Config
		for _, tc := range e.cfg.Transports {
			tc := tc
			if tc.Name == name {
				found = &tc
				break
			}
		}
		e.cfgMu.RUnlock()
		if found == nil {
			writeAPIError(w, http.StatusNotFound, "transport not found")
			return
		}
		at := apiTransport{
			Name:            found.Name,
			Base:            transport.NormalizeConfig(*found).Base,
			Listen:          found.Listen,
			ListenPort:      found.ListenPort,
			ListenAddresses: found.ListenAddresses,
			TLS:             found.TLS,
			TURN:            transport.NormalizeConfig(*found).TURN,
			Proxy:           transport.NormalizeConfig(*found).Proxy,
			IPv6Translate:   found.IPv6Translate,
			IPv6Prefix:      found.IPv6Prefix,
		}
		for _, ts := range e.GetTransportStatus() {
			if ts.Name != found.Name {
				continue
			}
			at.ActiveSessions = ts.ActiveSessions
			at.Connected = ts.Connected
			at.CarrierProtocol = ts.CarrierProtocol
			at.CarrierLocalAddr = ts.CarrierLocalAddr
			at.CarrierRemoteAddr = ts.CarrierRemoteAddr
			at.RelayAddr = ts.RelayAddr
			break
		}
		writeAPIJSON(w, http.StatusOK, at)

	case http.MethodDelete:
		if e.transportBind == nil {
			writeAPIError(w, http.StatusConflict, "pluggable transports not active")
			return
		}
		e.cfgMu.Lock()
		newCfgs := e.cfg.Transports[:0]
		found := false
		for _, tc := range e.cfg.Transports {
			if tc.Name == name {
				found = true
				continue
			}
			newCfgs = append(newCfgs, tc)
		}
		if found {
			e.cfg.Transports = newCfgs
		}
		e.cfgMu.Unlock()
		if !found {
			writeAPIError(w, http.StatusNotFound, "transport not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
