// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	meshTokenVersionV1     = 1
	meshTokenVersionV2     = 2
	meshAuthContextLabel   = "uwgsocks-mesh-auth"
	meshBodyContextLabel   = "uwgsocks-mesh-body"
	meshChallengeBodyLimit = 4 << 10
	meshDynamicPeerLimit   = 1024
)

type meshChallengeResponse struct {
	ServerPublicKey    string `json:"server_public_key"`
	ChallengePublicKey string `json:"challenge_public_key"`
	TokenVersion       uint8  `json:"token_version,omitempty"`
	ExpiresUnix        int64  `json:"expires_unix"`
}

type meshDiscoveredPeer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	PSK        string   `json:"psk,omitempty"`
	MeshAccept bool     `json:"mesh_accept_acls,omitempty"`
	MeshTrust  string   `json:"mesh_trust,omitempty"`
}

type meshACLResponse struct {
	Default  acl.Action `json:"default"`
	Inbound  []acl.Rule `json:"inbound,omitempty"`
	Outbound []acl.Rule `json:"outbound,omitempty"`
}

type meshAuthResult struct {
	PeerPublicKey string
	PeerIndex     int
	SharedSecret  []byte
}

type dynamicPeer struct {
	Peer            config.Peer
	ParentPublicKey string
	Active          bool
	LastControl     time.Time
}

type meshAuthenticator interface {
	Challenge(now time.Time) (meshChallengeResponse, error)
	Verify(r *http.Request) (meshAuthResult, error)
}

type meshChallengeState struct {
	priv    *ecdh.PrivateKey
	pub     []byte
	expires time.Time
}

type meshControlAuthenticator struct {
	e       *Engine
	curve   ecdh.Curve
	pubKey  wgtypes.Key
	privKey *ecdh.PrivateKey

	mu      sync.Mutex
	current meshChallengeState
	prev    meshChallengeState
}

func newMeshControlAuthenticator(e *Engine) (*meshControlAuthenticator, error) {
	pub, err := e.wgPublicKey()
	if err != nil {
		return nil, err
	}
	parsedPriv, err := wgtypes.ParseKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(parsedPriv[:])
	if err != nil {
		return nil, err
	}
	return &meshControlAuthenticator{
		e:       e,
		curve:   ecdh.X25519(),
		pubKey:  wgtypes.Key(pub),
		privKey: priv,
	}, nil
}

func (a *meshControlAuthenticator) Challenge(now time.Time) (meshChallengeResponse, error) {
	state, _, err := a.challengeState(now)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	return meshChallengeResponse{
		ServerPublicKey:    a.pubKey.String(),
		ChallengePublicKey: base64.StdEncoding.EncodeToString(state.pub),
		TokenVersion:       meshTokenVersionV2,
		ExpiresUnix:        state.expires.Unix(),
	}, nil
}

func (a *meshControlAuthenticator) Verify(r *http.Request) (meshAuthResult, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return meshAuthResult{}, errors.New("missing bearer token")
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")))
	if err != nil {
		return meshAuthResult{}, errors.New("invalid bearer token encoding")
	}
	if len(token) < 1+32+32+24+16+32 {
		return meshAuthResult{}, errors.New("invalid bearer token length")
	}
	tokenVersion := token[0]
	// v1 tokens were superseded by v2 in early development. Challenge() only
	// ever issues v2 (see meshChallengeResponse.TokenVersion in Challenge),
	// so the v1 branch is dead — tighten the gate to v2-only and drop the
	// v1 verifier entirely below to remove a maintenance trap.
	if tokenVersion != meshTokenVersionV2 {
		return meshAuthResult{}, errors.New("unsupported bearer token version")
	}
	ephPub := token[1:33]
	quick := token[33:65]
	body := token[65 : len(token)-32]
	wantHash := token[len(token)-32:]

	addrBinding, err := meshAddrBindingFromRemote(r.RemoteAddr)
	if err != nil {
		return meshAuthResult{}, err
	}
	now := time.Now()
	states, serverPubBytes, err := a.challengeCandidates(now)
	if err != nil {
		return meshAuthResult{}, err
	}
	for _, state := range states {
		if subtle.ConstantTimeCompare(meshQuickCheck(serverPubBytes, state.pub, addrBinding), quick) != 1 {
			continue
		}
		res, err := a.verifyWithState(tokenVersion, state, ephPub, body, wantHash, addrBinding, r.RemoteAddr)
		if err == nil {
			return res, nil
		}
	}
	return meshAuthResult{}, errors.New("invalid bearer token")
}

func (a *meshControlAuthenticator) verifyWithState(tokenVersion byte, state meshChallengeState, ephPub, body, wantHash, addrBinding []byte, remote string) (meshAuthResult, error) {
	eph, err := a.curve.NewPublicKey(append([]byte(nil), ephPub...))
	if err != nil {
		return meshAuthResult{}, err
	}
	k1, err := state.priv.ECDH(eph)
	if err != nil {
		return meshAuthResult{}, err
	}
	// v2 binds the server static key into the auth key alongside the
	// challenge ephemeral so a future leak of the challenge ECDH does not on
	// its own forge tokens. v1 (which only used k1) is no longer accepted.
	_ = tokenVersion
	staticShared, err := a.privKey.ECDH(eph)
	if err != nil {
		return meshAuthResult{}, err
	}
	authKey := meshAuthKey(k1, staticShared)
	plain, err := meshOpen(body, authKey, meshAuthContextLabel)
	if err != nil {
		return meshAuthResult{}, err
	}
	if len(plain) != 32 {
		return meshAuthResult{}, errors.New("invalid mesh auth identity size")
	}
	peerKey := wgtypes.Key(plain)
	peer, idx, ok := a.e.meshPeerConfig(peerKey.String())
	if !ok || !peer.MeshEnabled {
		return meshAuthResult{}, errors.New("mesh peer not enabled")
	}
	src := addrFromNetAddr(mustResolveTCPAddr(remote))
	if !src.IsValid() || a.e.peerKeyForIP(src) != peer.PublicKey {
		return meshAuthResult{}, errors.New("mesh peer source mismatch")
	}
	peerPub, err := a.curve.NewPublicKey(plain)
	if err != nil {
		return meshAuthResult{}, err
	}
	k2, err := state.priv.ECDH(peerPub)
	if err != nil {
		return meshAuthResult{}, err
	}
	secret := meshSharedSecret(authKey, k2, meshPeerPSKBytes(peer), addrBinding)
	gotHash := sha256.Sum256(secret)
	if subtle.ConstantTimeCompare(gotHash[:], wantHash) != 1 {
		return meshAuthResult{}, errors.New("mesh shared secret mismatch")
	}
	return meshAuthResult{
		PeerPublicKey: peer.PublicKey,
		PeerIndex:     idx,
		SharedSecret:  secret,
	}, nil
}

func (a *meshControlAuthenticator) challengeState(now time.Time) (meshChallengeState, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rotate := time.Duration(a.e.cfg.MeshControl.ChallengeRotateSeconds) * time.Second
	if rotate <= 0 {
		rotate = 120 * time.Second
	}
	if a.current.priv == nil || !now.Before(a.current.expires) {
		a.prev = a.current
		priv, err := a.curve.GenerateKey(rand.Reader)
		if err != nil {
			return meshChallengeState{}, nil, err
		}
		a.current = meshChallengeState{
			priv:    priv,
			pub:     append([]byte(nil), priv.PublicKey().Bytes()...),
			expires: now.Add(rotate),
		}
	}
	return a.current, a.pubKey[:], nil
}

func (a *meshControlAuthenticator) challengeCandidates(now time.Time) ([]meshChallengeState, []byte, error) {
	current, serverPubBytes, err := a.challengeState(now)
	if err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	states := []meshChallengeState{current}
	// The previous challenge state is honored for one extra rotation window
	// past its own expiry. This intentionally widens the verifier so that
	// clients which fetched a challenge moments before rotation still
	// authenticate cleanly. Effective lifetime of any single ephemeral is
	// therefore 2 * MeshControl.ChallengeRotateSeconds; size that field
	// accordingly.
	if a.prev.priv != nil && now.Before(a.prev.expires.Add(time.Duration(a.e.cfg.MeshControl.ChallengeRotateSeconds)*time.Second)) {
		states = append(states, a.prev)
	}
	return states, serverPubBytes, nil
}

// startMeshControlServer binds the opt-in mesh control HTTP service inside the
// userspace WireGuard netstack. It is intentionally tunnel-only, similar to
// dns_server.listen, and does not expose a host listener.
func (e *Engine) startMeshControlServer() error {
	if e.cfg.MeshControl.Listen == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(e.cfg.MeshControl.Listen)
	if err != nil {
		return err
	}
	baseLn, err := e.net.ListenTCPAddrPort(addr)
	if err != nil {
		return fmt.Errorf("mesh control listen: %w", err)
	}
	auth, err := newMeshControlAuthenticator(e)
	if err != nil {
		_ = baseLn.Close()
		return err
	}
	e.meshAuth = auth
	ln := e.wrapPeerListener(baseLn)
	e.addListener("mesh-control", ln)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", e.handleMeshControlChallenge)
	mux.HandleFunc("/v1/peers", e.handleMeshControlPeers)
	mux.HandleFunc("/v1/acls", e.handleMeshControlACLs)
	mux.HandleFunc("/v1/subscribe", e.handleMeshControlNotImplemented)

	server := e.proxyHTTPServer(e.meshControlRateLimit(mux))
	go func() {
		if err := server.Serve(ln); err != nil && !isClosedErr(err) {
			e.log.Printf("mesh control stopped: %v", err)
		}
	}()
	return nil
}

// meshControlRateLimit caps requests-per-second per source IP for the mesh
// control HTTP listener. WireGuard peers themselves are NOT trusted in this
// project's threat model — anyone who handshakes can hit the listener — so a
// chatty (or hostile) peer hammering /v1/challenge or /v1/peers must not be
// able to keep the mesh control loop hot or evict legitimate peers' state.
//
// The HTTP and SOCKS5 proxy listeners deliberately do NOT use this: they are
// intended for internal/local use, where rate-limiting trades off ergonomics
// for a defense the deployment doesn't need.
const (
	meshControlRequestsPerSecond = 10
	meshControlBurst             = 20
	meshControlMaxBuckets        = 4096
)

func (e *Engine) meshControlRateLimit(next http.Handler) http.Handler {
	bucketsMu := sync.Mutex{}
	buckets := make(map[string]*meshRateBucket)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteHostOnly(r.RemoteAddr)
		now := time.Now()
		bucketsMu.Lock()
		b := buckets[ip]
		if b == nil {
			// Cap the map so a peer cycling through source ports (or a
			// flood from a spoofed-source IPv6 range) cannot grow it
			// without bound. When full, drop the oldest entry rather
			// than refusing the new one — eviction is cheaper than the
			// cost of letting state grow unbounded.
			if len(buckets) >= meshControlMaxBuckets {
				evictOldestRateBucket(buckets)
			}
			b = &meshRateBucket{tokens: meshControlBurst, last: now}
			buckets[ip] = b
		}
		// Token bucket: refill since last touch, then try to spend one.
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = minFloat(float64(meshControlBurst), b.tokens+elapsed*float64(meshControlRequestsPerSecond))
		b.last = now
		ok := b.tokens >= 1
		if ok {
			b.tokens--
		}
		bucketsMu.Unlock()
		if !ok {
			if e.metrics != nil {
				e.metrics.meshRequestsRateLimited.Add(1)
			}
			w.Header().Set("Retry-After", "1")
			writeAPIError(w, http.StatusTooManyRequests, "mesh control rate limit exceeded")
			return
		}
		if e.metrics != nil {
			e.metrics.meshRequestsOK.Add(1)
		}
		next.ServeHTTP(w, r)
	})
}

type meshRateBucket struct {
	tokens float64
	last   time.Time
}

func evictOldestRateBucket(buckets map[string]*meshRateBucket) {
	var oldestKey string
	var oldest time.Time
	for k, v := range buckets {
		if oldestKey == "" || v.last.Before(oldest) {
			oldestKey = k
			oldest = v.last
		}
	}
	if oldestKey != "" {
		delete(buckets, oldestKey)
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// remoteHostOnly returns just the IP portion of a "host:port" RemoteAddr, so
// a peer cycling source ports doesn't get a fresh bucket each time.
func remoteHostOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

func (e *Engine) handleMeshControlChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	resp, err := e.meshAuth.Challenge(time.Now())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAPIJSON(w, http.StatusOK, resp)
}

func (e *Engine) handleMeshControlPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	peers, err := e.meshPeersForRequester(authRes.PeerPublicKey)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.Marshal(peers)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := meshSealRandom(payload, authRes.SharedSecret, meshBodyContextLabel)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (e *Engine) handleMeshControlACLs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	resp, err := e.meshACLsForRequester(authRes.PeerPublicKey)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := meshSealRandom(payload, authRes.SharedSecret, meshBodyContextLabel)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (e *Engine) handleMeshControlNotImplemented(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "mesh control endpoint is not implemented yet",
	})
}

func (e *Engine) meshPeersForRequester(requester string) ([]meshDiscoveredPeer, error) {
	status, err := e.Status()
	if err != nil {
		return nil, err
	}
	requesterPeer, _, ok := e.meshPeerConfig(requester)
	if !ok || !requesterPeer.MeshAcceptACLs {
		return nil, nil
	}
	e.cfgMu.RLock()
	configPeers := append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
	transports := append([]transport.Config(nil), e.cfg.Transports...)
	defaultTransport := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	window := time.Duration(e.cfg.MeshControl.ActivePeerWindowSeconds) * time.Second
	advertiseSelf := e.cfg.MeshControl.AdvertiseSelf
	e.cfgMu.RUnlock()
	if window <= 0 {
		window = 120 * time.Second
	}
	now := time.Now()
	statusByKey := make(map[string]PeerStatus, len(status.Peers))
	for _, st := range status.Peers {
		statusByKey[st.PublicKey] = st
	}

	out := make([]meshDiscoveredPeer, 0, len(configPeers))
	for _, peer := range configPeers {
		if peer.PublicKey == requester {
			continue
		}
		if !peer.MeshAcceptACLs && peer.MeshTrust == config.MeshTrustUntrusted {
			continue
		}
		if !advertiseSelf && peer.PublicKey == e.meshServerPublicKey() {
			continue
		}
		if peer.MeshAdvertise != nil && !*peer.MeshAdvertise {
			continue
		}
		st, ok := statusByKey[peer.PublicKey]
		if !ok || !st.HasHandshake {
			continue
		}
		if last := time.Unix(st.LastHandshakeTimeSec, st.LastHandshakeTimeNsec); now.Sub(last) > window {
			continue
		}
		allowed := slices.Clone(peer.AllowedIPs)
		sort.Strings(allowed)
		psk, err := e.meshPairPSK(requester, peer.PublicKey)
		if err != nil {
			return nil, err
		}
		endpoint := meshAdvertisedEndpoint(peer, st, transports, defaultTransport)
		out = append(out, meshDiscoveredPeer{
			PublicKey:  peer.PublicKey,
			Endpoint:   endpoint,
			AllowedIPs: allowed,
			PSK:        base64.StdEncoding.EncodeToString(psk),
			MeshAccept: peer.MeshAcceptACLs,
			MeshTrust:  string(peer.MeshTrust),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func (e *Engine) meshACLsForRequester(requester string) (meshACLResponse, error) {
	peer, _, ok := e.meshPeerConfig(requester)
	if !ok || !peer.MeshAcceptACLs {
		return meshACLResponse{}, nil
	}
	requesterPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{peer})
	if err != nil {
		return meshACLResponse{}, err
	}
	e.aclMu.RLock()
	rules := append([]acl.Rule(nil), e.relACL.Rules...)
	def := e.relACL.Default
	e.aclMu.RUnlock()
	inbound := make([]acl.Rule, 0, len(rules))
	outbound := make([]acl.Rule, 0, len(rules))
	for _, rule := range rules {
		if projected, ok := meshProjectRelayRuleForDestination(rule, requesterPrefixes); ok {
			inbound = append(inbound, projected)
		}
		if projected, ok := meshProjectRelayRuleForSource(rule, requesterPrefixes); ok {
			outbound = append(outbound, projected)
		}
	}
	return meshACLResponse{Default: def, Inbound: inbound, Outbound: outbound}, nil
}

func meshAdvertisedEndpoint(peer config.Peer, st PeerStatus, transports []transport.Config, defaultTransport string) string {
	if st.Endpoint == "" {
		return ""
	}
	if len(transports) == 0 {
		return st.Endpoint
	}
	name := peer.Transport
	if name == "" {
		name = defaultTransport
	}
	if name == "" {
		return st.Endpoint
	}
	for _, tc := range transports {
		tc = transport.NormalizeConfig(tc)
		if tc.Name != name {
			continue
		}
		switch tc.Base {
		case "", "udp":
			return st.Endpoint
		case "turn":
			proto := strings.ToLower(strings.TrimSpace(tc.TURN.Protocol))
			if proto == "" || proto == "udp" {
				return st.Endpoint
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

func (e *Engine) meshServerPublicKey() string {
	pub, err := e.wgPublicKey()
	if err != nil {
		return ""
	}
	return wgtypes.Key(pub).String()
}

func (e *Engine) meshPeerConfig(publicKey string) (config.Peer, int, bool) {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	for i, peer := range e.cfg.WireGuard.Peers {
		if peer.PublicKey == publicKey {
			return peer, i, true
		}
	}
	return config.Peer{}, -1, false
}

func (e *Engine) dynamicPeer(publicKey string) *dynamicPeer {
	e.dynamicMu.RLock()
	defer e.dynamicMu.RUnlock()
	return e.dynamicPeers[publicKey]
}

func (e *Engine) meshStaticPeers() []config.Peer {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
}

func (e *Engine) startMeshPolling() {
	peers := e.meshStaticPeers()
	enabled := false
	for _, peer := range peers {
		if peer.MeshEnabled && peer.MeshAcceptACLs && peer.ControlURL != "" {
			enabled = true
			break
		}
	}
	if !enabled {
		return
	}
	go e.meshPollingLoop()
}

func (e *Engine) meshPollingLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			e.runMeshPolling()
		}
	}
}

func (e *Engine) runMeshPolling() {
	peers := e.meshStaticPeers()
	for _, parent := range peers {
		if !parent.MeshEnabled || !parent.MeshAcceptACLs || parent.ControlURL == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		client, err := e.newMeshControlClient(ctx, parent)
		if err == nil {
			local := e.meshSourceAddr()
			if local.IsValid() {
				remote := netip.AddrPortFrom(local, 0)
				var peers []meshDiscoveredPeer
				peers, err = client.fetchPeers(ctx, remote)
				if err == nil {
					err = e.applyMeshDiscoveredPeers(parent, peers)
				}
				if err == nil {
					var aclResp meshACLResponse
					aclResp, err = client.fetchACLs(ctx, remote)
					if err == nil {
						err = e.applyMeshACLsWithDefault(parent.PublicKey, aclResp.Default, aclResp.Inbound, aclResp.Outbound)
					}
				}
			} else {
				err = errors.New("no local WireGuard address for mesh control")
			}
		}
		cancel()
		if err != nil {
			e.log.Printf("mesh control poll for %s failed: %v", parent.PublicKey, err)
		}
	}
	e.refreshDynamicPeerActivity()
}

func (e *Engine) meshSourceAddr() netip.Addr {
	for _, addr := range e.localAddrs {
		if addr.IsValid() {
			return addr
		}
	}
	return netip.Addr{}
}

func (e *Engine) applyMeshDiscoveredPeers(parent config.Peer, discovered []meshDiscoveredPeer) error {
	now := time.Now()
	parentPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{parent})
	if err != nil {
		return err
	}
	static := e.meshStaticPeers()
	staticKeys := make(map[string]struct{}, len(static))
	for _, peer := range static {
		staticKeys[peer.PublicKey] = struct{}{}
	}
	type update struct {
		key  string
		peer config.Peer
	}
	type candidate struct {
		key  string
		peer config.Peer
	}
	candidateIndex := make(map[string]int, len(discovered))
	candidates := make([]candidate, 0, len(discovered))
	for _, disc := range discovered {
		if disc.PublicKey == parent.PublicKey {
			continue
		}
		if _, ok := staticKeys[disc.PublicKey]; ok {
			continue
		}
		allowed := meshTrimAllowedIPs(disc.AllowedIPs, parentPrefixes)
		if len(allowed) == 0 {
			continue
		}
		trust := config.MeshTrust(disc.MeshTrust)
		switch trust {
		case "", config.MeshTrustUntrusted:
			trust = config.MeshTrustUntrusted
		case config.MeshTrustTrustedAlways, config.MeshTrustTrustedIfDynamicACLs:
		default:
			trust = config.MeshTrustUntrusted
		}
		peer := config.Peer{
			PublicKey:           disc.PublicKey,
			PresharedKey:        disc.PSK,
			Endpoint:            disc.Endpoint,
			AllowedIPs:          allowed,
			PersistentKeepalive: meshDynamicKeepalive(parent),
			MeshAcceptACLs:      disc.MeshAccept,
			MeshTrust:           trust,
		}
		if idx, ok := candidateIndex[disc.PublicKey]; ok {
			candidates[idx].peer = peer
			continue
		}
		candidateIndex[disc.PublicKey] = len(candidates)
		candidates = append(candidates, candidate{key: disc.PublicKey, peer: peer})
	}
	var upserts []update
	var removals []string

	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		if dp.ParentPublicKey == parent.PublicKey {
			if _, ok := candidateIndex[key]; !ok {
				removals = append(removals, key)
				delete(e.dynamicPeers, key)
			}
		}
	}
	for _, cand := range candidates {
		dp, exists := e.dynamicPeers[cand.key]
		if exists && dp.ParentPublicKey != parent.PublicKey {
			continue
		}
		if !exists && len(e.dynamicPeers) >= meshDynamicPeerLimit {
			continue
		}
		peer := cand.peer
		if exists && dp.Active && dp.Peer.Endpoint != "" {
			peer.Endpoint = dp.Peer.Endpoint
		}
		if !exists {
			dp = &dynamicPeer{ParentPublicKey: parent.PublicKey}
			e.dynamicPeers[cand.key] = dp
		}
		dp.Peer = peer
		dp.LastControl = now
		upserts = append(upserts, update{key: cand.key, peer: peer})
	}
	e.dynamicMu.Unlock()

	// Re-validate each upsert under the lock before pushing to
	// wireguard-go. Between the Unlock above and these IpcSets, a
	// concurrent runtime-API mutation (e.g. SetWireGuardConfig →
	// reconcileDynamicPeersWithStatic) could have deleted entries
	// from dynamicPeers. Without this re-check, we'd push a peer
	// to WG-go that no longer exists in our model, leaving the
	// device + map state desynchronised. M6 race-tier-2 finding.
	for _, up := range upserts {
		e.dynamicMu.RLock()
		_, stillTracked := e.dynamicPeers[up.key]
		e.dynamicMu.RUnlock()
		if !stillTracked {
			continue
		}
		if err := e.upsertDynamicPeerDevice(up.peer); err != nil {
			return err
		}
	}
	for _, key := range removals {
		if err := e.removeDynamicPeerDevice(key); err != nil {
			return err
		}
	}
	return e.reconcileDynamicPeerPriority()
}

func meshDynamicKeepalive(parent config.Peer) int {
	if parent.PersistentKeepalive > 0 {
		return parent.PersistentKeepalive
	}
	return 15
}

func meshTrimAllowedIPs(raw []string, parents []netip.Prefix) []string {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		for _, parent := range parents {
			if parent.Addr().BitLen() != prefix.Addr().BitLen() {
				continue
			}
			if parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr()) {
				out = append(out, prefix.String())
				break
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func meshProjectRelayRuleForDestination(rule acl.Rule, allowed []netip.Prefix) (acl.Rule, bool) {
	projected := rule
	projectedDsts := meshProjectDestinations(rule.Destination, rule.Destinations, allowed)
	if len(projectedDsts) == 0 {
		return acl.Rule{}, false
	}
	projected.Destination = ""
	projected.Destinations = projectedDsts
	if err := projected.Normalize(); err != nil {
		return acl.Rule{}, false
	}
	return projected, true
}

func meshProjectRelayRuleForSource(rule acl.Rule, allowed []netip.Prefix) (acl.Rule, bool) {
	projected := rule
	projectedSrcs := meshProjectDestinations(rule.Source, rule.Sources, allowed)
	if len(projectedSrcs) == 0 {
		return acl.Rule{}, false
	}
	projected.Source = ""
	projected.Sources = projectedSrcs
	if err := projected.Normalize(); err != nil {
		return acl.Rule{}, false
	}
	return projected, true
}

func meshProjectDestinations(single string, many []string, allowed []netip.Prefix) []string {
	raws := make([]string, 0, 1+len(many))
	if single != "" {
		raws = append(raws, single)
	}
	raws = append(raws, many...)
	if len(raws) == 0 {
		for _, prefix := range allowed {
			raws = append(raws, prefix.Masked().String())
		}
	}
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		if raw == "" {
			continue
		}
		prefix, ok := meshParseCIDROrAddr(raw)
		if !ok {
			continue
		}
		prefix = prefix.Masked()
		for _, allow := range allowed {
			allow = allow.Masked()
			projected, ok := meshPrefixIntersection(prefix, allow)
			if ok {
				out = append(out, projected.String())
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func meshAnyPrefixIntersects(prefix netip.Prefix, allowed []netip.Prefix) bool {
	for _, want := range allowed {
		if prefix.Addr().BitLen() != want.Addr().BitLen() {
			continue
		}
		if prefix.Bits() <= want.Bits() && prefix.Contains(want.Addr()) {
			return true
		}
		if want.Bits() <= prefix.Bits() && want.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func meshPrefixIntersection(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return netip.Prefix{}, false
	}
	a = a.Masked()
	b = b.Masked()
	if a.Bits() <= b.Bits() && a.Contains(b.Addr()) {
		return b, true
	}
	if b.Bits() <= a.Bits() && b.Contains(a.Addr()) {
		return a, true
	}
	return netip.Prefix{}, false
}

func meshParseCIDROrAddr(raw string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), true
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(ip.Unmap(), bits), true
	}
	return netip.Prefix{}, false
}

func (e *Engine) upsertDynamicPeerDevice(peer config.Peer) error {
	if e.dev == nil {
		return nil
	}
	uapi, err := peerUAPI(peer, false, nil, "")
	if err != nil {
		return err
	}
	return e.dev.IpcSet(uapi)
}

func (e *Engine) removeDynamicPeerDevice(publicKey string) error {
	if e.dev == nil {
		return nil
	}
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return e.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", base64ToHex(key[:])))
}

func base64ToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func (e *Engine) reconcileDynamicPeerPriority() error {
	if e.dev == nil {
		return e.applyPeerTrafficState(e.meshStaticPeers())
	}
	static := e.meshStaticPeers()
	type orderedDynamic struct {
		parentIndex int
		peer        config.Peer
	}
	var active []orderedDynamic
	e.dynamicMu.RLock()
	for _, dp := range e.dynamicPeers {
		if dp == nil || !dp.Active {
			continue
		}
		active = append(active, orderedDynamic{
			parentIndex: e.meshStaticPeerIndex(dp.ParentPublicKey, static),
			peer:        dp.Peer,
		})
	}
	e.dynamicMu.RUnlock()
	sort.Slice(active, func(i, j int) bool {
		if active[i].parentIndex == active[j].parentIndex {
			return active[i].peer.PublicKey < active[j].peer.PublicKey
		}
		return active[i].parentIndex < active[j].parentIndex
	})
	e.cfgMu.RLock()
	transports := append([]transport.Config(nil), e.cfg.Transports...)
	defaultTransport := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	e.cfgMu.RUnlock()
	for _, parent := range static {
		hasChild := false
		e.dynamicMu.RLock()
		for _, dp := range e.dynamicPeers {
			if dp != nil && dp.ParentPublicKey == parent.PublicKey {
				hasChild = true
				break
			}
		}
		e.dynamicMu.RUnlock()
		if !hasChild {
			continue
		}
		uapi, err := peerUAPI(parent, false, transports, defaultTransport)
		if err != nil {
			return err
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	for _, item := range active {
		uapi, err := peerUAPI(item.peer, false, nil, "")
		if err != nil {
			return err
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	return e.applyPeerTrafficState(static)
}

func (e *Engine) meshStaticPeerIndex(publicKey string, peers []config.Peer) int {
	for i, peer := range peers {
		if peer.PublicKey == publicKey {
			return i
		}
	}
	return len(peers)
}

func (e *Engine) refreshDynamicPeerActivity() {
	status, err := e.Status()
	if err != nil {
		return
	}
	window := time.Duration(e.cfg.MeshControl.ActivePeerWindowSeconds) * time.Second
	if window <= 0 {
		window = 120 * time.Second
	}
	now := time.Now()
	byKey := make(map[string]PeerStatus, len(status.Peers))
	for _, st := range status.Peers {
		byKey[st.PublicKey] = st
	}
	changed := false
	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		st, ok := byKey[key]
		active := ok && st.HasHandshake && now.Sub(time.Unix(st.LastHandshakeTimeSec, st.LastHandshakeTimeNsec)) <= window
		if dp.Active != active {
			dp.Active = active
			changed = true
		}
	}
	e.dynamicMu.Unlock()
	if changed {
		_ = e.reconcileDynamicPeerPriority()
	}
}

func (e *Engine) reconcileDynamicPeersWithStatic() {
	static := e.meshStaticPeers()
	staticKeys := make(map[string]struct{}, len(static))
	staticParents := make(map[string]config.Peer, len(static))
	for _, peer := range static {
		staticKeys[peer.PublicKey] = struct{}{}
		staticParents[peer.PublicKey] = peer
	}
	var removals []string
	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		if _, clash := staticKeys[key]; clash {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		parent, ok := staticParents[dp.ParentPublicKey]
		if !ok {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		if !parent.MeshAcceptACLs {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		parentPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{parent})
		if err != nil {
			continue
		}
		dp.Peer.AllowedIPs = meshTrimAllowedIPs(dp.Peer.AllowedIPs, parentPrefixes)
		if len(dp.Peer.AllowedIPs) == 0 {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
		}
	}
	e.dynamicMu.Unlock()
	for _, key := range removals {
		_ = e.removeDynamicPeerDevice(key)
	}
	_ = e.reconcileDynamicPeerPriority()
}

func (e *Engine) applyMeshACLs(parentPublicKey string, rules []acl.Rule) error {
	return e.applyMeshACLsWithDefault(parentPublicKey, acl.Deny, rules, nil)
}

func (e *Engine) applyMeshACLsWithDefault(parentPublicKey string, def acl.Action, inboundRules, outboundRules []acl.Rule) error {
	inList := acl.List{Default: def, Rules: append([]acl.Rule(nil), inboundRules...)}
	if err := inList.Normalize(); err != nil {
		return err
	}
	outList := acl.List{Default: def, Rules: append([]acl.Rule(nil), outboundRules...)}
	if err := outList.Normalize(); err != nil {
		return err
	}
	e.meshACLMu.Lock()
	if e.meshACLsIn == nil {
		e.meshACLsIn = make(map[string]acl.List)
	}
	if e.meshACLsOut == nil {
		e.meshACLsOut = make(map[string]acl.List)
	}
	if e.meshACLFlows == nil {
		e.meshACLFlows = make(map[string]map[relayFlowKey]*relayFlow)
	}
	if e.meshACLLastSweep == nil {
		e.meshACLLastSweep = make(map[string]time.Time)
	}
	e.meshACLsIn[parentPublicKey] = inList
	e.meshACLsOut[parentPublicKey] = outList
	if _, ok := e.meshACLFlows[parentPublicKey]; !ok {
		e.meshACLFlows[parentPublicKey] = make(map[relayFlowKey]*relayFlow)
	}
	e.meshACLMu.Unlock()
	return nil
}

func (e *Engine) meshInboundACLAllowed(meta relayPacketMeta) bool {
	parent, rules, _, _, ok := e.meshACLListsForPeerIP(meta.src.Addr())
	if !ok {
		return true
	}
	return e.allowMeshACLTracked(parent, rules, meta, time.Now())
}

func (e *Engine) meshAllowLocalACL(meta relayPacketMeta) bool {
	if !e.localAddrContains(meta.src.Addr()) {
		return true
	}
	parent, _, rules, peer, ok := e.meshACLListsForPeerIP(meta.dst.Addr())
	if !ok {
		return true
	}
	switch peer.MeshTrust {
	case config.MeshTrustTrustedAlways, config.MeshTrustTrustedIfDynamicACLs:
		return e.allowMeshACLTracked(parent, rules, meta, time.Now())
	default:
		return true
	}
}

func (e *Engine) meshTrackLocalACL(meta relayPacketMeta) {
	if !e.localAddrContains(meta.src.Addr()) {
		return
	}
	parent, _, rules, _, ok := e.meshACLListsForPeerIP(meta.dst.Addr())
	if !ok {
		return
	}
	e.trackMeshACLOutbound(parent, rules, meta, time.Now())
}

func (e *Engine) meshACLListsForPeerIP(ip netip.Addr) (string, acl.List, acl.List, config.Peer, bool) {
	ip = ip.Unmap()
	bestParent := ""
	bestBits := -1
	bestPeer := config.Peer{}
	e.dynamicMu.RLock()
	for _, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		for _, raw := range dp.Peer.AllowedIPs {
			prefix, ok := meshParseCIDROrAddr(raw)
			if !ok {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Contains(ip) && prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
				bestParent = dp.ParentPublicKey
				bestPeer = dp.Peer
			}
		}
	}
	e.dynamicMu.RUnlock()
	if bestParent == "" {
		e.cfgMu.RLock()
		for _, peer := range e.cfg.WireGuard.Peers {
			if !peer.MeshAcceptACLs && peer.MeshTrust == config.MeshTrustUntrusted {
				continue
			}
			for _, raw := range peer.AllowedIPs {
				prefix, ok := meshParseCIDROrAddr(raw)
				if !ok {
					continue
				}
				prefix = prefix.Masked()
				if prefix.Contains(ip) && prefix.Bits() > bestBits {
					bestBits = prefix.Bits()
					bestParent = peer.PublicKey
					bestPeer = peer
				}
			}
		}
		e.cfgMu.RUnlock()
	}
	if bestParent == "" {
		return "", acl.List{}, acl.List{}, config.Peer{}, false
	}
	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	inList, ok := e.meshACLsIn[bestParent]
	if !ok {
		return "", acl.List{}, acl.List{}, config.Peer{}, false
	}
	outList := e.meshACLsOut[bestParent]
	return bestParent, inList, outList, bestPeer, true
}

func (e *Engine) allowMeshACLTracked(parent string, rules acl.List, meta relayPacketMeta, now time.Time) bool {
	if meta.icmpErr {
		e.meshACLMu.Lock()
		defer e.meshACLMu.Unlock()
		e.ensureMeshACLFlowsLocked(parent)
		e.meshACLSweepLocked(parent, now)
		return e.allowMeshACLICMPErrorLocked(parent, meta, now)
	}
	if !relayTrackable(meta) {
		return rules.Allowed(meta.src, meta.dst, meta.network)
	}

	e.meshACLMu.Lock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		allowed := e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
		e.meshACLMu.Unlock()
		return allowed
	}
	e.meshACLMu.Unlock()

	if !rules.Allowed(meta.src, meta.dst, meta.network) {
		return false
	}
	if !relayCanOpenFlow(meta) {
		return false
	}

	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		return e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
	}
	e.meshACLFlows[parent][relayForwardKey(meta)] = newRelayFlow(meta, now)
	return true
}

func (e *Engine) trackMeshACLOutbound(parent string, rules acl.List, meta relayPacketMeta, now time.Time) {
	if meta.icmpErr {
		return
	}
	if !relayTrackable(meta) {
		return
	}
	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		_ = e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
		return
	}
	if !rules.Allowed(meta.src, meta.dst, meta.network) || !relayCanOpenFlow(meta) {
		return
	}
	e.meshACLFlows[parent][relayForwardKey(meta)] = newRelayFlow(meta, now)
}

func (e *Engine) ensureMeshACLFlowsLocked(parent string) {
	if _, ok := e.meshACLFlows[parent]; !ok {
		e.meshACLFlows[parent] = make(map[relayFlowKey]*relayFlow)
	}
}

func (e *Engine) meshACLSweepLocked(parent string, now time.Time) {
	flows := e.meshACLFlows[parent]
	if len(flows) == 0 {
		return
	}
	last := e.meshACLLastSweep[parent]
	if !last.IsZero() && now.Sub(last) < time.Second {
		return
	}
	e.meshACLLastSweep[parent] = now
	for key, flow := range flows {
		if relayFlowExpired(flow, now, e.tcpIdleTimeout(), e.udpIdleTimeout()) {
			delete(flows, key)
		}
	}
}

func (e *Engine) meshACLFindFlowLocked(parent string, meta relayPacketMeta) (*relayFlow, bool, bool) {
	flows := e.meshACLFlows[parent]
	if flow, ok := flows[relayForwardKey(meta)]; ok {
		return flow, true, true
	}
	if flow, ok := flows[relayReverseKey(meta)]; ok {
		return flow, false, true
	}
	return nil, false, false
}

func (e *Engine) allowExistingMeshACLFlowLocked(parent string, flow *relayFlow, forward bool, meta relayPacketMeta, now time.Time) bool {
	flows := e.meshACLFlows[parent]
	switch flow.state {
	case relayFlowUDP:
		flow.last = now
		return true
	case relayFlowICMP:
		if forward && relayICMPEchoRequest(meta) || !forward && relayICMPEchoReply(meta) {
			flow.last = now
			return true
		}
		return false
	case relayTCPSynSent:
		if forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK == 0 {
			flow.last = now
			return true
		}
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.state = relayTCPSynRecv
			flow.last = now
			return true
		}
		return false
	case relayTCPSynRecv:
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.last = now
			return true
		}
		if forward && meta.tcpFlags&tcpFlagACK != 0 && meta.tcpFlags&tcpFlagSYN == 0 {
			flow.state = relayTCPEstablished
			flow.last = now
			e.updateRelayTCPClosingLocked(flow, forward, meta)
			return true
		}
		return false
	case relayTCPEstablished, relayTCPFinWait, relayTCPTimeWait:
		flow.last = now
		if meta.tcpFlags&tcpFlagRST != 0 {
			delete(flows, flow.key)
			return true
		}
		e.updateRelayTCPClosingLocked(flow, forward, meta)
		return true
	default:
		return false
	}
}

func (e *Engine) allowMeshACLICMPErrorLocked(parent string, meta relayPacketMeta, now time.Time) bool {
	if meta.inner == nil {
		return false
	}
	flow, _, ok := e.meshACLFindFlowLocked(parent, *meta.inner)
	if !ok {
		return false
	}
	if meta.dst.Addr() != flow.key.InitIP && meta.dst.Addr() != flow.key.RespIP {
		return false
	}
	flow.last = now
	return true
}

func (e *Engine) meshPairPSK(a, b string) ([]byte, error) {
	pa, _, ok := e.meshPeerConfig(a)
	if !ok {
		return nil, fmt.Errorf("mesh peer %s not found", a)
	}
	pb, _, ok := e.meshPeerConfig(b)
	if !ok {
		return nil, fmt.Errorf("mesh peer %s not found", b)
	}
	pairs := []struct {
		pub string
		psk []byte
	}{
		{pub: pa.PublicKey, psk: meshPeerPSKBytes(pa)},
		{pub: pb.PublicKey, psk: meshPeerPSKBytes(pb)},
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].pub < pairs[j].pub })
	mac := hmac.New(sha256.New, e.meshMasterKey[:])
	_, _ = mac.Write(pairs[0].psk)
	_, _ = mac.Write(pairs[1].psk)
	_, _ = mac.Write(mustParseWGKeyBytes(pairs[0].pub))
	_, _ = mac.Write(mustParseWGKeyBytes(pairs[1].pub))
	return mac.Sum(nil), nil
}

func meshPeerPSKBytes(peer config.Peer) []byte {
	if peer.PresharedKey == "" {
		return make([]byte, 32)
	}
	key, err := wgtypes.ParseKey(peer.PresharedKey)
	if err != nil {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	copy(out, key[:])
	return out
}

func meshQuickCheck(serverPub, challengePub, addrBinding []byte) []byte {
	mac := hmac.New(sha256.New, serverPub)
	_, _ = mac.Write(challengePub)
	_, _ = mac.Write(addrBinding)
	return mac.Sum(nil)
}

func meshAuthKey(ephemeralShared, staticShared []byte) []byte {
	mac := hmac.New(sha256.New, ephemeralShared)
	_, _ = mac.Write([]byte("server-static"))
	_, _ = mac.Write(staticShared)
	return mac.Sum(nil)
}

func meshSharedSecret(k1, k2, psk, addrBinding []byte) []byte {
	inner := hmac.New(sha256.New, k1)
	_, _ = inner.Write(psk)
	mac := hmac.New(sha256.New, inner.Sum(nil))
	_, _ = mac.Write(k2)
	_, _ = mac.Write(addrBinding)
	return mac.Sum(nil)
}

func meshSealDeterministic(plain, secret []byte, label string) ([]byte, error) {
	key, nonce := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	out = aead.Seal(out, nonce, plain, nil)
	return out, nil
}

func meshSealRandom(plain, secret []byte, label string) ([]byte, error) {
	key, _ := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	out = aead.Seal(out, nonce, plain, nil)
	return out, nil
}

func meshOpen(sealed, secret []byte, label string) ([]byte, error) {
	key, _ := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("short sealed mesh payload")
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	return aead.Open(nil, nonce, sealed[chacha20poly1305.NonceSizeX:], nil)
}

func meshKeyNonce(secret []byte, label string) ([]byte, []byte) {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(label))
	sum := mac.Sum(nil)
	key := append([]byte(nil), sum...)
	mac = hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("nonce:" + label))
	nonce := mac.Sum(nil)[:chacha20poly1305.NonceSizeX]
	return key, append([]byte(nil), nonce...)
}

func meshAddrBindingFromRemote(remote string) ([]byte, error) {
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		ap, apErr := netip.ParseAddrPort(remote)
		if apErr == nil {
			ip = ap.Addr()
		} else {
			host, _, splitErr := net.SplitHostPort(remote)
			if splitErr != nil {
				return nil, fmt.Errorf("mesh remote addr: %w", err)
			}
			ip, err = netip.ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("mesh remote addr: %w", err)
			}
		}
	}
	ip = ip.Unmap()
	if !ip.IsValid() {
		return nil, errors.New("invalid mesh remote address")
	}
	var ip16 [16]byte
	if ip.Is4() {
		ip16[10], ip16[11] = 0xff, 0xff
		copy(ip16[12:], ip.AsSlice())
	} else {
		ip16 = ip.As16()
	}
	out := make([]byte, 16)
	copy(out, ip16[:])
	return out, nil
}

func mustResolveTCPAddr(remote string) net.Addr {
	ap, err := netip.ParseAddrPort(remote)
	if err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return dummyAddr(remote)
}

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

func mustParseWGKeyBytes(key string) []byte {
	parsed, err := wgtypes.ParseKey(key)
	if err != nil {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	copy(out, parsed[:])
	return out
}

type meshControlClient struct {
	controlURL *url.URL
	httpClient *http.Client
	peer       config.Peer
	privateKey wgtypes.Key
}

// testMeshDialContextOverride lets tests inject a lossy / throttled / etc.
// dialer in place of the regular tunnel dial. nil in production. Set via
// SetMeshDialContextOverride from a *_test.go file in this package.
var testMeshDialContextOverride func(ctx context.Context, network, addr string) (net.Conn, error)

func (e *Engine) newMeshControlClient(ctx context.Context, peer config.Peer) (*meshControlClient, error) {
	if peer.ControlURL == "" {
		return nil, errors.New("mesh control_url is required")
	}
	u, err := url.Parse(peer.ControlURL)
	if err != nil {
		return nil, err
	}
	key, err := wgtypes.ParseKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &meshControlClient{
		controlURL: u,
		peer:       peer,
		privateKey: key,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if testMeshDialContextOverride != nil {
						return testMeshDialContextOverride(ctx, network, addr)
					}
					return e.DialTunnelContext(ctx, network, addr)
				},
			},
		},
	}, nil
}

func (c *meshControlClient) fetchChallenge(ctx context.Context) (meshChallengeResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/challenge"}).String(), nil)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return meshChallengeResponse{}, fmt.Errorf("mesh challenge status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out meshChallengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, meshChallengeBodyLimit)).Decode(&out); err != nil {
		return meshChallengeResponse{}, err
	}
	return out, nil
}

func (c *meshControlClient) bearerToken(remote netip.AddrPort, challenge meshChallengeResponse) (string, []byte, error) {
	curve := ecdh.X25519()
	challengePubBytes, err := base64.StdEncoding.DecodeString(challenge.ChallengePublicKey)
	if err != nil {
		return "", nil, err
	}
	challengePub, err := curve.NewPublicKey(challengePubBytes)
	if err != nil {
		return "", nil, err
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	k1, err := ephPriv.ECDH(challengePub)
	if err != nil {
		return "", nil, err
	}
	authKey := k1
	wgPriv, err := curve.NewPrivateKey(c.privateKey[:])
	if err != nil {
		return "", nil, err
	}
	k2, err := wgPriv.ECDH(challengePub)
	if err != nil {
		return "", nil, err
	}
	addrBinding, err := meshAddrBindingFromRemote(remote.String())
	if err != nil {
		return "", nil, err
	}
	peerPub := c.privateKey.PublicKey()
	serverPub, err := wgtypes.ParseKey(challenge.ServerPublicKey)
	if err != nil {
		return "", nil, err
	}
	if challenge.TokenVersion >= meshTokenVersionV2 {
		serverStaticPub, err := curve.NewPublicKey(serverPub[:])
		if err != nil {
			return "", nil, err
		}
		staticShared, err := ephPriv.ECDH(serverStaticPub)
		if err != nil {
			return "", nil, err
		}
		authKey = meshAuthKey(k1, staticShared)
	}
	sealed, err := meshSealDeterministic(peerPub[:], authKey, meshAuthContextLabel)
	if err != nil {
		return "", nil, err
	}
	secret := meshSharedSecret(authKey, k2, meshPeerPSKBytes(c.peer), addrBinding)
	x := meshQuickCheck(serverPub[:], challengePubBytes, addrBinding)
	hash := sha256.Sum256(secret)
	token := make([]byte, 0, 1+32+32+len(sealed)+32)
	tokenVersion := byte(meshTokenVersionV1)
	if challenge.TokenVersion >= meshTokenVersionV2 {
		tokenVersion = meshTokenVersionV2
	}
	token = append(token, tokenVersion)
	token = append(token, ephPriv.PublicKey().Bytes()...)
	token = append(token, x...)
	token = append(token, sealed...)
	token = append(token, hash[:]...)
	return base64.RawURLEncoding.EncodeToString(token), secret, nil
}

func (c *meshControlClient) fetchPeers(ctx context.Context, remote netip.AddrPort) ([]meshDiscoveredPeer, error) {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return nil, err
	}
	token, secret, err := c.bearerToken(remote, challenge)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/peers"}).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mesh peers status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	plain, err := meshOpen(sealed, secret, meshBodyContextLabel)
	if err != nil {
		return nil, err
	}
	var out []meshDiscoveredPeer
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *meshControlClient) fetchACLs(ctx context.Context, remote netip.AddrPort) (meshACLResponse, error) {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return meshACLResponse{}, err
	}
	token, secret, err := c.bearerToken(remote, challenge)
	if err != nil {
		return meshACLResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/acls"}).String(), nil)
	if err != nil {
		return meshACLResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return meshACLResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return meshACLResponse{}, fmt.Errorf("mesh acls status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return meshACLResponse{}, err
	}
	plain, err := meshOpen(sealed, secret, meshBodyContextLabel)
	if err != nil {
		return meshACLResponse{}, err
	}
	var out meshACLResponse
	if err := json.Unmarshal(plain, &out); err != nil {
		return meshACLResponse{}, err
	}
	inList := acl.List{Default: out.Default, Rules: out.Inbound}
	if err := inList.Normalize(); err != nil {
		return meshACLResponse{}, err
	}
	outList := acl.List{Default: out.Default, Rules: out.Outbound}
	if err := outList.Normalize(); err != nil {
		return meshACLResponse{}, err
	}
	out.Default = inList.Default
	out.Inbound = inList.Rules
	out.Outbound = outList.Rules
	return out, nil
}
