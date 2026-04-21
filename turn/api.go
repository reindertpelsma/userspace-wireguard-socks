package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type APIConfig struct {
	Listen string `yaml:"listen,omitempty"`
	Token  string `yaml:"token,omitempty"`
}

type turnAPIServer struct {
	ln  net.Listener
	srv *http.Server
}

func (s *turnAPIServer) Addr() net.Addr {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *turnAPIServer) Close() error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var first error
	if s.srv != nil {
		if err := s.srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			first = err
		}
	}
	if s.ln != nil {
		if err := s.ln.Close(); err != nil && !isIgnorableCloseErr(err) && first == nil {
			first = err
		}
	}
	return first
}

type apiListenerSnapshot struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

type apiSessionSnapshot struct {
	Username      string `json:"username"`
	AuthUsername  string `json:"auth_username,omitempty"`
	ClientAddr    string `json:"client_addr"`
	RelayAddr     string `json:"relay_addr"`
	RequestedPort int    `json:"requested_port,omitempty"`
	AllocatedPort int    `json:"allocated_port,omitempty"`
	OutboundOnly  bool   `json:"outbound_only,omitempty"`
	InternalOnly  bool   `json:"internal_only,omitempty"`
}

type apiStatusSnapshot struct {
	Realm           string                `json:"realm"`
	MaxSessions     int                   `json:"max_sessions"`
	Users           int                   `json:"users"`
	PortRanges      int                   `json:"port_ranges"`
	GlobalSessions  int64                 `json:"global_sessions"`
	InternalPackets int64                 `json:"internal_packets"`
	ExternalPackets int64                 `json:"external_packets"`
	Listeners       []apiListenerSnapshot `json:"listeners"`
	Sessions        []apiSessionSnapshot  `json:"sessions"`
}

func (o *openRelayPion) statusSnapshot() apiStatusSnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()

	listeners := make([]apiListenerSnapshot, 0, len(o.boundListeners))
	for _, listener := range o.boundListeners {
		listeners = append(listeners, apiListenerSnapshot{
			Type: listener.Type,
			Addr: listener.Addr.String(),
		})
	}

	sessions := make([]apiSessionSnapshot, 0, len(o.activeRelays))
	for relayAddr, relay := range o.activeRelays {
		if relay == nil || relay.reservation == nil {
			continue
		}
		sessions = append(sessions, apiSessionSnapshot{
			Username:      relay.reservation.Username,
			AuthUsername:  relay.reservation.AuthUsername,
			ClientAddr:    relay.reservation.ClientAddr,
			RelayAddr:     relayAddr,
			RequestedPort: relay.reservation.RequestedPort,
			AllocatedPort: relay.reservation.AllocatedPort,
			OutboundOnly:  relay.reservation.OutboundOnly,
			InternalOnly:  relay.reservation.InternalOnly,
		})
	}

	return apiStatusSnapshot{
		Realm:           o.cfg.Realm,
		MaxSessions:     o.cfg.MaxSessions,
		Users:           len(o.cfg.Users),
		PortRanges:      len(o.cfg.PortRanges),
		GlobalSessions:  atomic.LoadInt64(&o.globalSessions),
		InternalPackets: atomic.LoadInt64(&o.internalPackets),
		ExternalPackets: atomic.LoadInt64(&o.externalPackets),
		Listeners:       listeners,
		Sessions:        sessions,
	}
}

func startAPIServer(cfg APIConfig, relay *openRelayPion) (*turnAPIServer, error) {
	listen := strings.TrimSpace(cfg.Listen)
	if listen == "" {
		return nil, nil
	}

	var (
		ln  net.Listener
		err error
	)
	if strings.HasPrefix(listen, "unix://") {
		path := strings.TrimPrefix(listen, "unix://")
		_ = os.Remove(path)
		ln, err = net.Listen("unix", path)
	} else {
		ln, err = net.Listen("tcp", listen)
	}
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, relay.statusSnapshot())
	})
	mux.HandleFunc("GET /v1/users", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, relay.usersSnapshot())
	})
	mux.HandleFunc("PUT /v1/users", func(w http.ResponseWriter, r *http.Request) {
		var users []UserConfig
		if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := relay.replaceAuthState(users, relay.portRangesSnapshot()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, relay.usersSnapshot())
	})
	mux.HandleFunc("POST /v1/users", func(w http.ResponseWriter, r *http.Request) {
		var user UserConfig
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(user.Username) == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		if err := relay.upsertUser(user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, user)
	})
	mux.HandleFunc("DELETE /v1/users", func(w http.ResponseWriter, r *http.Request) {
		username := strings.TrimSpace(r.URL.Query().Get("username"))
		if username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		if err := relay.deleteUser(username); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/port-ranges", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, relay.portRangesSnapshot())
	})
	mux.HandleFunc("PUT /v1/port-ranges", func(w http.ResponseWriter, r *http.Request) {
		var ranges []RangeConfig
		if err := json.NewDecoder(r.Body).Decode(&ranges); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := relay.replaceAuthState(relay.usersSnapshot(), ranges); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, relay.portRangesSnapshot())
	})
	mux.HandleFunc("POST /v1/port-ranges", func(w http.ResponseWriter, r *http.Request) {
		var rng RangeConfig
		if err := json.NewDecoder(r.Body).Decode(&rng); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := relay.upsertPortRange(rng); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, rng)
	})
	mux.HandleFunc("DELETE /v1/port-ranges", func(w http.ResponseWriter, r *http.Request) {
		start, err1 := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("start")))
		end, err2 := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("end")))
		if err1 != nil || err2 != nil {
			http.Error(w, "start and end are required", http.StatusBadRequest)
			return
		}
		if err := relay.deletePortRange(start, end); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	handler := http.Handler(mux)
	if token := strings.TrimSpace(cfg.Token); token != "" {
		handler = requireBearerToken(token, handler)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() { _ = server.Serve(ln) }()
	return &turnAPIServer{ln: ln, srv: server}, nil
}

func requireBearerToken(token string, next http.Handler) http.Handler {
	want := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Bearer realm="turn"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
