// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package config

import (
	"strings"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

const (
	testPrivateKey = "G6u23elV1ehynbk4m5+doY0e6QqWq5npz9jQ7juh6FQ="
	testPublicKey  = "zYx0fLGJHgYwR7sQkVqUQ2+1pnWc5kXJH0F0vTey0G0="
)

func TestNormalizeRejectsLiteUnsupportedFeatures(t *testing.T) {
	t.Run("mesh", func(t *testing.T) {
		cfg := Config{
			WireGuard: WireGuard{
				PrivateKey: testPrivateKey,
				Addresses:  []string{"10.0.0.1/24"},
				Peers: []Peer{{
					PublicKey:   testPublicKey,
					AllowedIPs:  []string{"10.0.0.2/32"},
					ControlURL:  "http://10.0.0.1:8080",
					MeshEnabled: true,
				}},
			},
		}
		if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "lite builds") {
			t.Fatalf("Normalize() error = %v, want lite-build rejection", err)
		}
	})

	t.Run("transports", func(t *testing.T) {
		cfg := Config{
			WireGuard: WireGuard{
				PrivateKey: testPrivateKey,
				Addresses:  []string{"10.0.0.1/24"},
			},
			Transports: []transport.Config{{Name: "web", Base: "https"}},
		}
		if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "lite builds") {
			t.Fatalf("Normalize() error = %v, want lite-build rejection", err)
		}
	})

	t.Run("traffic shaper", func(t *testing.T) {
		cfg := Config{
			WireGuard: WireGuard{
				PrivateKey: testPrivateKey,
				Addresses:  []string{"10.0.0.1/24"},
			},
			TrafficShaper: TrafficShaper{UploadBps: 1024},
		}
		if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "lite builds") {
			t.Fatalf("Normalize() error = %v, want lite-build rejection", err)
		}
	})
}
