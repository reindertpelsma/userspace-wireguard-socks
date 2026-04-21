// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"bytes"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNewTURNTransportIncludesWireGuardPublicKeyWhenConfigured(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.TURN.Server = "127.0.0.1:3478"
	cfg.TURN.Username = "user"
	cfg.TURN.Password = "pass"
	cfg.TURN.IncludeWGPublicKey = true

	turnTransport, err := newTURNTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if turnTransport == nil {
		t.Fatal("expected non-nil TURN transport")
	}
	publicKey := key.PublicKey()
	if turnTransport.RelayAddr() != "" {
		t.Fatal("unexpected allocated relay address before listen")
	}
	got := turnTransport.WGPublicKeyForTest()
	if !bytes.Equal(got[:], publicKey[:]) {
		t.Fatalf("TURN transport public key mismatch")
	}
}
