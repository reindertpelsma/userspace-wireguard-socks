// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNewTURNBindIncludesWireGuardPublicKeyWhenConfigured(t *testing.T) {
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

	bind, err := newTURNBind(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bind.IncludeWGPublicKey {
		t.Fatal("expected IncludeWGPublicKey to be enabled")
	}
	publicKey := key.PublicKey()
	if !bytes.Equal(bind.WGPublicKey[:], publicKey[:]) {
		t.Fatalf("TURN bind public key mismatch")
	}
}
