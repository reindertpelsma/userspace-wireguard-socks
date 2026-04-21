// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package transport

import (
	"context"
	"fmt"
)

type TURNTransport struct {
	name string
}

func NewTURNTransport(name string, _ TURNConfig, _ WebSocketConfig, _ ProxyDialer, _ [32]byte) (*TURNTransport, error) {
	return nil, fmt.Errorf("transport %q: TURN is not supported in lite builds", name)
}

func (t *TURNTransport) Name() string { return t.name }

func (t *TURNTransport) IsConnectionOriented() bool { return false }

func (t *TURNTransport) Dial(context.Context, string) (Session, error) {
	return nil, fmt.Errorf("TURN is not supported in lite builds")
}

func (t *TURNTransport) Listen(context.Context, int) (Listener, error) {
	return nil, fmt.Errorf("TURN is not supported in lite builds")
}

func (t *TURNTransport) UpdatePermissions([]string) {}
