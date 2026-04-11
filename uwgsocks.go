// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package uwgsocks exposes the userspace WireGuard proxy engine as a library
// for Go applications that want WireGuard transport without creating a kernel
// interface or exposing SOCKS/HTTP listeners.
package uwgsocks

import (
	"log"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
)

type Config = config.Config
type WireGuard = config.WireGuard
type Peer = config.Peer
type Proxy = config.Proxy
type Inbound = config.Inbound
type HostForward = config.HostForward
type HostForwardEndpoint = config.HostForwardEndpoint
type Routing = config.Routing
type Filtering = config.Filtering
type Relay = config.Relay
type API = config.API
type ACL = config.ACL
type Forward = config.Forward
type DNSServer = config.DNSServer
type Scripts = config.Scripts
type Log = config.Log

type ACLAction = acl.Action
type ACLRule = acl.Rule
type ACLList = acl.List

type Status = engine.Status
type PeerStatus = engine.PeerStatus
type PingResult = engine.PingResult
type PingReply = engine.PingReply

const (
	ACLAllow = acl.Allow
	ACLDeny  = acl.Deny
)

type Engine = engine.Engine

func DefaultConfig() Config {
	return config.Default()
}

func LoadConfig(path string) (Config, error) {
	return config.Load(path)
}

func New(cfg Config, logger *log.Logger) (*Engine, error) {
	return engine.New(cfg, logger)
}
