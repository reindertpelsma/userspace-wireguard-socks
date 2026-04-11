// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package acl implements the small ordered allow/deny rule language shared by
// inbound transparent proxying, outbound proxying, and relay forwarding.
package acl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type PortRange struct {
	From uint16 `yaml:"from" json:"from"`
	To   uint16 `yaml:"to" json:"to"`
}

func (r PortRange) Contains(port uint16) bool {
	return port >= r.From && port <= r.To
}

type Rule struct {
	Action Action `yaml:"action" json:"action"`

	// The string fields are kept so YAML/JSON/API users see the same compact
	// representation they configured. Normalize parses them into the private
	// fields below for fast per-connection checks.
	Source      string `yaml:"source" json:"source"`
	Destination string `yaml:"destination" json:"destination"`
	SourcePort  string `yaml:"source_port" json:"source_port"`
	DestPort    string `yaml:"destination_port" json:"destination_port"`

	sourcePrefix *netip.Prefix
	destPrefix   *netip.Prefix
	sourcePorts  *PortRange
	destPorts    *PortRange
}

type List struct {
	Default Action `yaml:"default" json:"default"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

func DefaultAllow() List {
	return List{Default: Allow}
}

func (l *List) Normalize() error {
	if l.Default == "" {
		l.Default = Allow
	}
	if l.Default != Allow && l.Default != Deny {
		return fmt.Errorf("invalid ACL default %q", l.Default)
	}
	for i := range l.Rules {
		if err := l.Rules[i].Normalize(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

// Normalize validates a rule and caches parsed prefixes/ranges. Callers should
// normalize once when loading config or API updates, not for every packet.
func (r *Rule) Normalize() error {
	if r.Action == "" {
		r.Action = Allow
	}
	if r.Action != Allow && r.Action != Deny {
		return fmt.Errorf("invalid action %q", r.Action)
	}
	if r.Source != "" {
		p, err := parsePrefix(r.Source)
		if err != nil {
			return fmt.Errorf("source: %w", err)
		}
		r.sourcePrefix = &p
	}
	if r.Destination != "" {
		p, err := parsePrefix(r.Destination)
		if err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		r.destPrefix = &p
	}
	if r.SourcePort != "" {
		p, err := ParsePortRange(r.SourcePort)
		if err != nil {
			return fmt.Errorf("source_port: %w", err)
		}
		r.sourcePorts = &p
	}
	if r.DestPort != "" {
		p, err := ParsePortRange(r.DestPort)
		if err != nil {
			return fmt.Errorf("destination_port: %w", err)
		}
		r.destPorts = &p
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return PortRange{From: 0, To: 65535}, nil
	}
	parse := func(part string) (uint16, error) {
		part = strings.TrimSpace(part)
		n, err := strconv.ParseUint(part, 10, 16)
		return uint16(n), err
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		from, err := parse(parts[0])
		if err != nil {
			return PortRange{}, err
		}
		to, err := parse(parts[1])
		if err != nil {
			return PortRange{}, err
		}
		if to < from {
			return PortRange{}, fmt.Errorf("invalid range %q", s)
		}
		return PortRange{From: from, To: to}, nil
	}
	port, err := parse(s)
	if err != nil {
		return PortRange{}, err
	}
	return PortRange{From: port, To: port}, nil
}

// Allowed evaluates rules in order. The first match wins; if nothing matches
// the list-level default is used.
func (l List) Allowed(src, dst netip.AddrPort) bool {
	for _, rule := range l.Rules {
		if rule.matches(src, dst) {
			return rule.Action == Allow
		}
	}
	return l.Default != Deny
}

func (r Rule) matches(src, dst netip.AddrPort) bool {
	if r.sourcePrefix != nil && !r.sourcePrefix.Contains(src.Addr()) {
		return false
	}
	if r.destPrefix != nil && !r.destPrefix.Contains(dst.Addr()) {
		return false
	}
	if r.sourcePorts != nil && !r.sourcePorts.Contains(src.Port()) {
		return false
	}
	if r.destPorts != nil && !r.destPorts.Contains(dst.Port()) {
		return false
	}
	return true
}

// ParseRule parses the CLI-friendly ACL syntax:
// "allow src=10.0.0.0/24 dst=100.64.0.0/10 dport=80-443".
func ParseRule(s string) (Rule, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return Rule{}, fmt.Errorf("empty ACL rule")
	}
	r := Rule{Action: Action(strings.ToLower(fields[0]))}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return Rule{}, fmt.Errorf("expected key=value in %q", f)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "src", "source":
			r.Source = v
		case "dst", "dest", "destination":
			r.Destination = v
		case "sport", "source_port":
			r.SourcePort = v
		case "dport", "dest_port", "destination_port":
			r.DestPort = v
		default:
			return Rule{}, fmt.Errorf("unknown ACL field %q", k)
		}
	}
	return r, r.Normalize()
}
