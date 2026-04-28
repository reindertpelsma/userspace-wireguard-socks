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
	// Action is what to do when a connection matches this rule.
	// One of `allow` or `deny`. First-match-wins ordering applies
	// across the rule list.
	Action Action `yaml:"action" json:"action"`

	// Source is a single CIDR (or IP) the connection's source must
	// match for this rule to fire. Empty means "any source".
	// Singular form kept for back-compat with single-rule configs;
	// for multiple sources use Sources instead.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// Destination is a single CIDR (or IP) the connection's
	// destination must match. Empty means "any destination".
	// Singular form; for multiple destinations use Destinations.
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	// Sources is the list variant of Source. When non-empty it is
	// used in addition to Source (the two are merged). Lets one
	// rule cover many CIDRs rather than duplicating the rule.
	Sources []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	// Destinations is the list variant of Destination. Same merge
	// semantics as Sources.
	Destinations []string `yaml:"destinations,omitempty" json:"destinations,omitempty"`
	// SourcePort is the source-port match: a single port "53" or
	// a range "1024-65535". Empty means "any port".
	SourcePort string `yaml:"source_port,omitempty" json:"source_port,omitempty"`
	// DestPort is the destination-port match: single port or
	// range. Empty means "any port".
	DestPort string `yaml:"destination_port,omitempty" json:"destination_port,omitempty"`
	// udp | tcp | tls | dtls | http | https | quic
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`

	sourcePrefixes []netip.Prefix
	destPrefixes   []netip.Prefix
	sourcePorts    *PortRange
	destPorts      *PortRange
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

	// Collect all source entries: singular Source + multi Sources list.
	srcEntries := make([]string, 0, 1+len(r.Sources))
	if r.Source != "" {
		srcEntries = append(srcEntries, r.Source)
	}
	srcEntries = append(srcEntries, r.Sources...)
	r.sourcePrefixes = r.sourcePrefixes[:0]
	for _, s := range srcEntries {
		if s == "" {
			continue
		}
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("source %q: %w", s, err)
		}
		r.sourcePrefixes = append(r.sourcePrefixes, p)
	}

	// Collect all destination entries.
	dstEntries := make([]string, 0, 1+len(r.Destinations))
	if r.Destination != "" {
		dstEntries = append(dstEntries, r.Destination)
	}
	dstEntries = append(dstEntries, r.Destinations...)
	r.destPrefixes = r.destPrefixes[:0]
	for _, s := range dstEntries {
		if s == "" {
			continue
		}
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("destination %q: %w", s, err)
		}
		r.destPrefixes = append(r.destPrefixes, p)
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
	if r.Protocol != "" {
		switch p := strings.ToLower(r.Protocol); p {
		case "tcp", "udp", "icmp":
			r.Protocol = p
		default:
			return fmt.Errorf("unknown protocol %q", r.Protocol)
		}
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
func (l List) Allowed(src, dst netip.AddrPort, network string) bool {
	for _, rule := range l.Rules {
		if rule.matches(src, dst, network) {
			return rule.Action == Allow
		}
	}
	return l.Default != Deny
}

func (r Rule) matches(src, dst netip.AddrPort, network string) bool {
	if network != "" && r.Protocol != "" && r.Protocol != network {
		return false
	}
	// Source check: if any prefixes are configured, src must match at least one.
	if len(r.sourcePrefixes) > 0 {
		matched := false
		for _, p := range r.sourcePrefixes {
			if p.Contains(src.Addr()) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// Destination check: if any prefixes are configured, dst must match at least one.
	if len(r.destPrefixes) > 0 {
		matched := false
		for _, p := range r.destPrefixes {
			if p.Contains(dst.Addr()) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
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
		case "protocol":
			switch strings.ToLower(v) {
			case "tcp", "udp", "icmp":
				r.Protocol = strings.ToLower(v)
			case "":
				r.Protocol = ""
			default:
				return Rule{}, fmt.Errorf("unknown ACL rule protocol %v", v)
			}
		default:
			return Rule{}, fmt.Errorf("unknown ACL field %q", k)
		}
	}
	return r, r.Normalize()
}
