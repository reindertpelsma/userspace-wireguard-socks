// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package acl

import (
	"net/netip"
	"strings"
	"testing"
)

// ---------------------------------------------------------------
// PortRange.Contains
// ---------------------------------------------------------------

func TestPortRange_Contains(t *testing.T) {
	r := PortRange{From: 80, To: 443}
	cases := []struct {
		port uint16
		want bool
	}{
		{0, false},
		{79, false},
		{80, true},
		{200, true},
		{443, true},
		{444, false},
		{65535, false},
	}
	for _, c := range cases {
		if got := r.Contains(c.port); got != c.want {
			t.Errorf("Contains(%d) on %v = %v; want %v", c.port, r, got, c.want)
		}
	}
}

func TestPortRange_SinglePort(t *testing.T) {
	r := PortRange{From: 22, To: 22}
	if !r.Contains(22) {
		t.Errorf("single-port range should contain that port")
	}
	if r.Contains(21) || r.Contains(23) {
		t.Errorf("single-port range should not contain neighbours")
	}
}

// ---------------------------------------------------------------
// ParsePortRange
// ---------------------------------------------------------------

func TestParsePortRange_HappyPath(t *testing.T) {
	cases := []struct {
		in       string
		from, to uint16
	}{
		{"80", 80, 80},
		{"80-443", 80, 443},
		{" 80 - 443 ", 80, 443},  // whitespace tolerance
		{"0-65535", 0, 65535},
		{"", 0, 65535},   // empty → all
		{"*", 0, 65535},  // wildcard → all
	}
	for _, c := range cases {
		got, err := ParsePortRange(c.in)
		if err != nil {
			t.Errorf("ParsePortRange(%q) err = %v", c.in, err)
			continue
		}
		if got.From != c.from || got.To != c.to {
			t.Errorf("ParsePortRange(%q) = {%d,%d}; want {%d,%d}",
				c.in, got.From, got.To, c.from, c.to)
		}
	}
}

func TestParsePortRange_Errors(t *testing.T) {
	bad := []string{
		"abc",
		"80-",
		"-443",
		"80-abc",
		"abc-443",
		"99999",       // out of uint16
		"443-80",      // reversed range
		"80-443-100",  // multiple separators (only first SplitN is used; second part = "443-100" → parse fails)
	}
	for _, s := range bad {
		if _, err := ParsePortRange(s); err == nil {
			t.Errorf("ParsePortRange(%q) accepted; should have errored", s)
		}
	}
}

// ---------------------------------------------------------------
// Rule.Normalize
// ---------------------------------------------------------------

func TestRuleNormalize_DefaultsAndAction(t *testing.T) {
	r := Rule{}
	if err := r.Normalize(); err != nil {
		t.Fatalf("empty rule should normalize: %v", err)
	}
	if r.Action != Allow {
		t.Errorf("default Action = %q; want Allow", r.Action)
	}

	r = Rule{Action: "weird"}
	if err := r.Normalize(); err == nil {
		t.Errorf("invalid action should error")
	}
}

func TestRuleNormalize_PrefixForms(t *testing.T) {
	// Bare addr → /32 (v4) or /128 (v6); CIDR notation passes through.
	r := Rule{
		Action:       Allow,
		Source:       "10.0.0.1",        // → 10.0.0.1/32
		Destination:  "fd00::1",         // → fd00::1/128
		Sources:      []string{"192.168.0.0/24"},
		Destinations: []string{"::1"},   // → ::1/128
	}
	if err := r.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(r.sourcePrefixes) != 2 {
		t.Errorf("want 2 source prefixes; got %d", len(r.sourcePrefixes))
	}
	if r.sourcePrefixes[0].Bits() != 32 {
		t.Errorf("bare IPv4 should be /32; got /%d", r.sourcePrefixes[0].Bits())
	}
	if len(r.destPrefixes) != 2 {
		t.Errorf("want 2 dest prefixes; got %d", len(r.destPrefixes))
	}
	if !r.destPrefixes[0].Contains(netip.MustParseAddr("fd00::1")) {
		t.Errorf("dest prefix should contain its source addr")
	}
}

func TestRuleNormalize_BadPrefix(t *testing.T) {
	bad := []Rule{
		{Action: Allow, Source: "not-an-ip"},
		{Action: Allow, Destination: "10.0.0.0/33"}, // too many bits for v4
		{Action: Allow, Sources: []string{"10.0.0.1", "garbage"}},
	}
	for i, r := range bad {
		if err := r.Normalize(); err == nil {
			t.Errorf("rule[%d] %+v: expected normalize error, got nil", i, r)
		}
	}
}

func TestRuleNormalize_ProtocolValidation(t *testing.T) {
	good := []string{"tcp", "TCP", "Udp", "icmp", ""}
	for _, p := range good {
		r := Rule{Action: Allow, Protocol: p}
		if err := r.Normalize(); err != nil {
			t.Errorf("Protocol=%q: unexpected error %v", p, err)
		}
		if p != "" && r.Protocol != strings.ToLower(p) {
			t.Errorf("Protocol=%q normalized to %q; want lowercased", p, r.Protocol)
		}
	}
	bad := []string{"sctp", "rdp", "ssh", "TCP-LIKE"}
	for _, p := range bad {
		r := Rule{Action: Allow, Protocol: p}
		if err := r.Normalize(); err == nil {
			t.Errorf("Protocol=%q: should have errored", p)
		}
	}
}

func TestRuleNormalize_PortRangeForms(t *testing.T) {
	r := Rule{Action: Allow, SourcePort: "1024-65535", DestPort: "443"}
	if err := r.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if r.sourcePorts == nil || r.sourcePorts.From != 1024 || r.sourcePorts.To != 65535 {
		t.Errorf("sourcePorts unexpected: %+v", r.sourcePorts)
	}
	if r.destPorts == nil || r.destPorts.From != 443 || r.destPorts.To != 443 {
		t.Errorf("destPorts unexpected: %+v", r.destPorts)
	}
}

// ---------------------------------------------------------------
// List.Normalize
// ---------------------------------------------------------------

func TestListNormalize_DefaultAndPropagatesErrors(t *testing.T) {
	l := List{}
	if err := l.Normalize(); err != nil {
		t.Fatalf("empty list should normalize: %v", err)
	}
	if l.Default != Allow {
		t.Errorf("default = %q; want Allow", l.Default)
	}

	bad := List{Rules: []Rule{{Action: Allow, Source: "garbage"}}}
	if err := bad.Normalize(); err == nil {
		t.Errorf("list with bad rule should propagate error")
	}

	bad = List{Default: "maybe"}
	if err := bad.Normalize(); err == nil {
		t.Errorf("list with bad default should error")
	}
}

// ---------------------------------------------------------------
// List.Allowed — the load-bearing semantics
// ---------------------------------------------------------------

func mustAddr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestAllowed_Default(t *testing.T) {
	// Empty list with Default=Allow → everything allowed.
	l := DefaultAllow()
	if !l.Allowed(mustAddr(t, "10.0.0.1:1234"), mustAddr(t, "10.0.0.2:80"), "tcp") {
		t.Errorf("default-allow empty list should allow")
	}

	// Empty list with Default=Deny → everything denied.
	l = List{Default: Deny}
	_ = l.Normalize()
	if l.Allowed(mustAddr(t, "10.0.0.1:1234"), mustAddr(t, "10.0.0.2:80"), "tcp") {
		t.Errorf("default-deny empty list should deny")
	}
}

func TestAllowed_FirstMatchWins(t *testing.T) {
	// Order matters: an early Allow shadows a later Deny on the
	// same flow. This is the load-bearing security invariant.
	l := List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, Source: "10.0.0.0/24"},
			{Action: Deny, Source: "10.0.0.5/32"}, // shadowed by rule above
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	src := mustAddr(t, "10.0.0.5:1024")
	dst := mustAddr(t, "100.64.0.1:80")
	if !l.Allowed(src, dst, "tcp") {
		t.Errorf("10.0.0.5 should be allowed by the broader-but-earlier /24 rule")
	}

	// Reverse order: Deny first wins.
	l = List{
		Default: Allow,
		Rules: []Rule{
			{Action: Deny, Source: "10.0.0.5/32"},
			{Action: Allow, Source: "10.0.0.0/24"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if l.Allowed(src, dst, "tcp") {
		t.Errorf("10.0.0.5 should be denied by the early /32 rule even though /24 follows")
	}
}

func TestAllowed_NoMatchHitsDefault(t *testing.T) {
	l := List{
		Default: Allow,
		Rules: []Rule{
			{Action: Deny, Source: "192.168.0.0/16"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	// Source outside any rule's prefix → fall through to Default=Allow.
	if !l.Allowed(mustAddr(t, "10.0.0.1:1024"), mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("no-match should hit default Allow")
	}

	l = List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, Source: "192.168.0.0/16"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if l.Allowed(mustAddr(t, "10.0.0.1:1024"), mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("no-match should hit default Deny")
	}
}

func TestAllowed_PortMatch(t *testing.T) {
	l := List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, DestPort: "80,443" /* invalid intentionally? */},
		},
	}
	// The "80,443" is NOT a supported syntax (we only do single port
	// or range). Should fail to normalize. Verify.
	if err := l.Normalize(); err == nil {
		t.Errorf("comma-separated port list should fail to normalize (we only support range)")
	}

	// Now a valid range.
	l = List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, DestPort: "80-443"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	src := mustAddr(t, "10.0.0.1:1234")
	if !l.Allowed(src, mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("port 80 should match 80-443 range")
	}
	if !l.Allowed(src, mustAddr(t, "100.64.0.1:443"), "tcp") {
		t.Errorf("port 443 should match 80-443 range")
	}
	if l.Allowed(src, mustAddr(t, "100.64.0.1:444"), "tcp") {
		t.Errorf("port 444 should NOT match 80-443 range — must hit Default=Deny")
	}
}

func TestAllowed_ProtocolFilter(t *testing.T) {
	l := List{
		Default: Allow,
		Rules: []Rule{
			{Action: Deny, Protocol: "udp"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	src := mustAddr(t, "10.0.0.1:1234")
	dst := mustAddr(t, "100.64.0.1:53")

	// UDP traffic hits the Deny rule.
	if l.Allowed(src, dst, "udp") {
		t.Errorf("udp should be denied by the udp-deny rule")
	}
	// TCP traffic doesn't match the Deny rule (protocol mismatch),
	// falls through to Default=Allow.
	if !l.Allowed(src, dst, "tcp") {
		t.Errorf("tcp should NOT be denied by the udp-deny rule")
	}
	// ICMP traffic also bypasses the udp-only rule.
	if !l.Allowed(src, dst, "icmp") {
		t.Errorf("icmp should NOT be denied by the udp-deny rule")
	}
}

func TestAllowed_SrcDstBothChecked(t *testing.T) {
	l := List{
		Default: Deny,
		Rules: []Rule{
			{
				Action:      Allow,
				Source:      "10.0.0.0/24",
				Destination: "100.64.0.0/16",
				DestPort:    "80",
			},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	// All three conditions met → allow.
	if !l.Allowed(mustAddr(t, "10.0.0.5:1234"),
		mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("matching all three (src+dst+dport) should allow")
	}
	// Wrong source CIDR → fall through to default Deny.
	if l.Allowed(mustAddr(t, "192.168.0.5:1234"),
		mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("source outside CIDR should not match → default Deny")
	}
	// Wrong dest CIDR → fall through.
	if l.Allowed(mustAddr(t, "10.0.0.5:1234"),
		mustAddr(t, "8.8.8.8:80"), "tcp") {
		t.Errorf("dest outside CIDR should not match → default Deny")
	}
	// Wrong dport → fall through.
	if l.Allowed(mustAddr(t, "10.0.0.5:1234"),
		mustAddr(t, "100.64.0.1:443"), "tcp") {
		t.Errorf("dport outside range should not match → default Deny")
	}
}

func TestAllowed_MultipleSourcesAreUnion(t *testing.T) {
	// Sources is a list; matching ANY one entry counts as "source matches".
	l := List{
		Default: Deny,
		Rules: []Rule{
			{
				Action:  Allow,
				Sources: []string{"10.0.0.0/24", "192.168.1.0/24"},
			},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	dst := mustAddr(t, "100.64.0.1:80")
	if !l.Allowed(mustAddr(t, "10.0.0.5:1234"), dst, "tcp") {
		t.Errorf("first Sources entry should match")
	}
	if !l.Allowed(mustAddr(t, "192.168.1.5:1234"), dst, "tcp") {
		t.Errorf("second Sources entry should match")
	}
	if l.Allowed(mustAddr(t, "172.16.0.5:1234"), dst, "tcp") {
		t.Errorf("source matching neither entry should fall through to Default=Deny")
	}
}

func TestAllowed_SingularAndListAreMerged(t *testing.T) {
	// Source + Sources both provided → both are honoured.
	l := List{
		Default: Deny,
		Rules: []Rule{
			{
				Action:  Allow,
				Source:  "10.0.0.0/24",
				Sources: []string{"192.168.1.0/24"},
			},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	dst := mustAddr(t, "100.64.0.1:80")
	if !l.Allowed(mustAddr(t, "10.0.0.5:1234"), dst, "tcp") {
		t.Errorf("singular Source should match")
	}
	if !l.Allowed(mustAddr(t, "192.168.1.5:1234"), dst, "tcp") {
		t.Errorf("Sources list should also match (merged with singular)")
	}
}

func TestAllowed_IPv6(t *testing.T) {
	l := List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, Destination: "fd00::/64"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	src := mustAddr(t, "[fd00::1]:1234")
	if !l.Allowed(src, mustAddr(t, "[fd00::abc]:80"), "tcp") {
		t.Errorf("dest in fd00::/64 should match")
	}
	if l.Allowed(src, mustAddr(t, "[fe80::abc]:80"), "tcp") {
		t.Errorf("dest outside fd00::/64 should fall through to default Deny")
	}
}

func TestAllowed_EmptyRuleMatchesAll(t *testing.T) {
	// A rule with no Source/Dest/Port/Protocol matches every flow —
	// useful as a "catch-all allow" or "catch-all deny" before
	// hitting the list default.
	l := List{
		Default: Deny, // never reached
		Rules: []Rule{
			{Action: Allow},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !l.Allowed(mustAddr(t, "10.0.0.5:1234"),
		mustAddr(t, "100.64.0.1:80"), "tcp") {
		t.Errorf("empty allow rule should match every flow")
	}
}

// ---------------------------------------------------------------
// ParseRule (CLI-friendly syntax)
// ---------------------------------------------------------------

func TestParseRule_HappyPath(t *testing.T) {
	r, err := ParseRule("allow src=10.0.0.0/24 dst=100.64.0.0/10 dport=80-443 protocol=tcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Action != Allow {
		t.Errorf("Action = %q; want allow", r.Action)
	}
	if r.Source != "10.0.0.0/24" {
		t.Errorf("Source = %q; want 10.0.0.0/24", r.Source)
	}
	if r.DestPort != "80-443" {
		t.Errorf("DestPort = %q; want 80-443", r.DestPort)
	}
	if r.Protocol != "tcp" {
		t.Errorf("Protocol = %q; want tcp", r.Protocol)
	}
	// Verify the rule normalizes (already called by ParseRule).
	if len(r.sourcePrefixes) == 0 {
		t.Errorf("normalize wasn't run by ParseRule")
	}
}

func TestParseRule_KeyAliases(t *testing.T) {
	cases := []string{
		"allow source=10.0.0.0/24 destination=100.64.0.0/10 source_port=1024-65535 destination_port=80",
		"allow src=10.0.0.0/24 dst=100.64.0.0/10 sport=1024-65535 dport=80",
		"allow src=10.0.0.0/24 dest=100.64.0.0/10 dport=80",
	}
	for _, in := range cases {
		if _, err := ParseRule(in); err != nil {
			t.Errorf("ParseRule(%q) err = %v", in, err)
		}
	}
}

func TestParseRule_Errors(t *testing.T) {
	bad := []string{
		"",                              // empty
		"allow src",                     // missing =value
		"allow weirdfield=10.0.0.0/24",  // unknown key
		"allow src=garbage",             // unparseable address
		"allow protocol=sctp",           // unknown protocol
	}
	for _, in := range bad {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) accepted; should have errored", in)
		}
	}
}

func TestParseRule_DenyAction(t *testing.T) {
	r, err := ParseRule("deny dst=8.8.8.8")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Action != Deny {
		t.Errorf("Action = %q; want deny", r.Action)
	}
}

func TestParseRule_ActionCaseInsensitive(t *testing.T) {
	for _, in := range []string{"ALLOW", "Allow", "DENY", "Deny"} {
		r, err := ParseRule(in + " src=10.0.0.0/24")
		if err != nil {
			t.Errorf("ParseRule(%q...) err = %v", in, err)
			continue
		}
		want := Action(strings.ToLower(in))
		if r.Action != want {
			t.Errorf("Action = %q; want %q", r.Action, want)
		}
	}
}

// ---------------------------------------------------------------
// CIDR-overlap edge cases (the audit's specific concern)
// ---------------------------------------------------------------

func TestAllowed_OverlappingCIDR_FirstWins(t *testing.T) {
	// A common security pattern: deny a specific host inside an
	// otherwise-allowed subnet. Order MUST be Deny first.
	l := List{
		Default: Deny,
		Rules: []Rule{
			// Block the specific bad host.
			{Action: Deny, Source: "10.0.0.7/32"},
			// Allow the rest of the subnet.
			{Action: Allow, Source: "10.0.0.0/24"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	dst := mustAddr(t, "100.64.0.1:80")
	if l.Allowed(mustAddr(t, "10.0.0.7:1234"), dst, "tcp") {
		t.Errorf("specific deny should win over broader allow")
	}
	if !l.Allowed(mustAddr(t, "10.0.0.8:1234"), dst, "tcp") {
		t.Errorf("non-blocked host in subnet should be allowed")
	}
}

func TestAllowed_OverlappingCIDR_AllowFirstShadowsDeny(t *testing.T) {
	// If the allow rule comes first, it shadows the deny — this
	// is the OPPOSITE of what an admin probably wants. The test
	// nails down the actual behaviour so a future refactor can't
	// silently change it.
	l := List{
		Default: Deny,
		Rules: []Rule{
			{Action: Allow, Source: "10.0.0.0/24"},
			{Action: Deny, Source: "10.0.0.7/32"},
		},
	}
	if err := l.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	dst := mustAddr(t, "100.64.0.1:80")
	if !l.Allowed(mustAddr(t, "10.0.0.7:1234"), dst, "tcp") {
		t.Errorf("rule order = first-match-wins; the allow should shadow the later deny")
	}
}

// ---------------------------------------------------------------
// Defensive: re-Normalize is idempotent (cached prefix lists are reset)
// ---------------------------------------------------------------

func TestRuleNormalize_Idempotent(t *testing.T) {
	r := Rule{
		Action:  Allow,
		Sources: []string{"10.0.0.0/24", "192.168.0.0/24"},
	}
	if err := r.Normalize(); err != nil {
		t.Fatalf("first normalize: %v", err)
	}
	first := len(r.sourcePrefixes)
	if err := r.Normalize(); err != nil {
		t.Fatalf("second normalize: %v", err)
	}
	if len(r.sourcePrefixes) != first {
		t.Errorf("re-normalize should not duplicate prefix entries: had %d, now %d",
			first, len(r.sourcePrefixes))
	}
}
