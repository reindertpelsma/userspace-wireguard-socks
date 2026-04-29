// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---------------------------------------------------------------------------
// Flag type unit tests
// ---------------------------------------------------------------------------

func TestOptionalBoolSet(t *testing.T) {
	truthy := []string{"1", "t", "true", "yes", "y", "on"}
	falsy := []string{"0", "f", "false", "no", "n", "off"}
	for _, v := range truthy {
		var b optionalBool
		if err := b.Set(v); err != nil {
			t.Fatalf("Set(%q) err = %v", v, err)
		}
		if !b.set || !b.value {
			t.Fatalf("Set(%q): want set=true value=true, got set=%v value=%v", v, b.set, b.value)
		}
	}
	for _, v := range falsy {
		var b optionalBool
		if err := b.Set(v); err != nil {
			t.Fatalf("Set(%q) err = %v", v, err)
		}
		if !b.set || b.value {
			t.Fatalf("Set(%q): want set=true value=false, got set=%v value=%v", v, b.set, b.value)
		}
	}
	var b optionalBool
	if err := b.Set("invalid"); err == nil {
		t.Fatal("Set(invalid) should return error")
	}
	if b.IsBoolFlag() != true {
		t.Fatal("IsBoolFlag should return true")
	}
}

func TestOptionalBoolString(t *testing.T) {
	var b optionalBool
	if b.String() != "" {
		t.Fatalf("unset optionalBool.String() = %q, want empty", b.String())
	}
	_ = b.Set("true")
	if b.String() != "true" {
		t.Fatalf("true optionalBool.String() = %q", b.String())
	}
	_ = b.Set("false")
	if b.String() != "false" {
		t.Fatalf("false optionalBool.String() = %q", b.String())
	}
}

func TestListFlagRepeatable(t *testing.T) {
	var f listFlag
	vals := []string{"a", "b", "c"}
	for _, v := range vals {
		if err := f.Set(v); err != nil {
			t.Fatalf("Set(%q) err = %v", v, err)
		}
	}
	if len(f) != 3 {
		t.Fatalf("len = %d, want 3", len(f))
	}
	if f.String() != "a,b,c" {
		t.Fatalf("String() = %q, want a,b,c", f.String())
	}
}

// ---------------------------------------------------------------------------
// ParsePeerArg — covers all documented peer fields
// ---------------------------------------------------------------------------

func TestParsePeerArgMinimal(t *testing.T) {
	p, err := config.ParsePeerArg("public_key=peerkey,allowed_ips=10.0.0.2/32")
	if err != nil {
		t.Fatal(err)
	}
	if p.PublicKey != "peerkey" {
		t.Fatalf("public_key = %q", p.PublicKey)
	}
	if len(p.AllowedIPs) == 0 || p.AllowedIPs[0] != "10.0.0.2/32" {
		t.Fatalf("allowed_ips = %v", p.AllowedIPs)
	}
}

func TestParsePeerArgFull(t *testing.T) {
	p, err := config.ParsePeerArg(
		"public_key=AAAA,allowed_ips=10.0.0.2/32,endpoint=vpn.example.com:51820," +
			"persistent_keepalive=25,upload_bps=4096,download_bps=8192,latency_ms=20",
	)
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint != "vpn.example.com:51820" {
		t.Fatalf("endpoint = %q", p.Endpoint)
	}
	if p.PersistentKeepalive != 25 {
		t.Fatalf("keepalive = %d", p.PersistentKeepalive)
	}
}

func TestParsePeerArgDouble(t *testing.T) {
	// Simulates --peer repeated twice on the CLI (docs/howto/01-simple-client-proxy.md pattern)
	args := []string{
		"public_key=peer1,allowed_ips=10.0.0.2/32",
		"public_key=peer2,allowed_ips=10.0.0.3/32",
	}
	var peers []config.Peer
	for _, a := range args {
		p, err := config.ParsePeerArg(a)
		if err != nil {
			t.Fatalf("ParsePeerArg(%q): %v", a, err)
		}
		peers = append(peers, p)
	}
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}
	if peers[0].PublicKey != "peer1" || peers[1].PublicKey != "peer2" {
		t.Fatalf("peer keys wrong: %v", peers)
	}
}

func TestParsePeerArgWithPSK(t *testing.T) {
	psk, _ := wgtypes.GenerateKey()
	p, err := config.ParsePeerArg("public_key=AAAA,allowed_ips=10.0.0.2/32,preshared_key=" + psk.String())
	if err != nil {
		t.Fatal(err)
	}
	if p.PresharedKey != psk.String() {
		t.Fatalf("preshared_key = %q", p.PresharedKey)
	}
}

// ---------------------------------------------------------------------------
// ParseForwardArg — --forward and --reverse-forward formats
// ---------------------------------------------------------------------------

func TestParseForwardArgTCP(t *testing.T) {
	// From docs/howto/01-simple-client-proxy.md and examples/forwarding.yaml
	f, err := config.ParseForwardArg("tcp://127.0.0.1:18081=100.64.90.1:8081")
	if err != nil {
		t.Fatal(err)
	}
	if f.Proto != "tcp" {
		t.Fatalf("proto = %q", f.Proto)
	}
	if f.Listen != "127.0.0.1:18081" {
		t.Fatalf("listen = %q", f.Listen)
	}
	if f.Target != "100.64.90.1:8081" {
		t.Fatalf("target = %q", f.Target)
	}
}

func TestParseForwardArgUDP(t *testing.T) {
	// UDP forward: --forward udp://127.0.0.1:5353=100.64.90.1:53
	f, err := config.ParseForwardArg("udp://127.0.0.1:5353=100.64.90.1:53")
	if err != nil {
		t.Fatal(err)
	}
	if f.Proto != "udp" {
		t.Fatalf("proto = %q", f.Proto)
	}
}

func TestParseReverseForwardArg(t *testing.T) {
	// Reverse forward: --reverse-forward tcp://100.64.90.99:8080=127.0.0.1:8080
	f, err := config.ParseForwardArg("tcp://100.64.90.99:8080=127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if f.Listen != "100.64.90.99:8080" {
		t.Fatalf("listen = %q", f.Listen)
	}
	if f.Target != "127.0.0.1:8080" {
		t.Fatalf("target = %q", f.Target)
	}
}

// ---------------------------------------------------------------------------
// ParseOutboundProxyArg — --outbound-proxy format
// ---------------------------------------------------------------------------

func TestParseOutboundProxyArg(t *testing.T) {
	// From flag docs: socks5://127.0.0.1:1081;roles=socks,inbound;subnets=0.0.0.0/0
	p, err := config.ParseOutboundProxyArg("socks5://127.0.0.1:1081;roles=socks,inbound;subnets=0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Address == "" {
		t.Fatal("Address is empty")
	}
}

func TestParseOutboundProxyHTTP(t *testing.T) {
	p, err := config.ParseOutboundProxyArg("http://proxy.corp.example:3128;roles=socks")
	if err != nil {
		t.Fatal(err)
	}
	if p.Address == "" {
		t.Fatal("Address is empty")
	}
}

// ---------------------------------------------------------------------------
// ACL ParseRule — --acl-inbound / --acl-outbound / --acl-relay formats
// ---------------------------------------------------------------------------

func TestParseACLRuleAllow(t *testing.T) {
	r, err := acl.ParseRule("allow src=10.0.0.0/24 dst=0.0.0.0/0 dport=80-443")
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != acl.Allow {
		t.Fatalf("action = %q, want allow", r.Action)
	}
}

func TestParseACLRuleDeny(t *testing.T) {
	r, err := acl.ParseRule("deny")
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != acl.Deny {
		t.Fatalf("action = %q, want deny", r.Action)
	}
}

func TestParseACLRuleProtocol(t *testing.T) {
	r, err := acl.ParseRule("allow protocol=tcp dport=22")
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != acl.Allow {
		t.Fatalf("action = %q", r.Action)
	}
}

// ---------------------------------------------------------------------------
// Utility subcommand extended coverage
// ---------------------------------------------------------------------------

func TestGenPairNoPSK(t *testing.T) {
	tmp := t.TempDir()
	serverOut := filepath.Join(tmp, "server.conf")
	clientOut := filepath.Join(tmp, "client.conf")
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			"--client-address", "10.0.0.2/32",
			"--no-psk",
			"--server-out", serverOut,
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := os.ReadFile(serverOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serverCfg), "PresharedKey") {
		t.Fatal("--no-psk: PresharedKey should be absent")
	}
}

func TestGenPairStdout(t *testing.T) {
	// Without --server-out/--client-out: both configs printed to stdout.
	out, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.10.0.1/32",
			"--client-address", "10.10.0.2/32",
			"--server-endpoint", "server.example.com:51820",
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[Interface]") {
		t.Fatalf("stdout should contain WireGuard config, got:\n%s", out)
	}
	if !strings.Contains(out, "server-server.conf") && !strings.Contains(out, "peer-server.conf") {
		// check for the default --name prefix
	}
}

func TestGenPairName(t *testing.T) {
	out, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			"--client-address", "10.0.0.2/32",
			"--name", "mynode",
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mynode-server.conf") {
		t.Fatalf("expected 'mynode-server.conf' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "mynode-client.conf") {
		t.Fatalf("expected 'mynode-client.conf' in output, got:\n%s", out)
	}
}

func TestGenPairClientEndpoint(t *testing.T) {
	tmp := t.TempDir()
	serverOut := filepath.Join(tmp, "server.conf")
	clientOut := filepath.Join(tmp, "client.conf")
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			"--client-address", "10.0.0.2/32",
			"--client-endpoint", "client.dyn.example:51820",
			"--server-out", serverOut,
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, _ := os.ReadFile(serverOut)
	if !strings.Contains(string(serverCfg), "Endpoint = client.dyn.example:51820") {
		t.Fatalf("server config missing client endpoint:\n%s", serverCfg)
	}
}

func TestGenPairCustomAllowedIPs(t *testing.T) {
	tmp := t.TempDir()
	serverOut := filepath.Join(tmp, "server.conf")
	clientOut := filepath.Join(tmp, "client.conf")
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			"--client-address", "10.0.0.2/32",
			"--server-allowed-ip", "0.0.0.0/0",
			"--client-allowed-ip", "10.0.0.0/8",
			"--server-out", serverOut,
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, _ := os.ReadFile(serverOut)
	clientCfg, _ := os.ReadFile(clientOut)
	if !strings.Contains(string(serverCfg), "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("server config wrong allowed IPs:\n%s", serverCfg)
	}
	if !strings.Contains(string(clientCfg), "AllowedIPs = 10.0.0.0/8") {
		t.Fatalf("client config wrong allowed IPs:\n%s", clientCfg)
	}
}

func TestGenPairListenPort(t *testing.T) {
	tmp := t.TempDir()
	serverOut := filepath.Join(tmp, "server.conf")
	clientOut := filepath.Join(tmp, "client.conf")
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			"--client-address", "10.0.0.2/32",
			"--server-listen-port", "9999",
			"--server-out", serverOut,
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, _ := os.ReadFile(serverOut)
	if !strings.Contains(string(serverCfg), "ListenPort = 9999") {
		t.Fatalf("expected ListenPort = 9999:\n%s", serverCfg)
	}
}

func TestAddClientNoPSK(t *testing.T) {
	tmp := t.TempDir()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverCfgPath := filepath.Join(tmp, "server.conf")
	serverCfg := "[Interface]\nPrivateKey = " + serverKey.String() + "\nAddress = 10.0.0.1/32\nListenPort = 51820\n"
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	clientOut := filepath.Join(tmp, "client.conf")
	_, err = captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"add-client",
			"--server-config", serverCfgPath,
			"--client-address", "10.0.0.99/32",
			"--no-psk",
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("add-client was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, _ := os.ReadFile(clientOut)
	if strings.Contains(string(clientCfg), "PresharedKey") {
		t.Fatal("--no-psk: PresharedKey should be absent")
	}
}

func TestAddClientDNS(t *testing.T) {
	tmp := t.TempDir()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverCfgPath := filepath.Join(tmp, "server.conf")
	serverCfg := "[Interface]\nPrivateKey = " + serverKey.String() + "\nAddress = 10.0.0.1/32\nListenPort = 51820\n"
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	clientOut := filepath.Join(tmp, "client.conf")
	_, err = captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"add-client",
			"--server-config", serverCfgPath,
			"--client-address", "10.0.0.88/32",
			"--dns", "1.1.1.1",
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("add-client was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, _ := os.ReadFile(clientOut)
	if !strings.Contains(string(clientCfg), "DNS = 1.1.1.1") {
		t.Fatalf("expected DNS = 1.1.1.1 in client config:\n%s", clientCfg)
	}
}

func TestAddClientName(t *testing.T) {
	tmp := t.TempDir()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverCfgPath := filepath.Join(tmp, "server.conf")
	serverCfg := "[Interface]\nPrivateKey = " + serverKey.String() + "\nAddress = 10.0.0.1/32\nListenPort = 51820\n"
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"add-client",
			"--server-config", serverCfgPath,
			"--client-address", "10.0.0.77/32",
			"--name", "laptop",
		})
		if !handled {
			t.Fatal("add-client was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "laptop.conf") {
		t.Fatalf("expected 'laptop.conf' in output, got:\n%s", out)
	}
}

func TestAddClientCustomAllowedIP(t *testing.T) {
	tmp := t.TempDir()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverCfgPath := filepath.Join(tmp, "server.conf")
	serverCfg := "[Interface]\nPrivateKey = " + serverKey.String() + "\nAddress = 10.0.0.1/32\nListenPort = 51820\n"
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	clientOut := filepath.Join(tmp, "client.conf")
	_, err = captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"add-client",
			"--server-config", serverCfgPath,
			"--client-address", "10.0.0.66/32",
			"--client-allowed-ip", "0.0.0.0/0",
			"--client-out", clientOut,
		})
		if !handled {
			t.Fatal("add-client was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, _ := os.ReadFile(clientOut)
	if !strings.Contains(string(clientCfg), "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("expected AllowedIPs = 0.0.0.0/0:\n%s", clientCfg)
	}
}

func TestPubkeyFromFile(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "priv.key")
	if err := os.WriteFile(keyFile, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{"pubkey", "--in", keyFile})
		if !handled {
			t.Fatal("pubkey was not handled")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != priv.PublicKey().String() {
		t.Fatalf("pubkey --in: got %q, want %q", strings.TrimSpace(out), priv.PublicKey().String())
	}
}

func TestGenPairMissingRequiredFlags(t *testing.T) {
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"genpair",
			"--server-address", "10.0.0.1/32",
			// missing --client-address
		})
		if !handled {
			t.Fatal("genpair was not handled")
		}
		return err
	})
	if err == nil {
		t.Fatal("genpair with no --client-address should return error")
	}
}

func TestAddClientMissingRequiredFlags(t *testing.T) {
	_, err := captureStdout(func() error {
		handled, err := runUtilityCommand([]string{
			"add-client",
			// missing --server-config and --client-address
		})
		if !handled {
			t.Fatal("add-client was not handled")
		}
		return err
	})
	if err == nil {
		t.Fatal("add-client with no required flags should return error")
	}
}

func TestUnknownUtilityCommand(t *testing.T) {
	handled, _ := runUtilityCommand([]string{"not-a-command"})
	if handled {
		t.Fatal("unknown command should not be handled")
	}
}

func TestDaemonFlagPrefix(t *testing.T) {
	// A leading dash means it's a daemon flag, not a utility subcommand.
	handled, _ := runUtilityCommand([]string{"--config", "x.yaml"})
	if handled {
		t.Fatal("leading dash should not be handled as utility command")
	}
}

// ---------------------------------------------------------------------------
// API subcommand extended coverage
// ---------------------------------------------------------------------------

func TestAPIResolveCommand(t *testing.T) {
	// Build a minimal NXDOMAIN DNS wire-format response to satisfy the DoH client.
	resp := new(dns.Msg)
	resp.SetRcode(new(dns.Msg).SetQuestion("example.com.", dns.TypeA), dns.RcodeNameError)
	wire, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	var hitPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPaths = append(hitPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	t.Setenv("UWGS_API", server.URL)
	t.Setenv("UWGS_API_TOKEN", "")

	for _, subcmd := range []string{"resolve", "dig"} {
		t.Run(subcmd, func(t *testing.T) {
			_, err := captureStdout(func() error {
				handled, err := runAPICommand([]string{subcmd, "example.com"})
				if !handled {
					t.Fatalf("%s was not handled", subcmd)
				}
				return err
			})
			if err != nil {
				t.Fatalf("%s failed: %v", subcmd, err)
			}
		})
	}
	if len(hitPaths) < 2 {
		t.Fatalf("expected at least 2 API hits for resolve+dig, got %d", len(hitPaths))
	}
}

func TestAPISetconfAlias(t *testing.T) {
	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.URL.Path)
		if !strings.Contains(string(body), "[Interface]") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	t.Setenv("UWGS_API", server.URL)
	t.Setenv("UWGS_API_TOKEN", "")

	tmp := t.TempDir()
	wgFile := filepath.Join(tmp, "wg.conf")
	if err := os.WriteFile(wgFile, []byte("[Interface]\nPrivateKey = TEST\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, subcmd := range []string{"wg-setconf", "setconf"} {
		t.Run(subcmd, func(t *testing.T) {
			_, err := captureStdout(func() error {
				handled, err := runAPICommand([]string{subcmd, wgFile})
				if !handled {
					t.Fatalf("%s was not handled", subcmd)
				}
				return err
			})
			if err != nil {
				t.Fatalf("%s failed: %v", subcmd, err)
			}
		})
	}
}

func TestAPIUnknownCommand(t *testing.T) {
	handled, _ := runAPICommand([]string{"not-a-command"})
	if handled {
		t.Fatal("unknown API command should not be handled")
	}
}

// ---------------------------------------------------------------------------
// WireGuard config parsing used by --wg-config
// ---------------------------------------------------------------------------

func TestMergeWGQuickInline(t *testing.T) {
	// Exercises the --wg-inline path that main() uses
	inline := "[Interface]\nPrivateKey = SIcaKz9M+RGqA6MVnzbQsU9uvoyr1iBULxsdxyFQU3s=\nAddress = 100.64.90.2/32\n\n" +
		"[Peer]\nPublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:51821\n"
	var wg config.WireGuard
	if err := config.MergeWGQuick(&wg, inline); err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey == "" {
		t.Fatal("PrivateKey not parsed")
	}
	if len(wg.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(wg.Peers))
	}
}

func TestMergeWGQuickFile(t *testing.T) {
	// Exercises the --wg-config path; uses the checked-in demo server config.
	repoRoot := findRepoRoot(t)
	wgFile := filepath.Join(repoRoot, "examples", "server.conf")
	var wg config.WireGuard
	if err := config.MergeWGQuickFile(&wg, wgFile); err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey == "" {
		t.Fatal("PrivateKey not loaded from server.conf")
	}
	if len(wg.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(wg.Peers))
	}
}

// ---------------------------------------------------------------------------
// Config load / normalize via YAML (--config flag path)
// ---------------------------------------------------------------------------

func TestConfigLoadYAML(t *testing.T) {
	// Exercises config.Load — the --config flag path.
	// Write a temp YAML config with an inline private key so config.Load
	// can normalize without needing a relative wg config file.
	priv, _ := wgtypes.GeneratePrivateKey()
	yaml := "wireguard:\n  private_key: " + priv.String() + "\n  addresses:\n    - 10.99.0.1/32\nproxy:\n  socks5: 127.0.0.1:1080\n  http: 127.0.0.1:8082\nforwards:\n  - proto: tcp\n    listen: 127.0.0.1:18081\n    target: 10.99.0.2:80\n"
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "test.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.SOCKS5 != "127.0.0.1:1080" {
		t.Fatalf("socks5 = %q", cfg.Proxy.SOCKS5)
	}
	if len(cfg.Forwards) == 0 {
		t.Fatal("expected at least one forward")
	}
}

func TestConfigLoadEmptyPath(t *testing.T) {
	// config.Load("") returns the default config — exercises the empty --config path.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	// Should have default values without panicking.
	_ = cfg
}

func TestConfigNormalizeWithFlags(t *testing.T) {
	// Simulate --private-key, --address, --socks5, --listen-port flags applied to an empty config.
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuard.PrivateKey = priv.String()
	cfg.WireGuard.Addresses = []string{"10.99.0.1/32"}
	lp := 0
	cfg.WireGuard.ListenPort = &lp
	cfg.Proxy.SOCKS5 = "127.0.0.1:19080"
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// --check flag via subprocess (not -short: requires building)
// ---------------------------------------------------------------------------

func TestCheckFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	wgConfig := filepath.Join(repoRoot, "examples", "server.conf")
	// Build binary to temp dir to avoid repeated builds across subtests.
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-check-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// Run with --check using the demo server config.
	cmd := exec.Command(bin, "--check", "--wg-config", wgConfig)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check exited non-zero: %v", err)
	}
}

func TestCheckFlagWithInlineFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Test that common daemon flags are accepted and normalize correctly.
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-inline-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--socks5", "127.0.0.1:0",
		"--verbose",
		"--acl-outbound-default", "allow",
		"--acl-inbound-default", "deny",
		"--fallback-direct",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with inline flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithDoublePeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()
	peer1, _ := wgtypes.GeneratePrivateKey()
	peer2, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-doublepeer-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --peer repeated twice: must both be accepted.
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--peer", "public_key="+peer1.PublicKey().String()+",allowed_ips=10.99.0.2/32",
		"--peer", "public_key="+peer2.PublicKey().String()+",allowed_ips=10.99.0.3/32",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with double --peer exited non-zero: %v", err)
	}
}

func TestCheckFlagWithForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-forward-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--forward", "tcp://127.0.0.1:0=10.99.0.2:80",
		"--forward", "udp://127.0.0.1:0=10.99.0.2:53",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with --forward flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithACLs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-acl-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// Exercises --acl-inbound, --acl-outbound, --acl-relay, --acl-*-default
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--acl-inbound", "allow src=10.0.0.0/8",
		"--acl-outbound", "allow dst=0.0.0.0/0",
		"--acl-relay", "deny",
		"--acl-inbound-default", "deny",
		"--acl-outbound-default", "allow",
		"--acl-relay-default", "deny",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with ACL flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithOutboundProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-proxy-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --outbound-proxy, --fallback-socks5, --honor-proxy-env, --proxy-ipv6
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--outbound-proxy", "socks5://127.0.0.1:1081;roles=socks",
		"--fallback-socks5", "socks5://127.0.0.1:1082",
		"--honor-proxy-env=false",
		"--proxy-ipv6=false",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with outbound proxy flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithTrafficShaper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-shaper-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --traffic-upload-bps, --traffic-download-bps, --traffic-latency-ms
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--traffic-upload-bps", "1000000",
		"--traffic-download-bps", "2000000",
		"--traffic-latency-ms", "20",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with traffic shaper flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithConnectionLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-limits-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --max-connections, --max-connections-per-peer, --tcp-idle-timeout, --udp-idle-timeout
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--max-connections", "1000",
		"--max-connections-per-peer", "100",
		"--tcp-idle-timeout", "900",
		"--udp-idle-timeout", "30",
		"--tcp-receive-window", "1048576",
		"--tcp-max-buffered", "268435456",
		"--connection-table-grace", "30",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with connection limit flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-api-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	apiSock := filepath.Join(tmp, "api.sock")
	// --api-listen, --api-token, --api-allow-unauthenticated-unix
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--api-listen", "unix://"+apiSock,
		"--api-token", "secret",
		"--api-allow-unauthenticated-unix=true",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with API flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithMixed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-mixed-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --http, --mixed, --proxy-username, --proxy-password, --socks5-udp-associate, --socks5-bind
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--http", "127.0.0.1:0",
		"--mixed", "127.0.0.1:0",
		"--proxy-username", "alice",
		"--proxy-password", "secret",
		"--socks5-udp-associate=false",
		"--socks5-bind=false",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with mixed proxy flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithFilteringFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-filter-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --drop-ipv4-invalid, --drop-ipv6-link-local-multicast, --enforce-address-subnets
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--drop-ipv4-invalid=true",
		"--drop-ipv6-link-local-multicast=true",
		"--enforce-address-subnets=false",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with filtering flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithRelayFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-relay-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --relay, --relay-conntrack, --relay-conntrack-max-flows, --relay-conntrack-max-per-peer
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--relay=true",
		"--relay-conntrack=true",
		"--relay-conntrack-max-flows", "1000",
		"--relay-conntrack-max-per-peer", "100",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with relay flags exited non-zero: %v", err)
	}
}

func TestCheckFlagWithWGInline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-wginline-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	priv, _ := wgtypes.GeneratePrivateKey()
	inline := "[Interface]\nPrivateKey = " + priv.String() + "\nAddress = 10.99.0.5/32\n"

	// --wg-inline: pass wg-quick config as a string
	cmd := exec.Command(bin,
		"--check",
		"--wg-inline", inline,
		"--listen-port", "0",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with --wg-inline exited non-zero: %v", err)
	}
}

func TestCheckFlagWithDNSAndMTU(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine startup in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess build path differs on windows")
	}
	repoRoot := findRepoRoot(t)
	priv, _ := wgtypes.GeneratePrivateKey()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "uwgsocks-dns-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot, "cmd", "uwgsocks")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}

	// --dns, --mtu, --roam-fallback, --listen-address
	cmd := exec.Command(bin,
		"--check",
		"--private-key", priv.String(),
		"--address", "10.99.0.1/32",
		"--listen-port", "0",
		"--dns", "1.1.1.1",
		"--mtu", "1420",
		"--roam-fallback", "120",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--check with DNS/MTU flags exited non-zero: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JSON serialization round-trip for status view (used by API status command)
// ---------------------------------------------------------------------------

func TestStatusViewJSONRoundTrip(t *testing.T) {
	sv := statusView{
		Running:           true,
		ListenPort:        51820,
		ActiveConnections: 5,
		Peers: []statusPeer{{
			PublicKey:     "testkey",
			Endpoint:      "1.2.3.4:51820",
			HasHandshake:  true,
			LastHandshake: "2026-04-29T10:00:00Z",
			ReceiveBytes:  1024,
			TransmitBytes: 2048,
			Dynamic:       true,
		}},
	}
	data, err := json.Marshal(sv)
	if err != nil {
		t.Fatal(err)
	}
	var sv2 statusView
	if err := json.Unmarshal(data, &sv2); err != nil {
		t.Fatal(err)
	}
	if sv2.ListenPort != sv.ListenPort || len(sv2.Peers) != 1 {
		t.Fatalf("round-trip failed: %+v", sv2)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}
