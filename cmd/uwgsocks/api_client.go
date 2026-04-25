// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
)

// base64Std aliases the standard base64 encoder so resolve's Basic-auth header
// stays readable inline without shadowing the existing url.QueryEscape style.
var base64Std = base64.StdEncoding

type apiClientOptions struct {
	endpoint string
	token    string
}

// runAPICommand implements the small "uwgsocks status/ping/peers/..." client.
// It intentionally lives in the main binary so administrators can inspect and
// mutate a running daemon without installing a second tool.
func runAPICommand(args []string) (bool, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return false, nil
	}
	commands := map[string]func([]string) error{
		"status":         apiStatusCommand,
		"ping":           apiPingCommand,
		"peers":          apiPeersCommand,
		"add-peer":       apiAddPeerCommand,
		"remove-peer":    apiRemovePeerCommand,
		"acl-list":       apiACLListCommand,
		"acl-add":        apiACLAddCommand,
		"acl-set":        apiACLSetCommand,
		"acl-remove":     apiACLRemoveCommand,
		"wg-setconf":     apiWGSetConfCommand,
		"setconf":        apiWGSetConfCommand,
		"interface-ips":  apiInterfaceIPsCommand,
		"forwards":       apiForwardsCommand,
		"add-forward":    apiAddForwardCommand,
		"remove-forward": apiRemoveForwardCommand,
		"resolve":        apiResolveCommand,
		"dig":            apiResolveCommand,
	}
	fn, ok := commands[args[0]]
	if !ok {
		return false, nil
	}
	return true, fn(args[1:])
}

func apiFlagSet(name string) (*flag.FlagSet, *apiClientOptions) {
	opts := &apiClientOptions{
		endpoint: os.Getenv("UWGS_API"),
		token:    os.Getenv("UWGS_API_TOKEN"),
	}
	if opts.endpoint == "" {
		opts.endpoint = "http://127.0.0.1:9090"
	}
	fs := flag.NewFlagSet("uwgsocks "+name, flag.ContinueOnError)
	fs.StringVar(&opts.endpoint, "api", opts.endpoint, "API endpoint, e.g. http://127.0.0.1:9090 or unix:/run/uwgsocks/api.sock")
	fs.StringVar(&opts.token, "token", opts.token, "API bearer token, default from UWGS_API_TOKEN")
	return fs, opts
}

func (o apiClientOptions) request(method, path, contentType string, body []byte) ([]byte, error) {
	base := o.endpoint
	transport := http.DefaultTransport
	if strings.HasPrefix(base, "unix:") {
		socket := strings.TrimPrefix(base, "unix:")
		base = "http://uwg"
		transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}
	} else if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.JoinPath(base, path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(path, "?") {
		u = strings.TrimRight(base, "/") + path
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(out) == 0 {
			return nil, fmt.Errorf("API returned %s", resp.Status)
		}
		return nil, fmt.Errorf("API returned %s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func printAPIResponse(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	_, err := os.Stdout.Write(body)
	if err == nil && !bytes.HasSuffix(body, []byte("\n")) {
		_, err = fmt.Fprintln(os.Stdout)
	}
	return err
}

func apiStatusCommand(args []string) error {
	fs, opts := apiFlagSet("status")
	text := fs.Bool("text", false, "print a terminal-friendly peer table instead of raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := opts.request(http.MethodGet, "/v1/status", "", nil)
	if err != nil {
		return err
	}
	if *text {
		var st statusView
		if err := json.Unmarshal(body, &st); err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, renderStatusText(st))
		return err
	}
	return printAPIResponse(body)
}

func apiPingCommand(args []string) error {
	fs, opts := apiFlagSet("ping")
	count := fs.Int("count", 4, "ICMP echo count")
	timeoutMS := fs.Int("timeout-ms", 1000, "per-echo timeout in milliseconds")
	target := fs.String("target", "", "target IP or hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" && fs.NArg() > 0 {
		*target = fs.Arg(0)
	}
	if *target == "" {
		return fmt.Errorf("ping target is required")
	}
	path := fmt.Sprintf("/v1/ping?target=%s&count=%d&timeout_ms=%d", url.QueryEscape(*target), *count, *timeoutMS)
	body, err := opts.request(http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	return printAPIResponse(body)
}

func apiPeersCommand(args []string) error {
	fs, opts := apiFlagSet("peers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := opts.request(http.MethodGet, "/v1/peers", "", nil)
	if err != nil {
		return err
	}
	return printAPIResponse(body)
}

func apiAddPeerCommand(args []string) error {
	fs, opts := apiFlagSet("add-peer")
	var allowed listFlag
	publicKey := fs.String("public-key", "", "peer public key")
	presharedKey := fs.String("preshared-key", "", "optional preshared key")
	endpoint := fs.String("endpoint", "", "optional endpoint host:port")
	keepalive := fs.Int("keepalive", 0, "persistent keepalive seconds")
	fs.Var(&allowed, "allowed-ip", "peer AllowedIPs entry; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *publicKey == "" {
		return fmt.Errorf("--public-key is required")
	}
	req := map[string]any{
		"public_key":           *publicKey,
		"preshared_key":        *presharedKey,
		"endpoint":             *endpoint,
		"allowed_ips":          []string(allowed),
		"persistent_keepalive": *keepalive,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	out, err := opts.request(http.MethodPost, "/v1/peers", "application/json", body)
	if err != nil {
		return err
	}
	return printAPIResponse(out)
}

func apiRemovePeerCommand(args []string) error {
	fs, opts := apiFlagSet("remove-peer")
	publicKey := fs.String("public-key", "", "peer public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *publicKey == "" && fs.NArg() > 0 {
		*publicKey = fs.Arg(0)
	}
	if *publicKey == "" {
		return fmt.Errorf("public key is required")
	}
	_, err := opts.request(http.MethodDelete, "/v1/peers?public_key="+url.QueryEscape(*publicKey), "", nil)
	return err
}

func apiACLListCommand(args []string) error {
	fs, opts := apiFlagSet("acl-list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := "/v1/acls"
	if fs.NArg() > 0 {
		path = "/v1/acls/" + fs.Arg(0)
	}
	body, err := opts.request(http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	return printAPIResponse(body)
}

func apiACLAddCommand(args []string) error {
	fs, opts := apiFlagSet("acl-add")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: uwgsocks acl-add <inbound|outbound|relay> '<rule>'")
	}
	name := fs.Arg(0)
	rule, err := acl.ParseRule(strings.Join(fs.Args()[1:], " "))
	if err != nil {
		return err
	}
	body, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	out, err := opts.request(http.MethodPost, "/v1/acls/"+name, "application/json", body)
	if err != nil {
		return err
	}
	return printAPIResponse(out)
}

func apiACLRemoveCommand(args []string) error {
	fs, opts := apiFlagSet("acl-remove")
	index := fs.Int("index", -1, "ACL rule index")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || *index < 0 {
		return fmt.Errorf("usage: uwgsocks acl-remove <inbound|outbound|relay> --index N")
	}
	_, err := opts.request(http.MethodDelete, fmt.Sprintf("/v1/acls/%s?index=%d", fs.Arg(0), *index), "", nil)
	return err
}

func apiACLSetCommand(args []string) error {
	fs, opts := apiFlagSet("acl-set")
	file := fs.String("file", "", "JSON file containing an array of ACL rules, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: uwgsocks acl-set <inbound|outbound|relay> --file rules.json")
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	var body []byte
	var err error
	if *file == "-" {
		body, err = io.ReadAll(os.Stdin)
	} else {
		body, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	_, err = opts.request(http.MethodPut, "/v1/acls/"+fs.Arg(0), "application/json", body)
	return err
}

func apiWGSetConfCommand(args []string) error {
	fs, opts := apiFlagSet("wg-setconf")
	file := fs.String("file", "", "wg-quick config file, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" && fs.NArg() > 0 {
		*file = fs.Arg(0)
	}
	if *file == "" {
		return fmt.Errorf("wg-setconf requires --file PATH, PATH, or - for stdin")
	}
	var body []byte
	var err error
	if *file == "-" {
		body, err = io.ReadAll(os.Stdin)
	} else {
		body, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	_, err = opts.request(http.MethodPut, "/v1/wireguard/config", "text/plain", body)
	return err
}

func apiInterfaceIPsCommand(args []string) error {
	fs, opts := apiFlagSet("interface-ips")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := opts.request(http.MethodGet, "/v1/interface_ips", "", nil)
	if err != nil {
		return err
	}
	return printAPIResponse(body)
}

func apiForwardsCommand(args []string) error {
	fs, opts := apiFlagSet("forwards")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := opts.request(http.MethodGet, "/v1/forwards", "", nil)
	if err != nil {
		return err
	}
	return printAPIResponse(body)
}

func apiAddForwardCommand(args []string) error {
	fs, opts := apiFlagSet("add-forward")
	reverse := fs.Bool("reverse", false, "create a reverse forward inside the WireGuard netstack")
	proto := fs.String("proto", "tcp", "tcp or udp")
	listen := fs.String("listen", "", "listen address")
	target := fs.String("target", "", "target address")
	proxyProtocol := fs.String("proxy-protocol", "", "optional PROXY protocol version: v1 or v2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *listen == "" || *target == "" {
		return fmt.Errorf("--listen and --target are required")
	}
	req := map[string]any{
		"reverse":        *reverse,
		"proto":          *proto,
		"listen":         *listen,
		"target":         *target,
		"proxy_protocol": *proxyProtocol,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	out, err := opts.request(http.MethodPost, "/v1/forwards", "application/json", body)
	if err != nil {
		return err
	}
	return printAPIResponse(out)
}

func apiRemoveForwardCommand(args []string) error {
	fs, opts := apiFlagSet("remove-forward")
	name := fs.String("name", "", "forward name returned by add-forward or forwards")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" && fs.NArg() > 0 {
		*name = fs.Arg(0)
	}
	if *name == "" {
		return fmt.Errorf("forward name is required")
	}
	_, err := opts.request(http.MethodDelete, "/v1/forwards?name="+url.QueryEscape(*name), "", nil)
	return err
}

// requestDoH POSTs a binary DNS message to /uwg/resolve. /uwg/resolve is
// exposed on both the admin API listener (as an alias of /v1/resolve) and the
// HTTP proxy listener, so this works against either via --api.
//
// To stay listener-agnostic the same token is sent two ways:
//   - Authorization: Bearer <token>          (admin listener)
//   - Proxy-Authorization: Basic _:<token>   (HTTP proxy listener, with the
//     empty username path enabled by the optional-proxy-username change)
//
// Whichever listener handles the request picks the header it cares about; the
// other is ignored.
func (o apiClientOptions) requestDoH(ctx context.Context, query []byte) ([]byte, error) {
	base := o.endpoint
	transport := http.DefaultTransport
	if strings.HasPrefix(base, "unix:") {
		socket := strings.TrimPrefix(base, "unix:")
		base = "http://uwg"
		transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}
	} else if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	endpoint := strings.TrimRight(base, "/") + "/uwg/resolve"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
		basic := base64Std.EncodeToString([]byte(":" + o.token))
		req.Header.Set("Proxy-Authorization", "Basic "+basic)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DoH request returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("DoH response Content-Type = %q, want application/dns-message", ct)
	}
	return body, nil
}

func apiResolveCommand(args []string) error {
	fs, opts := apiFlagSet("resolve")
	qtype := fs.String("type", "A", "DNS record type (A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV, ANY)")
	timeoutS := fs.Int("timeout", 10, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: uwgsocks resolve [--api URL] [--token TOKEN] [--type TYPE] NAME")
	}
	name := dns.Fqdn(fs.Arg(0))
	rrtype, ok := dns.StringToType[strings.ToUpper(*qtype)]
	if !ok {
		return fmt.Errorf("unknown DNS type %q", *qtype)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, rrtype)
	msg.RecursionDesired = true
	wire, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("build DNS query: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutS)*time.Second)
	defer cancel()
	body, err := opts.requestDoH(ctx, wire)
	if err != nil {
		return err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return fmt.Errorf("parse DNS response: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		fmt.Fprintf(os.Stdout, ";; status: %s\n", dns.RcodeToString[resp.Rcode])
	}
	for _, q := range resp.Question {
		fmt.Fprintf(os.Stdout, ";; QUESTION: %s %s %s\n", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
	}
	if len(resp.Answer) == 0 {
		fmt.Fprintln(os.Stdout, ";; ANSWER: (none)")
		return nil
	}
	fmt.Fprintln(os.Stdout, ";; ANSWER:")
	for _, rr := range resp.Answer {
		fmt.Fprintln(os.Stdout, rr.String())
	}
	return nil
}
