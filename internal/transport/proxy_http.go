// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
)

// HTTPConnectDialer implements ProxyDialer by issuing HTTP CONNECT requests.
// It only supports TCP streams; UDP (DialPacket) returns ErrUDPNotSupported.
//
// Certificate validation behaviour when reaching the proxy over HTTPS:
//   - If no credentials are set: InsecureSkipVerify=true (default).
//   - If credentials are set:    InsecureSkipVerify=false (default).
//   - ValidateCert overrides both defaults when non-nil.
type HTTPConnectDialer struct {
	// Server is the proxy host:port.
	Server string
	// HTTPS wraps the connection to the proxy in TLS.
	HTTPS bool
	// Username and Password for Proxy-Authorization.
	Username, Password string
	// ValidateCert overrides default certificate validation behaviour.
	// nil = use the credential-based default.
	ValidateCert *bool
}

// NewHTTPConnectDialer creates an HTTPConnectDialer.  scheme should be "http"
// or "https"; the HTTPS flag is set automatically.
func NewHTTPConnectDialer(server, scheme, username, password string, validateCert *bool) (*HTTPConnectDialer, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nil, fmt.Errorf("http proxy: invalid server address %q: %w", server, err)
	}
	return &HTTPConnectDialer{
		Server:       server,
		HTTPS:        scheme == "https",
		Username:     username,
		Password:     password,
		ValidateCert: validateCert,
	}, nil
}

// DialContext connects to addr via HTTP CONNECT through the proxy.
func (d *HTTPConnectDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	// 1. Connect to the proxy itself.
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", d.Server)
	if err != nil {
		return nil, fmt.Errorf("http proxy: connect to %s: %w", d.Server, err)
	}

	// 2. Optionally wrap in TLS for HTTPS proxies.
	var conn net.Conn = raw
	if d.HTTPS {
		skip := d.skipVerify()
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:         serverName(d.Server),
			InsecureSkipVerify: skip, //nolint:gosec
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("http proxy: TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// 3. Send CONNECT request.
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+addr, nil)
	req.Host = addr
	if d.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(d.Username + ":" + d.Password))
		req.Header.Set("Proxy-Authorization", "Basic "+creds)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy: send CONNECT: %w", err)
	}

	// 4. Read response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy: read CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("http proxy: CONNECT %s: %s", addr, resp.Status)
	}

	// Return the tunnel connection.  If the bufio reader buffered any bytes
	// wrap conn so they are not lost.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// DialPacket is not supported by HTTP CONNECT proxies.
func (d *HTTPConnectDialer) DialPacket(_ context.Context, _ string) (net.PacketConn, string, error) {
	return nil, "", ErrUDPNotSupported
}

// SupportsHostname returns true; HTTP CONNECT forwards the hostname verbatim.
func (d *HTTPConnectDialer) SupportsHostname() bool { return true }

func (d *HTTPConnectDialer) skipVerify() bool {
	if d.ValidateCert != nil {
		return !*d.ValidateCert
	}
	return d.Username == "" // skip when no credentials
}

// serverName extracts the host portion for SNI.
func serverName(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// bufferedConn wraps a net.Conn with a bufio.Reader that may hold leftover
// bytes from the HTTP header parsing.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
