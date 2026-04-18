// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"time"
)

// CertManager manages a TLS certificate for server-mode transports.  When
// CertFile and KeyFile are empty it auto-generates an ephemeral self-signed
// ECDSA P-256 certificate.  When they are set it loads from disk and
// optionally reloads on a configured interval so that externally renewed
// certificates (e.g. from certbot) are picked up without a restart.
type CertManager struct {
	CertFile       string
	KeyFile        string
	ReloadInterval time.Duration

	mu      sync.RWMutex
	current *tls.Certificate
}

// Start initialises the certificate.  For auto-generated certs this happens
// once; for file-based certs the goroutine polls for renewal until ctx is
// cancelled.
func (m *CertManager) Start() error {
	cert, err := m.load()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.current = cert
	m.mu.Unlock()

	if m.CertFile != "" && m.ReloadInterval > 0 {
		go m.reloadLoop()
	}
	return nil
}

func (m *CertManager) reloadLoop() {
	t := time.NewTicker(m.ReloadInterval)
	defer t.Stop()
	for range t.C {
		cert, err := m.load()
		if err != nil {
			continue
		}
		m.mu.Lock()
		m.current = cert
		m.mu.Unlock()
	}
}

// GetCertificate is suitable for use as tls.Config.GetCertificate.
func (m *CertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	c := m.current
	m.mu.RUnlock()
	if c == nil {
		return nil, nil
	}
	return c, nil
}

// TLSConfig returns a *tls.Config suitable for use as a server TLS config.
func (m *CertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
	}
}

func (m *CertManager) load() (*tls.Certificate, error) {
	if m.CertFile == "" {
		return generateSelfSigned()
	}
	cert, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// generateSelfSigned creates a new ephemeral ECDSA P-256 self-signed
// certificate valid for 10 years.
func generateSelfSigned() (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "uwgsocks-transport"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// loadCertPoolFromFile loads a PEM-encoded certificate pool from disk.
// Returns nil (use system pool) when path is empty.
func loadCertPoolFromFile(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, os.ErrInvalid
	}
	return pool, nil
}
