package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v3"
)

type turnCertManager struct {
	CertFile       string
	KeyFile        string
	ReloadInterval time.Duration

	mu      sync.RWMutex
	current *tls.Certificate

	stopOnce sync.Once
	stopCh   chan struct{}
}

func newTurnCertManager(cfg TURNListenerConfig) (*turnCertManager, error) {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("listener %q: cert_file and key_file must both be set", cfg.Listen)
	}
	reload := time.Duration(0)
	if cfg.ReloadInterval != "" {
		d, err := time.ParseDuration(cfg.ReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("listener %q reload_interval: %w", cfg.Listen, err)
		}
		reload = d
	} else if cfg.CertFile != "" {
		reload = time.Minute
	}
	mgr := &turnCertManager{
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
		ReloadInterval: reload,
		stopCh:         make(chan struct{}),
	}
	if err := mgr.Start(); err != nil {
		return nil, err
	}
	return mgr, nil
}

func (m *turnCertManager) Start() error {
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

func (m *turnCertManager) reloadLoop() {
	ticker := time.NewTicker(m.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cert, err := m.load()
			if err != nil {
				continue
			}
			m.mu.Lock()
			m.current = cert
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *turnCertManager) Close() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

func (m *turnCertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return nil, nil
	}
	return m.current, nil
}

func (m *turnCertManager) GetDTLSCertificate(_ *piondtls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.GetCertificate(nil)
}

func (m *turnCertManager) CurrentCertificate() (*tls.Certificate, error) {
	return m.GetCertificate(nil)
}

func (m *turnCertManager) load() (*tls.Certificate, error) {
	if m.CertFile == "" {
		return generateTurnSelfSigned()
	}
	cert, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func generateTurnSelfSigned() (*tls.Certificate, error) {
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
		Subject:      pkix.Name{CommonName: "turn-open-relay"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

func buildTurnTLSServerConfig(cfg TURNListenerConfig, certMgr *turnCertManager) (*tls.Config, error) {
	if certMgr == nil {
		return nil, fmt.Errorf("listener %q: certificate manager is required", cfg.Listen)
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certMgr.GetCertificate,
	}
	if !cfg.VerifyPeer {
		tlsCfg.ClientAuth = tls.NoClientCert
		return tlsCfg, nil
	}
	if cfg.CAFile == "" {
		return nil, fmt.Errorf("listener %q: ca_file is required when verify_peer is true", cfg.Listen)
	}
	pool, err := loadTurnCertPoolFromFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("listener %q ca_file: %w", cfg.Listen, err)
	}
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = pool
	return tlsCfg, nil
}

func buildTurnDTLSServerConfig(cfg TURNListenerConfig, certMgr *turnCertManager) (*piondtls.Config, error) {
	if certMgr == nil {
		return nil, fmt.Errorf("listener %q: certificate manager is required", cfg.Listen)
	}
	dtlsCfg := &piondtls.Config{
		GetCertificate: certMgr.GetDTLSCertificate,
	}
	if cert, err := certMgr.CurrentCertificate(); err == nil && cert != nil {
		dtlsCfg.Certificates = []tls.Certificate{*cert}
	}
	if !cfg.VerifyPeer {
		dtlsCfg.ClientAuth = piondtls.NoClientCert
		return dtlsCfg, nil
	}
	if cfg.CAFile == "" {
		return nil, fmt.Errorf("listener %q: ca_file is required when verify_peer is true", cfg.Listen)
	}
	pool, err := loadTurnCertPoolFromFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("listener %q ca_file: %w", cfg.Listen, err)
	}
	dtlsCfg.ClientAuth = piondtls.RequireAndVerifyClientCert
	dtlsCfg.ClientCAs = pool
	return dtlsCfg, nil
}

func loadTurnCertPoolFromFile(path string) (*x509.CertPool, error) {
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
