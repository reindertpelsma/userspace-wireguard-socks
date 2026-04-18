// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	piondtls "github.com/pion/dtls/v3"
)

func buildCertManager(tlsCfg TLSConfig, autoGenerate bool) (*CertManager, error) {
	if err := tlsCfg.validateClientCertFiles(); err != nil {
		return nil, err
	}
	if !autoGenerate && tlsCfg.CertFile == "" {
		return nil, nil
	}
	reload, err := parseTLSReloadInterval(tlsCfg.ReloadInterval)
	if err != nil {
		return nil, err
	}
	mgr := &CertManager{
		CertFile:       tlsCfg.CertFile,
		KeyFile:        tlsCfg.KeyFile,
		ReloadInterval: reload,
		AutoGenerate:   autoGenerate,
	}
	if err := mgr.Start(); err != nil {
		return nil, fmt.Errorf("cert manager: %w", err)
	}
	return mgr, nil
}

func parseTLSReloadInterval(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("tls.reload_interval: %w", err)
	}
	return d, nil
}

func buildTLSServerConfig(tlsCfg TLSConfig, certMgr *CertManager) (*tls.Config, error) {
	if certMgr == nil {
		return nil, errors.New("tls: server certificate manager is required")
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certMgr.GetCertificate,
	}
	if !tlsCfg.verifyPeerOr(false) {
		cfg.ClientAuth = tls.NoClientCert
		return cfg, nil
	}
	if tlsCfg.CAFile == "" {
		return nil, errors.New("tls: ca_file is required when verify_peer is true for servers")
	}
	pool, err := loadCertPoolFromFile(tlsCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tls ca_file: %w", err)
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}

func buildTLSClientConfig(tlsCfg TLSConfig, certMgr *CertManager, defaultServerName string, defaultVerifyPeer bool) (*tls.Config, error) {
	verifyPeer := tlsCfg.verifyPeerOr(defaultVerifyPeer)
	roots, err := loadCertPoolFromFile(tlsCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tls ca_file: %w", err)
	}
	serverName, sendSNI := tlsCfg.ServerSNI.resolve(defaultServerName)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	if certMgr != nil {
		cfg.GetClientCertificate = certMgr.GetClientCertificate
	}
	if sendSNI {
		cfg.ServerName = serverName
	}
	if !verifyPeer {
		cfg.InsecureSkipVerify = true //nolint:gosec
		return cfg, nil
	}
	if sendSNI {
		return cfg, nil
	}
	cfg.InsecureSkipVerify = true //nolint:gosec
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return verifyX509PeerCertificates(cs.PeerCertificates, roots, defaultServerName, x509.ExtKeyUsageServerAuth)
	}
	return cfg, nil
}

func buildDTLSServerConfig(tlsCfg TLSConfig, certMgr *CertManager) (*piondtls.Config, error) {
	if certMgr == nil {
		return nil, errors.New("dtls: server certificate manager is required")
	}
	cfg := &piondtls.Config{
		GetCertificate: certMgr.GetDTLSCertificate,
	}
	if cert, err := certMgr.CurrentCertificate(); err == nil && cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if !tlsCfg.verifyPeerOr(false) {
		cfg.ClientAuth = piondtls.NoClientCert
		return cfg, nil
	}
	if tlsCfg.CAFile == "" {
		return nil, errors.New("dtls: ca_file is required when verify_peer is true for servers")
	}
	pool, err := loadCertPoolFromFile(tlsCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("dtls ca_file: %w", err)
	}
	cfg.ClientAuth = piondtls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}

func buildDTLSClientConfig(tlsCfg TLSConfig, certMgr *CertManager, defaultServerName string, defaultVerifyPeer bool) (*piondtls.Config, error) {
	verifyPeer := tlsCfg.verifyPeerOr(defaultVerifyPeer)
	roots, err := loadCertPoolFromFile(tlsCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("dtls ca_file: %w", err)
	}
	serverName, sendSNI := tlsCfg.ServerSNI.resolve(defaultServerName)
	cfg := &piondtls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: !verifyPeer,
	}
	if certMgr != nil {
		if cert, err := certMgr.CurrentCertificate(); err == nil && cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		cfg.GetClientCertificate = certMgr.GetDTLSClientCertificate
	}
	if sendSNI {
		cfg.ServerName = serverName
	}
	if !verifyPeer || sendSNI {
		return cfg, nil
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(state *piondtls.State) error {
		certs, err := parseRawPeerCertificates(state.PeerCertificates)
		if err != nil {
			return err
		}
		return verifyX509PeerCertificates(certs, roots, defaultServerName, x509.ExtKeyUsageServerAuth)
	}
	return cfg, nil
}

func verifyX509PeerCertificates(peerCerts []*x509.Certificate, roots *x509.CertPool, verifyName string, usage x509.ExtKeyUsage) error {
	if len(peerCerts) == 0 {
		return errors.New("tls: peer did not present a certificate")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}
	for _, cert := range peerCerts[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := peerCerts[0].Verify(opts); err != nil {
		return err
	}
	if verifyName != "" && usage == x509.ExtKeyUsageServerAuth {
		return peerCerts[0].VerifyHostname(verifyName)
	}
	return nil
}

func parseRawPeerCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("dtls: peer did not present a certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
