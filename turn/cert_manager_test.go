package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTurnCertManagerAutoGenerate(t *testing.T) {
	mgr, err := newTurnCertManager(TURNListenerConfig{
		Type:   "tls",
		Listen: "127.0.0.1:3478",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	cert, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected generated certificate")
	}
}

func TestTurnCertManagerReloadsFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "turn.crt")
	keyPath := filepath.Join(dir, "turn.key")

	if err := writeTestCertPair(certPath, keyPath, 1); err != nil {
		t.Fatal(err)
	}

	mgr, err := newTurnCertManager(TURNListenerConfig{
		Type:           "tls",
		Listen:         "127.0.0.1:3478",
		CertFile:       certPath,
		KeyFile:        keyPath,
		ReloadInterval: "20ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	initialSerial := certificateSerial(t, mgr)
	if initialSerial.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("unexpected initial serial %s", initialSerial)
	}

	if err := writeTestCertPair(certPath, keyPath, 2); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if serial := certificateSerial(t, mgr); serial.Cmp(big.NewInt(2)) == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("certificate manager did not reload updated certificate")
}

func certificateSerial(t *testing.T, mgr *turnCertManager) *big.Int {
	t.Helper()
	cert, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected loaded certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber
}

func writeTestCertPair(certPath, keyPath string, serial int64) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: "turn-test",
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}
