package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

func TestExamplesNormalize(t *testing.T) {
	if !testconfig.Get().Examples {
		t.Skip("set UWG_TEST_EXAMPLES=1 or -uwgs-examples to validate shipped example configs")
	}
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir %s: %v", repoRoot, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})
	paths := []string{
		"examples/client.yaml",
		"examples/exit-client.yaml",
		"examples/exit-server.yaml",
		"examples/forwarding.yaml",
		"examples/mesh-control-hub.yaml",
		"examples/mesh-control-peer.yaml",
		"examples/multi-peer.yaml",
		"examples/relay-acls.yaml",
		"examples/server.yaml",
		"examples/socksify.yaml",
		"examples/transport-http-quic.yaml",
		"examples/turn-server.yaml",
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("load %s: %v", path, err)
			}
			if cfg.WireGuard.PrivateKey == "" && cfg.WireGuard.ConfigFile == "" && cfg.WireGuard.Config == "" {
				t.Fatalf("%s produced no wireguard config", path)
			}
		})
	}
}

func TestExampleWGQuickFilesParse(t *testing.T) {
	if !testconfig.Get().Examples {
		t.Skip("set UWG_TEST_EXAMPLES=1 or -uwgs-examples to validate shipped example configs")
	}
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir %s: %v", repoRoot, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})
	paths := []string{"examples/client.conf", "examples/server.conf"}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var wg config.WireGuard
			if err := config.MergeWGQuick(&wg, string(b)); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if strings.TrimSpace(wg.PrivateKey) == "" {
				t.Fatalf("%s produced empty private key", path)
			}
		})
	}
}
