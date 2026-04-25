package engine_test

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// Smoke-test the `uwgsocks resolve` CLI subcommand against a live engine.
// We start an engine with both an api listener and an http proxy listener,
// then exercise the CLI against each — verifying /uwg/resolve works on both
// listeners with one binary + one --token. RFC 8484 DoH wire compatibility.
func TestUwgsocksResolveSubcommandWorksOnBothListeners(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	repoRoot, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	repo := strings.TrimSpace(string(repoRoot))

	binDir := t.TempDir()
	binName := "uwgsocks-resolve-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(binDir, binName)
	build := exec.Command("go", "build", "-o", binPath, "./cmd/uwgsocks")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.Proxy.Password = "secret"
	eng := mustStart(t, cfg)
	defer eng.Close()

	for _, target := range []string{eng.Addr("api"), eng.Addr("http")} {
		t.Run(target, func(t *testing.T) {
			cmd := exec.Command(binPath,
				"resolve",
				"--api", "http://"+target,
				"--token", "secret",
				"--type", "A",
				"--timeout", "5",
				"localhost",
			)
			out, err := cmd.CombinedOutput()
			outStr := string(out)
			// Some CI runners (notably the GitHub Windows image) have no
			// system DNS resolvers configured, so the daemon's
			// exchangeSystemDNSPacket returns 502 "no system DNS servers".
			// That still proves the CLI plumbing works end-to-end (auth
			// headers accepted, DoH wire format round-tripped, the right
			// listener handled the request) — the missing piece is upstream
			// DNS, which is environmental, not a code issue.
			if err != nil && strings.Contains(outStr, "no system DNS servers") {
				t.Skipf("no system DNS configured on this runner; CLI plumbing reached the daemon and was rejected upstream:\n%s", outStr)
			}
			if err != nil {
				t.Fatalf("uwgsocks resolve failed: %v\n%s", err, outStr)
			}
			lower := strings.ToLower(outStr)
			if !strings.Contains(lower, "answer") {
				t.Fatalf("expected ANSWER section in output:\n%s", outStr)
			}
			if !strings.Contains(lower, "127.0.0.1") && !strings.Contains(lower, "::1") {
				t.Logf("note: localhost did not resolve to loopback in test env, output:\n%s", outStr)
			}
		})
	}
	_ = url.PathEscape
	_ = os.Stdout
}
