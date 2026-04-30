// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package testconfig provides a unified test-gating and configuration system
// for the uwgsocks test suite.
//
// Configuration is resolved in priority order:
//  1. CLI flags passed via go test -args (e.g. -args -uwgs-all)
//  2. Environment variables (UWGS_* / UWG_TEST_* as documented below)
//  3. Built-in defaults (all gates disabled)
//
// Usage in test files:
//
//	func TestFoo(t *testing.T) {
//	    cfg := testconfig.Get()
//	    if !cfg.RealTUN {
//	        t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run")
//	    }
//	}
//
// To run all gated tests at once:
//
//	go test ./... -args -uwgs-all
//
// All existing UWGS_* / UWG_TEST_* environment variable names continue to
// work as before for backward compatibility with CI scripts and shell aliases.
package testconfig

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Config holds the resolved test configuration.
type Config struct {
	// All enables every gated test unconditionally.
	// Flag: -uwgs-all  Env: UWGS_ALL
	All bool

	// RealTUN enables tests that create real kernel TUN devices (requires root/NET_ADMIN).
	// Flag: -uwgs-real-tun  Env: UWG_TEST_REAL_TUN
	RealTUN bool

	// RealTUNDefault enables the "default name" real-TUN test variant.
	// Flag: -uwgs-real-tun-default  Env: UWG_TEST_REAL_TUN_DEFAULT
	RealTUNDefault bool

	// Soak enables long-running soak tests.
	// Flag: -uwgs-soak  Env: UWGS_SOAK
	Soak bool

	// SoakSeconds overrides the soak test duration in seconds (0 = use test default).
	// Flag: -uwgs-soak-seconds  Env: UWGS_SOAK_SECONDS
	SoakSeconds int

	// Stress enables stress/load tests.
	// Flag: -uwgs-stress  Env: UWGS_STRESS
	Stress bool

	// MeshChaos enables the mesh-control chaos suite (long-running, Tier 3).
	// Flag: -uwgs-mesh-chaos  Env: UWGS_RUN_MESH_CHAOS
	MeshChaos bool

	// TransportSoak enables the adversarial transport soak test.
	// Flag: -uwgs-transport-soak  Env: UWGS_TRANSPORT_SOAK
	TransportSoak bool

	// TransportSoakSeconds overrides the transport soak duration (0 = use test default).
	// Flag: -uwgs-transport-soak-seconds  Env: UWGS_TRANSPORT_SOAK_SECONDS
	TransportSoakSeconds int

	// Perf enables the performance/throughput benchmark tests.
	// Flag: -uwgs-perf  Env: UWGS_PERF
	Perf bool

	// StdioHeavyDiag enables the stdio-heavy combination diagnostic test.
	// Flag: -uwgs-stdio-heavy-diag  Env: UWGS_RUN_STDIO_HEAVY_DIAG
	StdioHeavyDiag bool

	// StrictStdioHotpath causes the stdio-heavy test to fail if the workload
	// introduces any new traced syscalls beyond the startup baseline.
	// Flag: -uwgs-strict-stdio-hotpath  Env: UWGS_STRICT_STDIO_HOTPATH
	StrictStdioHotpath bool

	// PtraceThreadedDeath enables the ptrace threaded-death diagnostic test.
	// Flag: -uwgs-ptrace-threaded-death  Env: UWGS_RUN_PTRACE_THREADED_DEATH
	PtraceThreadedDeath bool

	// ChromeSmoke enables the headless Chrome smoke test.
	// Flag: -uwgs-chrome-smoke  Env: UWGS_RUN_HEADLESS_CHROME_SMOKE
	ChromeSmoke bool

	// ChromiumSupervised enables the systrap-supervised Chromium test.
	// Flag: -uwgs-chromium-supervised  Env: UWGS_RUN_CHROMIUM_SUPERVISED
	ChromiumSupervised bool

	// ChromiumRealInet enables the Chromium real-internet test.
	// Flag: -uwgs-chromium-real-inet  Env: UWGS_RUN_CHROMIUM_REAL_INTERNET
	ChromiumRealInet bool

	// Phase1ChromeSmoke enables the Phase 1 headless Chrome smoke test.
	// Flag: -uwgs-phase1-chrome-smoke  Env: UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE
	Phase1ChromeSmoke bool

	// Phase2Diag enables the Phase 2 natural-exit hang diagnostic.
	// Flag: -uwgs-phase2-diag  Env: UWG_PHASE2_DIAG
	Phase2Diag bool

	// Examples enables the config examples validation tests.
	// Flag: -uwgs-examples  Env: UWG_TEST_EXAMPLES
	Examples bool

	// Verbose enables verbose wrapper subprocess output (adds -v to stub args).
	// Flag: -uwgs-verbose  Env: UWGS_TEST_DEBUG
	Verbose bool

	// VerboseStress enables verbose output for stress sub-tests only.
	// Flag: -uwgs-verbose-stress  Env: UWGS_TEST_DEBUG_STRESS
	VerboseStress bool

	// ChromeBin is the path to the Chrome/Chromium binary.
	// Flag: -uwgs-chrome-bin  Env: UWGS_CHROME_BIN
	ChromeBin string

	// BrowserSmokeTransport is the wrapper transport to use for browser smoke tests.
	// Flag: -uwgs-browser-smoke-transport  Env: UWGS_BROWSER_SMOKE_TRANSPORT
	BrowserSmokeTransport string
}

// Flags registered at init time so that go test -args can override them.
// All default to zero; env vars are merged in Get() after flag.Parse() runs.
var (
	flagAll                   = flag.Bool("uwgs-all", false, "enable all gated tests unconditionally")
	flagRealTUN               = flag.Bool("uwgs-real-tun", false, "run real host-TUN tests (requires root/NET_ADMIN)")
	flagRealTUNDefault        = flag.Bool("uwgs-real-tun-default", false, "run default-name real-TUN test variant")
	flagSoak                  = flag.Bool("uwgs-soak", false, "run long-running soak tests")
	flagSoakSeconds           = flag.Int("uwgs-soak-seconds", 0, "soak test duration override in seconds")
	flagStress                = flag.Bool("uwgs-stress", false, "run stress/load tests")
	flagMeshChaos             = flag.Bool("uwgs-mesh-chaos", false, "run mesh-control chaos suite (Tier 3)")
	flagTransportSoak         = flag.Bool("uwgs-transport-soak", false, "run adversarial transport soak test")
	flagTransportSoakSeconds  = flag.Int("uwgs-transport-soak-seconds", 0, "transport soak duration override in seconds")
	flagPerf                  = flag.Bool("uwgs-perf", false, "run performance/throughput tests")
	flagStdioHeavyDiag        = flag.Bool("uwgs-stdio-heavy-diag", false, "run stdio-heavy diagnostic test")
	flagStrictStdioHotpath    = flag.Bool("uwgs-strict-stdio-hotpath", false, "fail if workload adds traced syscalls beyond baseline")
	flagPtraceThreadedDeath   = flag.Bool("uwgs-ptrace-threaded-death", false, "run ptrace threaded-death diagnostic")
	flagChromeSmoke           = flag.Bool("uwgs-chrome-smoke", false, "run headless Chrome smoke test")
	flagChromiumSupervised    = flag.Bool("uwgs-chromium-supervised", false, "run systrap-supervised Chromium test")
	flagChromiumRealInet      = flag.Bool("uwgs-chromium-real-inet", false, "run Chromium real-internet test")
	flagPhase1ChromeSmoke     = flag.Bool("uwgs-phase1-chrome-smoke", false, "run Phase 1 headless Chrome smoke test")
	flagPhase2Diag            = flag.Bool("uwgs-phase2-diag", false, "run Phase 2 natural-exit hang diagnostic")
	flagExamples              = flag.Bool("uwgs-examples", false, "run config examples validation tests")
	flagVerbose               = flag.Bool("uwgs-verbose", false, "enable verbose wrapper subprocess output")
	flagVerboseStress         = flag.Bool("uwgs-verbose-stress", false, "enable verbose output for stress sub-tests")
	flagChromeBin             = flag.String("uwgs-chrome-bin", "", "path to Chrome/Chromium binary")
	flagBrowserSmokeTransport = flag.String("uwgs-browser-smoke-transport", "", "wrapper transport for browser smoke tests")
)

var (
	once   sync.Once
	cached Config
)

// Get returns the resolved test configuration. It is safe to call from any
// test function; it must not be called from package-level var initialisers or
// init() functions (flag.Parse has not run yet at that point).
//
// The first call resolves and caches the configuration; subsequent calls return
// the cached value.
func Get() Config {
	once.Do(resolve)
	return cached
}

func resolve() {
	// Start from env vars.
	var cfg Config
	applyEnv(&cfg)

	// Apply CLI flags that were explicitly set on the command line
	// (flag.Visit visits only flags set via -args, overriding env vars).
	flag.Visit(func(f *flag.Flag) {
		applyFlag(&cfg, f)
	})

	// If -uwgs-all was set (via flag or env), enable all boolean gates.
	if cfg.All {
		enableAll(&cfg)
	}

	cached = cfg
}

func applyEnv(cfg *Config) {
	if envBool("UWGS_ALL") {
		cfg.All = true
	}
	if envBool("UWG_TEST_REAL_TUN") {
		cfg.RealTUN = true
	}
	if envBool("UWG_TEST_REAL_TUN_DEFAULT") {
		cfg.RealTUNDefault = true
	}
	if envBool("UWGS_SOAK") {
		cfg.Soak = true
	}
	if s := envInt("UWGS_SOAK_SECONDS"); s > 0 {
		cfg.SoakSeconds = s
	}
	if envBool("UWGS_STRESS") {
		cfg.Stress = true
	}
	if envBool("UWGS_RUN_MESH_CHAOS") {
		cfg.MeshChaos = true
	}
	if envBool("UWGS_TRANSPORT_SOAK") {
		cfg.TransportSoak = true
	}
	if s := envInt("UWGS_TRANSPORT_SOAK_SECONDS"); s > 0 {
		cfg.TransportSoakSeconds = s
	}
	if envBool("UWGS_PERF") {
		cfg.Perf = true
	}
	if envBool("UWGS_RUN_STDIO_HEAVY_DIAG") {
		cfg.StdioHeavyDiag = true
	}
	if envBool("UWGS_STRICT_STDIO_HOTPATH") {
		cfg.StrictStdioHotpath = true
	}
	if envBool("UWGS_RUN_PTRACE_THREADED_DEATH") {
		cfg.PtraceThreadedDeath = true
	}
	if envBool("UWGS_RUN_HEADLESS_CHROME_SMOKE") {
		cfg.ChromeSmoke = true
	}
	if envBool("UWGS_RUN_CHROMIUM_SUPERVISED") {
		cfg.ChromiumSupervised = true
	}
	if envBool("UWGS_RUN_CHROMIUM_REAL_INTERNET") {
		cfg.ChromiumRealInet = true
	}
	if envBool("UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE") {
		cfg.Phase1ChromeSmoke = true
	}
	if envBool("UWG_PHASE2_DIAG") {
		cfg.Phase2Diag = true
	}
	if envBool("UWG_TEST_EXAMPLES") {
		cfg.Examples = true
	}
	if envBool("UWGS_TEST_DEBUG") {
		cfg.Verbose = true
	}
	if envBool("UWGS_TEST_DEBUG_STRESS") {
		cfg.VerboseStress = true
	}
	if v := strings.TrimSpace(os.Getenv("UWGS_CHROME_BIN")); v != "" {
		cfg.ChromeBin = v
	}
	if v := strings.TrimSpace(os.Getenv("UWGS_BROWSER_SMOKE_TRANSPORT")); v != "" {
		cfg.BrowserSmokeTransport = v
	}
}

func applyFlag(cfg *Config, f *flag.Flag) {
	switch f.Name {
	case "uwgs-all":
		cfg.All = *flagAll
	case "uwgs-real-tun":
		cfg.RealTUN = *flagRealTUN
	case "uwgs-real-tun-default":
		cfg.RealTUNDefault = *flagRealTUNDefault
	case "uwgs-soak":
		cfg.Soak = *flagSoak
	case "uwgs-soak-seconds":
		cfg.SoakSeconds = *flagSoakSeconds
	case "uwgs-stress":
		cfg.Stress = *flagStress
	case "uwgs-mesh-chaos":
		cfg.MeshChaos = *flagMeshChaos
	case "uwgs-transport-soak":
		cfg.TransportSoak = *flagTransportSoak
	case "uwgs-transport-soak-seconds":
		cfg.TransportSoakSeconds = *flagTransportSoakSeconds
	case "uwgs-perf":
		cfg.Perf = *flagPerf
	case "uwgs-stdio-heavy-diag":
		cfg.StdioHeavyDiag = *flagStdioHeavyDiag
	case "uwgs-strict-stdio-hotpath":
		cfg.StrictStdioHotpath = *flagStrictStdioHotpath
	case "uwgs-ptrace-threaded-death":
		cfg.PtraceThreadedDeath = *flagPtraceThreadedDeath
	case "uwgs-chrome-smoke":
		cfg.ChromeSmoke = *flagChromeSmoke
	case "uwgs-chromium-supervised":
		cfg.ChromiumSupervised = *flagChromiumSupervised
	case "uwgs-chromium-real-inet":
		cfg.ChromiumRealInet = *flagChromiumRealInet
	case "uwgs-phase1-chrome-smoke":
		cfg.Phase1ChromeSmoke = *flagPhase1ChromeSmoke
	case "uwgs-phase2-diag":
		cfg.Phase2Diag = *flagPhase2Diag
	case "uwgs-examples":
		cfg.Examples = *flagExamples
	case "uwgs-verbose":
		cfg.Verbose = *flagVerbose
	case "uwgs-verbose-stress":
		cfg.VerboseStress = *flagVerboseStress
	case "uwgs-chrome-bin":
		cfg.ChromeBin = *flagChromeBin
	case "uwgs-browser-smoke-transport":
		cfg.BrowserSmokeTransport = *flagBrowserSmokeTransport
	}
}

func enableAll(cfg *Config) {
	cfg.RealTUN = true
	cfg.RealTUNDefault = true
	cfg.Soak = true
	cfg.Stress = true
	cfg.MeshChaos = true
	cfg.TransportSoak = true
	cfg.Perf = true
	cfg.StdioHeavyDiag = true
	cfg.PtraceThreadedDeath = true
	cfg.ChromeSmoke = true
	cfg.ChromiumSupervised = true
	cfg.ChromiumRealInet = true
	cfg.Phase1ChromeSmoke = true
	cfg.Phase2Diag = true
	cfg.Examples = true
	// Note: StrictStdioHotpath and VerboseStress are diagnostic modifiers,
	// not test gates — -uwgs-all does not enable them automatically.
}

func envBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func envInt(key string) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
