//go:build race

package engine_test

// 10× under -race. macOS-latest GitHub runners are intermittently
// 10× slower than the equivalent Linux/Windows runner under
// -race for these integration tests (full WG handshake + SOCKS5
// + multi-MB ping-pong). 6× was tight and TestPacketLossTransfer
// blew past 180s on macOS in v0.1.0-beta.14 release CI; 10×
// gives 300s which still fails fast on a real hang.
const testDeadlineScale = 10
