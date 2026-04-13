package preload_test

import (
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
)

func TestCompatCProgram(t *testing.T) {
    if runtime.GOOS != "linux" {
        t.Skip("linux-only preload test")
    }
    bin := filepath.Join(t.TempDir(), "uwgpreload_sockname_test")
    cmd := exec.Command("cc", "-Wall", "-Wextra", "-O2", "-o", bin, "uwgpreload_sockname_test.c", "-ldl")
    out, err := cmd.CombinedOutput()
    if err != nil {
        t.Fatalf("compile failed: %v\n%s", err, out)
    }
    run := exec.Command(bin)
    rout, err := run.CombinedOutput()
    if err != nil {
        t.Fatalf("run failed: %v\n%s", err, rout)
    }
    if strings.TrimSpace(string(rout)) != "ok" {
        t.Fatalf("unexpected output: %q", string(rout))
    }
}
