// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/tailcat/internal/buildtags"
	"tailscale.com/tstest/integration"
)

// binDir is where buildTailcatOnce puts the binary; TestMain removes
// it after the tests run.
var binDir string

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// buildTailcatOnce builds the tailcat binary once per test process,
// with the same build tags official releases use, so the end-to-end
// tests exercise the released feature set. The test harness itself
// must stay untagged: the tailscale.com test-only dependencies do not
// compile under the release omit tags, so only the child binary under
// test gets them.
var buildTailcatOnce = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "tailcat-e2e")
	if err != nil {
		return "", err
	}
	binDir = dir
	bin := filepath.Join(dir, "tailcat")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-tags", buildtags.ReleaseTags(), "-o", bin, ".").CombinedOutput(); err != nil {
		return "", fmt.Errorf("build: %v\n%s", err, out)
	}
	return bin, nil
})

// buildTailcat returns the path of the release-tagged tailcat binary,
// building it on first use.
func buildTailcat(t *testing.T) string {
	t.Helper()
	bin, err := buildTailcatOnce()
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

// testNoopCommand returns a child command that exits successfully,
// for tests that only care that a wrapper ran it. Windows has no
// "true" binary.
func testNoopCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/d", "/c", "exit", "/b", "0"}
	}
	return []string{"true"}
}

// cacheEnv returns environment variables that point os.UserCacheDir
// at a temp dir on all operating systems, so test runs don't litter
// the real user cache with DERP map entries keyed by a test's
// ephemeral --derpmap-url. Pointing HOME at the temp dir also keeps
// SSH state (the server's generated host key under os.UserConfigDir
// and the client's ~/.ssh) out of the real home directory.
func cacheEnv(t *testing.T) []string {
	dir := t.TempDir()
	return []string{
		"XDG_CACHE_HOME=" + dir, // Linux
		"HOME=" + dir,           // macOS
		"LocalAppData=" + dir,   // Windows
	}
}

// waitBlob polls addrFile every 100ms for up to 30 seconds and
// returns the trimmed address blob a tailcat server wrote there via
// TAILCAT_ADDR_FILE. On timeout it fails the test, including the
// server's stderr.
func waitBlob(t *testing.T, addrFile string, stderr *bytes.Buffer) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for addr file; server stderr:\n%s", stderr.String())
		}
		b, err := os.ReadFile(addrFile)
		if err == nil && len(b) > 0 {
			blob := strings.TrimSpace(string(b))
			t.Logf("server blob: %s", blob)
			return blob
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// testEnv is a hermetic environment for CLI end-to-end tests: a
// localhost DERP+STUN server, an httptest server serving its DERP map
// JSON, and environment variables pointing the binary's caches at
// temp dirs.
type testEnv struct {
	t          *testing.T
	bin        string
	derpMapURL string
	env        []string
}

// newTestEnv builds the tailcat binary and starts the DERP+STUN and
// DERP map servers, all cleaned up with the test.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	bin := buildTailcat(t)

	dm := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	dmJSON, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	dmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dmJSON)
	}))
	t.Cleanup(dmSrv.Close)

	return &testEnv{
		t:          t,
		bin:        bin,
		derpMapURL: dmSrv.URL,
		env:        append(os.Environ(), cacheEnv(t)...),
	}
}

// cmd returns an unstarted command running the tailcat binary with
// the test cache environment. Callers pass all flags explicitly,
// including --derpmap-url=e.derpMapURL where needed.
func (e *testEnv) cmd(args ...string) *exec.Cmd {
	cmd := exec.Command(e.bin, args...)
	cmd.Env = e.env
	return cmd
}

// serverCmd returns an unstarted server-mode command with the given
// extra flags and the addr file path its TAILCAT_ADDR_FILE points at,
// so callers can wire up pipes before starting it.
func (e *testEnv) serverCmd(extraFlags ...string) (*exec.Cmd, string) {
	addrFile := filepath.Join(e.t.TempDir(), "addr")
	args := append([]string{"--key=new", "--derpmap-url=" + e.derpMapURL}, extraFlags...)
	cmd := e.cmd(args...)
	cmd.Env = append(cmd.Env, "TAILCAT_ADDR_FILE="+addrFile)
	return cmd, addrFile
}

// startServer starts a tailcat server with the given extra flags,
// arranges for it to be killed when the test ends, waits for its
// address blob, and returns the running command, the blob, and the
// server's captured stderr.
func (e *testEnv) startServer(extraFlags ...string) (*exec.Cmd, string, *bytes.Buffer) {
	e.t.Helper()
	server, addrFile := e.serverCmd(extraFlags...)
	var stderr bytes.Buffer
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { server.Process.Kill() })
	blob := waitBlob(e.t, addrFile, &stderr)
	return server, blob, &stderr
}
