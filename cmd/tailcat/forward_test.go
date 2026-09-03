// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestParseForwardSpec(t *testing.T) {
	for _, tt := range []struct {
		spec, wantAddr string
		wantPort       uint16
		wantErr        bool
	}{
		{"8080", "127.0.0.1:8080", 8080, false},
		{"18080:8080", "127.0.0.1:18080", 8080, false},
		{"1:65535", "127.0.0.1:1", 65535, false},
		{"0", "", 0, true},
		{"0:8080", "127.0.0.1:0", 8080, false},
		{"8080:0", "", 0, true},
		{"8080:bad", "", 0, true},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			gotAddr, gotPort, err := parseForwardSpec("127.0.0.1", tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseForwardSpec succeeded; want error")
				}
				return
			}
			if err != nil || gotAddr != tt.wantAddr || gotPort != tt.wantPort {
				t.Fatalf("parseForwardSpec(%q) = %q, %d, %v; want %q, %d", tt.spec, gotAddr, gotPort, err, tt.wantAddr, tt.wantPort)
			}
		})
	}
}

func TestForwardEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	remotePort := startEchoListener(t)

	_, tailcatAddr, serverStderr := e.startServer("--verbose", "serve", strconv.Itoa(int(remotePort)))

	// Forward from local port 0 (OS-assigned) and learn the picked
	// address from the "forwarding" line on stderr. Pre-picking a free
	// port here and passing it explicitly would race other processes
	// on this machine binding it first. Stderr goes to a file, polled
	// below, because reading a shared buffer while the process writes
	// it would race.
	forward := e.cmd("--verbose", "--key=new", "--derpmap-url="+e.derpMapURL, "forward", tailcatAddr, fmt.Sprintf("0:%d", remotePort))
	stderrPath := filepath.Join(t.TempDir(), "forward.stderr")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	forward.Stderr = stderrFile
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = forward.Process.Kill()
		_ = forward.Wait()
	})
	forwardStderr := func() string {
		b, _ := os.ReadFile(stderrPath)
		return string(b)
	}

	addrRx := regexp.MustCompile(`forwarding (\S+) ->`)
	var addr string
	deadline := time.Now().Add(30 * time.Second)
	for addr == "" {
		if time.Now().After(deadline) {
			t.Fatalf("forward never listened; stderr:\n%s", forwardStderr())
		}
		if m := addrRx.FindStringSubmatch(forwardStderr()); m != nil {
			addr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("forwarding from %s", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const payload = "forwarded over tailcat"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v\nforward stderr:\n%s\nserver stderr:\n%s", err, forwardStderr(), serverStderr)
	}
	if string(got) != payload {
		t.Errorf("got %q; want %q", got, payload)
	}
}
