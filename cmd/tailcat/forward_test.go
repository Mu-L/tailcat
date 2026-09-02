// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
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
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localPort := localLn.Addr().(*net.TCPAddr).Port
	localLn.Close()

	_, tailcatAddr, _ := e.startServer("serve", strconv.Itoa(int(remotePort)))
	forward := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "forward", tailcatAddr, fmt.Sprintf("%d:%d", localPort, remotePort))
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = forward.Process.Kill()
		_ = forward.Wait()
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("forward listener did not become available: %v", err)
	}
	defer conn.Close()

	const payload = "forwarded over tailcat"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Errorf("got %q; want %q", got, payload)
	}
}
