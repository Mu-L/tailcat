// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_ssh || !(linux || darwin || windows)

package tailcat

import (
	"net"
)

// SupportsSSHServer reports whether the platform supports running the built-in
// auth-free SSH server.
func SupportsSSHServer() bool { return false }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	c.Close()
}
