//go:build !(linux || darwin)

package derpcat

import (
	"io"
	"net"
	"runtime"
)

func (b *locoBackend) ShouldRunSSH() bool { return false }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	io.WriteString(c, "Not supported on "+runtime.GOOS+"\n")
	c.Close()
}
