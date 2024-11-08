//go:build !((linux || darwin) && !ts_omit_ssh)

package derpcat

import (
	"net"

	"github.com/tailscale/golang-x-crypto/ssh"
)

func (b *locoBackend) ShouldRunSSH() bool { return false }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	c.Close()
}

func (b *locoBackend) GetSSH_HostKeys() (ret []ssh.Signer, err error) {
	return nil, nil
}
