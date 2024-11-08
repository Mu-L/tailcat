//go:build (linux || darwin) && !ts_omit_ssh

package derpcat

import (
	"net"
	"os"
	"path/filepath"

	"github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ssh/tailssh"
)

func (b *locoBackend) ShouldRunSSH() bool { return true }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	h := tailssh.NewDERPCatServer(s.lb.logf, s.lb)
	if err := h(c); err != nil {
		s.lb.logf("HandleTailscaleSSHConn: %v", err)
		c.Close()
		return
	}
}

func (b *locoBackend) GetSSH_HostKeys() (ret []ssh.Signer, err error) {
	conf, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	varRoot := filepath.Join(conf, "derpcat-server")
	if err := os.MkdirAll(varRoot, 0700); err != nil {
		return nil, err
	}
	var lb ipnlocal.LocalBackend
	lb.SetVarRoot(varRoot)
	return lb.GetSSH_HostKeys()
}
