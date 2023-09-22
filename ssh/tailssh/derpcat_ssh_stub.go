package tailssh

import (
	"errors"
	"net"
	"runtime"

	"tailscale.com/types/logger"
)

func NewDERPCatServer(logf logger.Logf, lb any) (handler func(net.Conn) error) {
	return func(c net.Conn) error {
		return errors.New("not supported on " + runtime.GOOS)
	}
}
