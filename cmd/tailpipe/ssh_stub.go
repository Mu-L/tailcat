//go:build ts_omit_ssh

package main

import (
	"os"

	"tailscale.com/types/logger"
)

const tailPipeSSHEnabled = false

func clientSSHMode(logf logger.Logf) {
	logf("ssh support not compiled in")
	os.Exit(1)
}
