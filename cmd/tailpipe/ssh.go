//go:build !ts_omit_ssh

package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"tailscale.com/types/logger"
)

const tailPipeSSHEnabled = true

func clientSSHMode(logf logger.Logf) {
	args := flag.Args()
	args = args[1:] // trim off "ssh"
	if len(args) == 0 {
		usage("derp ssh [-p <port|ip:port)> [user@]<derpaddr>")
	}

	portOrIPPort := "22"
	if len(args) >= 2 && args[0] == "-p" {
		portOrIPPort = args[1]
		args = args[2:]
		if ip, err := netip.ParseAddr(portOrIPPort); err == nil {
			portOrIPPort = netip.AddrPortFrom(ip, 22).String()
		}
	}
	dst := args[0] // either a derpaddr alone or "user@<derpaddr>"

	connBlobStr := dst
	if strings.Contains(dst, "@") {
		_, connBlobStr, _ = strings.Cut(dst, "@")
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	argv := []string{
		"/usr/bin/ssh",
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", fmt.Sprintf("ProxyCommand=%s --key=%q %s %s", exe, *flagKey, connBlobStr, portOrIPPort),
		dst,
	}
	err = syscall.Exec("/usr/bin/ssh", argv, os.Environ())
	log.Fatalf("failed to exec: %v", err)
}
