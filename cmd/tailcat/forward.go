// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
)

func forwardCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("forward").SetParent(parent)
	bind := fs.StringLong("bind", "127.0.0.1", "listen address; used as the local address when a mapping only specifies a port")
	return &ff.Command{
		Name:      "forward",
		Usage:     "tailcat forward [flags] <tc-addr> <[local:]remote> [<[local:]remote> ...]",
		ShortHelp: "forward local TCP ports to a tailcat server",
		LongHelp: `Listen on local TCP ports and forward connections to ports served by a tailcat server.

A mapping with one port uses the same local and remote port. A mapping with
local:remote uses different local and remote ports. For example:

	tailcat forward <tc-addr> 8080
	tailcat forward --bind=0.0.0.0 <tc-addr> 18080:8080`,
		Flags: fs,
		Exec: func(ctx context.Context, args []string) error {
			return runForward(ctx, getLogf(), *bind, args)
		},
	}
}

func runForward(ctx context.Context, logf logger.Logf, bind string, args []string) error {
	if len(args) < 2 {
		return usagef("forward takes a <tc-addr> and at least one port mapping")
	}

	cl := newClient(logf, tailcatAddrArg(args[0]), clientKey())
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	listeners := make([]net.Listener, 0, len(args)-1)
	var listenersWG, connectionsWG sync.WaitGroup
	var active sync.Map
	defer func() {
		stop()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		listenersWG.Wait()
		active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		connectionsWG.Wait()
		_ = cl.Close()
	}()
	for _, spec := range args[1:] {
		listenAddr, remotePort, err := parseForwardSpec(bind, spec)
		if err != nil {
			for _, ln := range listeners {
				ln.Close()
			}
			return usagef("mapping %q is invalid: %v", spec, err)
		}
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			for _, old := range listeners {
				old.Close()
			}
			return fmt.Errorf("listen on %s: %w", listenAddr, err)
		}
		listeners = append(listeners, ln)
		listenersWG.Add(1)
		go forwardListener(ctx, logf, cl, ln, remotePort, &listenersWG, &connectionsWG, &active)
	}

	<-ctx.Done()
	for _, ln := range listeners {
		ln.Close()
	}
	return nil
}

func forwardListener(ctx context.Context, logf logger.Logf, cl *tailcat.Client, ln net.Listener, remotePort uint16, listenersWG, connectionsWG *sync.WaitGroup, active *sync.Map) {
	defer listenersWG.Done()
	logf("forwarding %s -> remote localhost:%d", ln.Addr(), remotePort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		connectionsWG.Add(1)
		active.Store(conn, struct{}{})
		go func() {
			defer connectionsWG.Done()
			defer active.Delete(conn)
			defer conn.Close()
			remote, err := cl.DialTCPPort(ctx, remotePort)
			if err != nil {
				if ctx.Err() == nil {
					logf("dial remote port %d: %v", remotePort, err)
				}
				return
			}
			tailcat.ProxyConns(conn, remote)
		}()
	}
}

func parseForwardSpec(bind, spec string) (string, uint16, error) {
	local, remote, hasColon := strings.Cut(spec, ":")
	if !hasColon {
		remote = local
	}
	remotePort, err := parseForwardPort(remote)
	if err != nil {
		return "", 0, fmt.Errorf("remote port: %w", err)
	}
	localPort, err := parseForwardPort(local)
	if err != nil {
		return "", 0, fmt.Errorf("local port: %w", err)
	}
	return net.JoinHostPort(bind, strconv.Itoa(int(localPort))), remotePort, nil
}

func parseForwardPort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(p), nil
}
