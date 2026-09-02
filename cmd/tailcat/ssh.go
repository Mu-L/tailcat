// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
)

const tailCatSSHEnabled = true

const sshLongHelp = `Examples:

	tailcat ssh <addrblob>
	tailcat ssh root@<addrblob>
	tailcat ssh <addrblob> uptime
	tailcat ssh example.com
	tailcat ssh -p 2222 <addrblob>
	tailcat ssh -p 10.0.0.1:22 <addrblob>

This execs the system ssh client with a ProxyCommand that runs
tailcat itself, so ssh sees a normal (if oddly named) destination
while the connection actually goes over tailcat to the server.
Anything after the destination is passed through to ssh, like a
remote command to run.
A DNS name whose "tailcat=" TXT record holds an address blob works
as the destination too.

The -p flag is the server port to connect to (default 22), or, if
the server is an exit node (--serve=exit-node), an ip:port on the
server's network to reach through it; a bare IP means its port 22.`

// sshCommand returns the "tailcat ssh" subcommand, with parent as the
// parent flag set for the global flags.
func sshCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("ssh").SetParent(parent)
	port := fs.StringShort('p', "22", "port number, or ip:port to reach via the server's exit node; a bare IP means port 22 on it")
	return &ff.Command{
		Name:      "ssh",
		Usage:     "tailcat ssh [-p <port|ip:port>] [user@]<addrblob> [<command> [args...]]",
		ShortHelp: "connect the system ssh client through a tailcat server",
		LongHelp:  sshLongHelp,
		Flags:     fs,
		Exec: func(ctx context.Context, args []string) error {
			return clientSSHMode(*port, args)
		},
	}
}

func clientSSHMode(portOrIPPort string, args []string) error {
	if len(args) == 0 {
		return usagef("ssh requires a [user@]<addrblob> destination argument")
	}
	portOrIPPort, err := validatedSSHPort(portOrIPPort)
	if err != nil {
		return err
	}
	dst := args[0] // either a derpaddr alone or "user@<derpaddr>"
	cmdArgs := args[1:]

	sshUser, connBlobStr, hasUser := strings.Cut(dst, "@")
	if !hasUser {
		connBlobStr = sshUser
		sshUser = ""
	}
	connBlobStr, err = validatedConnBlob(connBlobStr)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		log.Fatalf("no ssh client found in $PATH: %v", err)
	}
	sshDst := sshDestHost(connBlobStr)
	if sshUser != "" {
		sshDst = sshUser + "@" + sshDst
	}
	proxyCommand, err := sshProxyCommand(exe, *flagKey, *flagDERPMapURL, connBlobStr, portOrIPPort)
	if err != nil {
		return err
	}
	argv := []string{
		sshExe,
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile " + os.DevNull,
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand=" + proxyCommand,
		"--",
		sshDst,
	}
	argv = append(argv, cmdArgs...)
	err = execSSH(sshExe, argv)
	log.Fatalf("failed to run ssh: %v", err)
	return nil
}

// validatedSSHPort validates and canonicalizes the port or IP:port passed to
// tailcat's child ProxyCommand. A bare IP means port 22.
func validatedSSHPort(v string) (string, error) {
	if port, err := strconv.ParseUint(v, 10, 16); err == nil && port != 0 {
		return strconv.FormatUint(port, 10), nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return netip.AddrPortFrom(ip, 22).String(), nil
	}
	if ipPort, err := netip.ParseAddrPort(v); err == nil && ipPort.Port() != 0 {
		return ipPort.String(), nil
	}
	return "", usagef("invalid port or IP:port %q", v)
}

// validatedConnBlob resolves arg if it is a DNS name and verifies that the
// result is a valid connection blob before it is handed to ssh or scp.
func validatedConnBlob(arg string) (string, error) {
	connBlob := tailcat.ConnBlob(arg)
	if strings.Contains(arg, ".") {
		connBlob = addrBlobArg(arg)
	}
	if _, err := tailcat.ParseConnBlob(connBlob); err != nil {
		return "", fmt.Errorf("invalid connection blob %q: %w", arg, err)
	}
	return string(connBlob), nil
}

// sshProxyCommand returns the command passed to OpenSSH to connect the SSH
// client to a tailcat server. The command is run by OpenSSH, so values that
// can contain shell-special characters must be quoted.
func sshProxyCommand(exe, keyName, derpMapURL, connBlob, portOrIPPort string) (string, error) {
	args := []string{exe}
	// No --key flag at all when unset: ff parses --key= by consuming the
	// connection blob as the flag's value.
	if keyName != "" {
		args = append(args, "--key="+keyName)
	}
	if derpMapURL != tailcat.DefaultDERPMapURL {
		args = append(args, "--derpmap-url="+derpMapURL)
	}
	args = append(args, connBlob, portOrIPPort)
	if runtime.GOOS == "windows" {
		return proxyCommandJoinWindows(args)
	}
	return proxyCommandJoinUnix(args)
}

// proxyCommandJoinUnix quotes args for the POSIX shell OpenSSH uses to run a
// ProxyCommand. Percent signs are doubled for OpenSSH's own token expansion;
// it changes %% back to % before handing the command to the shell.
func proxyCommandJoinUnix(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains a control character: %q", arg)
		}
		arg = strings.ReplaceAll(arg, "%", "%%")
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
	}
	return strings.Join(quoted, " "), nil
}

// proxyCommandJoinWindows quotes args for cmd.exe, which Win32-OpenSSH uses
// to run a ProxyCommand. cmd.exe expands %variables% and, depending on
// configuration, !variables! even inside quotes, so reject those characters
// rather than claiming they can be safely escaped through both OpenSSH and
// cmd.exe.
func proxyCommandJoinWindows(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\"%!\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains a character unsafe for cmd.exe: %q", arg)
		}
		quoted[i] = quoteWindowsCommandArg(arg)
	}
	return strings.Join(quoted, " "), nil
}

// quoteWindowsCommandArg always double-quotes arg, protecting cmd.exe
// metacharacters, and doubles trailing backslashes as required by the Windows
// argv parser used by the tailcat child. Embedded quotes are rejected above
// because cmd.exe and that argv parser assign them incompatible meanings.
func quoteWindowsCommandArg(arg string) string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(arg)
	b.WriteString(strings.Repeat("\\", len(arg)-len(strings.TrimRight(arg, "\\"))))
	b.WriteByte('"')
	return b.String()
}

// sshDestHost returns the hostname to give the system ssh client as the
// connection destination for a tailcat ConnBlob. It is a short, deterministic
// function of blob rather than blob itself.
//
// ssh substitutes the literal destination hostname into %n in ControlPath
// (commonly "~/.ssh/master-%r@%n:%p"), and that expansion has to fit in an
// AF_UNIX socket path (~100 bytes total, including the home directory and
// ".ssh/master-" prefix). A ConnBlob can run past that on its own, so ssh
// with connection multiplexing fails with "too long for Unix domain socket"
// before tailcat is ever invoked (#12). The real blob is unaffected: it's
// passed to ProxyCommand as its own argument and still does the actual
// routing, so this string only ever labels the connection for ssh's
// bookkeeping (%n, and StrictHostKeyChecking is already off).
//
// Deterministic hashing, not blob truncation, matters here: ssh's connection
// sharing keys a control socket off ControlPath, so the same blob must
// always produce the same short host or multiplexing silently stops
// reusing (or worse, collides across) the right server.
func sshDestHost(blob string) string {
	sum := sha256.Sum256([]byte(blob))
	return "tailcat-" + hex.EncodeToString(sum[:8])
}
