package main

// TODO: in dev derp mode: 2023/09/14 21:26:25 magicsock: last netcheck reported send error. Rebinding.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derpcat"
	"tailscale.com/envknob"
	"tailscale.com/net/socks5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

var (
	flagServe        = flag.String("serve", "", "comma-separated list of port numbers, port ranges, or service names to serve. Service names are: 'all' (serve all ports), 'exit' (run an exit node for all addresses), 'no-auth-ssh' (auth-free SSH server). If empty, it listens only on port 0 and writes to stdout.")
	flagVerbose      = flag.Bool("verbose", false, "be verbose")
	flagEmbedDERPMap = flag.Bool("embed-derp-map", false, "embed the DERP map nodes in the connection string")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage:

Server mode, accept one connection (any port), write to stdout:

	derp

Server mode, given ports:

	derp --serve=22,80,443,8000-8999

Server mode, all ports:

	derp --serve=all

Server mode, certain ports and Tailscale SSH (auth without
password or public key):

	derp --serve=80,no-auth-ssh

Client mode, to default port 0 for stdin/stdout pipe:

	echo hello | derp <derpaddr>

Client mode to an explicit pipe:

	echo "GET / HTTP/1.1..." | derp <derpaddr> 80

Client mode, ssh:

	dc ssh <derpaddr>

Client mode, ssh to specific IP:port via derpaddr's exit node:

	dc ssh -p 10.0.0.1:22 <derpaddr>

Client mode, run an ephemeral socks (socks5h) proxy and pass
its address as 'all_proxy' environment variable to a child
process:

	dc socks <derpaddr> <cmd> [args...]
	dc socks <derpaddr> curl http://server.derpcat:8081/
`)
	os.Exit(1)
}

func main() {
	flag.Usage = func() { usage("") }
	flag.Parse()
	args := flag.Args()
	serverMode := len(args) == 0 || *flagServe != ""
	if len(args) > 0 && serverMode {
		usage("No positional arguments are valid along with --serve")
	}
	var logf logger.Logf = logger.Discard
	if *flagVerbose {
		logf = log.Printf
	}
	if serverMode {
		server(logf)
		return
	}
	switch args[0] {
	case "socks":
		clientSOCKSMode(logf)
	case "ssh":
		clientSSHMode(logf)
	case "parse":
		clientParseMode(logf)
	default:
		if !strings.HasPrefix(args[0], "dc") {
			usage(fmt.Sprintf("unknown subcommand %q", args[0]))
		}
		var dst string
		if len(args) == 2 {
			dst = args[1]
		}
		clientMode(logf, args[0], dst)
	}
}

func clientMode(logf logger.Logf, connStr, optDest string) {
	cl, err := derpcat.NewClient(logf, derpcat.ConnBlob(connStr))
	if err != nil {
		log.Fatal(err)
	}

	var dial func(context.Context) (net.Conn, error)
	switch {
	case optDest == "":
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, 0) }
	case !strings.Contains(optDest, ":"):
		port, err := strconv.ParseUint(optDest, 10, 16)
		if err != nil {
			usage(fmt.Sprintf("invalid port number %q", optDest))
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, uint16(port)) }
	default:
		addrPort, err := netip.ParseAddrPort(optDest)
		if err != nil {
			usage(fmt.Sprintf("invalid IP:port %q", optDest))
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCP(ctx, addrPort) }
	}

	if err := cl.Start(); err != nil {
		log.Fatal(err)
	}
	pi, err := cl.Ping(context.Background())
	if err != nil {
		log.Fatalf("derpcat.Ping: %v", err)
	}
	if *flagVerbose {
		logf("got ping: %+v", pi)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		log.Fatal(err)
	}
	rxErr := make(chan error, 1)
	txErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, c)
		rxErr <- err
	}()
	go func() {
		_, err := io.Copy(c, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		if err := c.(*gonet.TCPConn).CloseWrite(); err != nil {
			log.Fatal(err)
		}
		// TODO(bradfitz): figure out more why this trashy sleep is required. It
		// seems that without it, our CloseWrite above never makes it out onto
		// the network (no OS kernel to deal with it async after we os.Exit!).
		// So we need to give it some time to send via DERP, etc. But where
		// exactly is the buffering happening? The magicsock derp conn send,
		// almost certainly. Maybe we can ask magicsock for its tx count before
		// the CloseWrite and then wait for it to change, and then exit?
		// But even then, do we want an ACK for our RST? Can we ask gvisor for
		// that? Poll the gonet.TCPConn status or something?
		time.Sleep(500 * time.Millisecond)
		txErr <- nil
	}()

	// TODO(bradfitz): probably more here
	select {
	case <-txErr:
	case <-rxErr:
	}
	return
}

func clientSOCKSMode(logf logger.Logf) {
	args := flag.Args() // "socks", <derpaddr>, <cmd>, [args...]
	if len(args) < 3 {
		usage("derp socks <derpaddr> <cmd> [args...]")
	}
	progArgs := args[2:]

	cl, err := derpcat.NewClient(logf, derpcat.ConnBlob(args[1]))
	if err != nil {
		log.Fatal(err)
	}
	if err := cl.Start(); err != nil {
		log.Fatal(err)
	}
	pi, err := cl.Ping(context.Background())
	if err != nil {
		log.Fatalf("derpcat.Ping: %v", err)
	}
	logf("got ping: %+v", pi)

	socksLn, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	ss := &socks5.Server{
		Logf: logger.WithPrefix(logf, "socks5: "),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			portNum, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, err
			}
			return cl.DialTCPPort(ctx, uint16(portNum))
		},
	}
	go func() {
		log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksLn))
	}()
	socksAddr := "socks5h://" + socksLn.Addr().String()
	logf("SOCKS running at %v", socksAddr)
	cmd := exec.Command(progArgs[0], progArgs[1:]...)
	cmd.Env = append(os.Environ(),
		"all_proxy="+socksAddr,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func clientParseMode(logf logger.Logf) {
	args := flag.Args()
	if len(args) != 2 {
		usage("derp parse <derpaddr>")
	}
	dst := args[1]
	ci, err := derpcat.ParseConnBlob(derpcat.ConnBlob(dst))
	if err != nil {
		log.Fatal(err)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "    ")
	e.Encode(ci)
}

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
		"-o", fmt.Sprintf("ProxyCommand=%s %s %s", exe, connBlobStr, portOrIPPort),
		dst,
	}
	err = syscall.Exec("/usr/bin/ssh", argv, os.Environ())
	log.Fatalf("failed to exec: %v", err)
}

func server(logf logger.Logf) {
	portSet, services, err := parsePortSet(*flagServe)
	if err != nil {
		log.Fatalf("invalid value in --serve: %v", err)
	}

	var reg *tailcfg.DERPRegion
	if envknob.Bool("TS_DEBUG_DC_LOCAL_DERP") {
		log.Printf("Local DERP mode.")
		reg = runDevDERP(logger.WithPrefix(logf, "[dev-derp] "))
	} else {
		reg, err = derpcat.PickRegion()
		if err != nil {
			log.Fatalf("finding DERP region: %v", err)
		}
	}
	priv := key.NewNode()
	s, err := derpcat.NewServer(priv, logf, reg)
	if err != nil {
		log.Fatalf("NewServer: %v", err)
	}
	if services.Contains("no-auth-ssh") && !s.CanRunSSHServer() {
		log.Fatalf("Tailscale SSH server not supported on %v", runtime.GOOS)
	}

	tcpForwardTo := func(ipPortStr string) func(net.Conn) {
		return func(c net.Conn) {
			defer c.Close()
			localConn, err := net.Dial("tcp", ipPortStr)
			if err != nil {
				logf("error proxying to %v: %v", ipPortStr, err)
				return
			}
			defer localConn.Close()
			errc := make(chan error, 1)
			go func() {
				_, err := io.Copy(c, localConn)
				errc <- err
			}()
			go func() {
				_, err := io.Copy(localConn, c)
				errc <- err
			}()
			<-errc
		}
	}

	if services.Contains("exit-node") {
		s.OnTCPForward = func(dst netip.AddrPort) (handler func(net.Conn)) {
			return tcpForwardTo(dst.String())
		}
	}

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if port == 22 && services.Contains("no-auth-ssh") {
			return s.HandleTailscaleSSHConn
		}
		if services.Contains("exit-node") {
			// Being an exit node includes localhost without needing
			// to specify all the local port ranges.
			return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
		}
		if len(portSet) == 0 {
			return func(c net.Conn) {
				defer c.Close()
				_, err := io.Copy(os.Stdout, c)
				if err != nil {
					log.Fatal(err)
				}
				os.Exit(0)
			}
		}
		if !portSet.Contains(port) {
			return nil // RST
		}
		return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
	}

	if err := s.Start(); err != nil {
		log.Fatalf("Server.Start: %v", err)
	}
	connStr := s.ConnBlob(*flagEmbedDERPMap)
	fmt.Fprintf(os.Stderr, "# Server derpaddr: %v\n", connStr)
	if v := os.Getenv("DC_ADDR_FILE"); v != "" {
		if err := os.WriteFile(v, []byte(connStr), 0600); err != nil {
			log.Fatal(err)
		}
	}

	if os.Getenv("DERPCAT_STATUS_LOOP") == "1" {
		go func() {
			for {
				log.Printf("status = %v", logger.AsJSON(s.Status()))
				time.Sleep(5 * time.Second)
			}
		}()
	}
	select {}
}

var (
	portRangeRx = regexp.MustCompile(`^\d+-\d+$`)
	numRx       = regexp.MustCompile(`^\d+$`)
)

func parsePortSet(s string) (ports set.Set[uint16], services set.Set[string], _ error) {
	services = set.Set[string]{}
	if s == "" {
		return nil, nil, nil
	}
	ret := set.Set[uint16]{}
	s = strings.TrimSpace(s)

	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		switch r {
		case "all":
			for i := 1; i <= 65535; i++ {
				ret.Add(uint16(i))
			}
			continue
		case "no-auth-ssh", "exit-node":
			services.Add(r)
			continue
		}
		if !numRx.MatchString(r) && !portRangeRx.MatchString(r) {
			return nil, nil, fmt.Errorf("%q is not a known named service (want one of: all, no-auth-ssh, exit-node)", r)
		}
		a, b := r, ""
		if portRangeRx.MatchString(r) {
			a, b, _ = strings.Cut(r, "-")
		}

		lo, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("%q is not a valid port", a)
		}
		hi := lo
		if b != "" {
			hi, err = strconv.ParseUint(b, 10, 16)
			if err != nil {
				return nil, nil, fmt.Errorf("%q is not a valid port number", b)
			}
		}
		if hi < lo {
			hi, lo = lo, hi
		}
		for i := lo; i <= hi; i++ {
			ret.Add(uint16(i))
		}
	}
	return ret, services, nil
}

func runDevDERP(logf logger.Logf) *tailcfg.DERPRegion {
	d := derp.NewServer(key.NewNode(), logf)
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	logf("starting dev derp on %v ...", ln.Addr())

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
	httpsrv.Listener = ln
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "D",
		Nodes: []*tailcfg.DERPNode{
			{
				Name:             "t1",
				RegionID:         1,
				HostName:         "T",
				IPv4:             "127.0.0.1",
				IPv6:             "-",
				STUNPort:         0, // default (TODO: actually run a STUN server in this func)
				DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
				InsecureForTests: true,
			},
		},
	}
}
