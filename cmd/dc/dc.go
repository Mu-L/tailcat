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
	"os"
	"os/exec"
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
	flagPorts        = flag.String("ports", "", "ports to serve. comma-separated list of port numbers, or \"all\". If empty, in server mode only port 0 listens, which then writes to stdout.")
	flagVerbose      = flag.Bool("verbose", false, "be verbose")
	flagEmbedDERPMap = flag.Bool("embed-derp-map", false, "embed the DERP map nodes in the connection string")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage:

Server mode, accept one connection (any port), write to stdout:

	dc

Server mode, given ports:

	dc --ports=22,80,443,8000-8999

Server mode, all ports:

	dc --ports=all

Server mode, certain ports and Tailscale SSH (auth without
password or public key):

	dc --ports=123,tssh

Client mode, to default port 0 for stdin/stdout pipe:

	echo hello | dc <derpaddr>

Client mode to an explicit pipe:

	echo "GET / HTTP/1.1..." | dc <derpaddr> 80

Client mode, ssh:

	dc ssh <derpaddr>

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
	if len(args) > 0 && *flagPorts != "" {
		usage("No positional arguments are valid along with --ports")
	}
	var logf logger.Logf = logger.Discard
	if *flagVerbose {
		logf = log.Printf
	}
	serverMode := len(args) == 0
	if serverMode {
		server(logf)
		return
	}
	if len(args) >= 3 && args[0] == "socks" {
		clientSOCKSMode(logf)
		return
	}
	if len(args) >= 2 && args[0] == "ssh" {
		clientSSHMode(logf)
		return
	}
	if len(args) >= 2 && args[0] == "parse" {
		clientParseMode(logf)
		return
	}

	if (len(args) == 1 || len(args) == 2) && strings.HasPrefix(args[0], "derpcat_") {
		var port uint16 // default 0
		if len(args) == 2 {
			portStr := args[1]
			port64, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				usage(fmt.Sprintf("invalid port number %q", portStr))
			}
			port = uint16(port64)
		}
		cl, err := derpcat.NewClient(logf, derpcat.ConnBlob(args[0]))
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := cl.DialTCPPort(ctx, port)
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

		// TODO(bradfitz): probably more ehre
		select {
		case <-txErr:
		case <-rxErr:
		}
		return
	}
	panic("TODO")
}

func clientSOCKSMode(logf logger.Logf) {
	args := flag.Args()
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
	dst := args[1] // either a derpaddr alone or "user@<derpaddr>"

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
		"-o", fmt.Sprintf("ProxyCommand=%s %s 22", exe, connBlobStr),
		dst,
	}
	err = syscall.Exec("/usr/bin/ssh", argv, os.Environ())
	log.Fatalf("failed to exec: %v", err)
}

func server(logf logger.Logf) {
	portSet, services, err := parsePortSet(*flagPorts)
	if err != nil {
		log.Fatalf("invalid value in --ports: %v", err)
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
	if services.Contains("tailscale-ssh") && !s.CanRunSSHServer() {
		log.Fatalf("Tailscale SSH server not supported on %v", runtime.GOOS)
	}

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if port == 22 && services.Contains("tailscale-ssh") {
			return s.HandleTailscaleSSHConn
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
		return func(c net.Conn) {
			defer c.Close()
			localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%v", port))
			if err != nil {
				logf("error proxying to localhost:%v: %v", port, err)
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

	if err := s.Start(); err != nil {
		log.Fatalf("Server.Start: %v", err)
	}
	connStr := s.ConnBlob(*flagEmbedDERPMap)
	fmt.Fprintf(os.Stderr, "Server derpaddr: %v\n", connStr)
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

func parsePortSet(s string) (ports set.Set[uint16], services set.Set[string], _ error) {
	services = set.Set[string]{}
	if s == "" {
		return nil, nil, nil
	}
	ret := set.Set[uint16]{}
	s = strings.TrimSpace(s)

	for _, r := range strings.Split(s, ",") {
		switch r {
		case "all":
			for i := 1; i <= 65535; i++ {
				ret.Add(uint16(i))
			}
			continue
		case "tssh":
			services.Add("tailscale-ssh")
			continue
		}
		a, b, ok := strings.Cut(strings.TrimSpace(r), "-")

		lo, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("%q is not a valid port number", a)
		}
		hi := lo
		if ok {
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
