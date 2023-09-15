package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derpcat"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

var (
	flagPorts   = flag.String("ports", "", "ports to serve. comma-separated list of port numbers, or \"all\". If empty, in server mode only port 0 listens, which then writes to stdout.")
	flagVerbose = flag.Bool("verbose", false, "be verbose")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage:

Server mode, accept one connection (any port), write to stdout:

	dc

Server mode, given ports:

	dc --ports=80,443,8000-8999

Server mode, all ports and Tailscale auth-free SSH:

	dc --ports=all --ssh-server-no-auth

Client mode, to default port 0 for stdin/stdout pipe:

	echo hello | dc <derpaddr>

Client mode to an explicit pipe:

	echo "GET / HTTP/1.1..." | dc <derpaddr> 80

Client mode, ssh:

	dc ssh <derpaddr>
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
	panic("TODO")
}

func server(logf logger.Logf) {
	portSet, err := parsePortSet(*flagPorts)
	if err != nil {
		log.Fatalf("invalid value in --ports: %v", err)
	}

	var reg *tailcfg.DERPRegion
	if envknob.Bool("TS_DEBUG_DC_LOCAL_DERP") {
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

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if len(portSet) == 0 {
			return func(c net.Conn) {
				defer c.Close()
				io.Copy(os.Stdout, c)
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
	fmt.Fprintf(os.Stderr, "Server derpaddr: %v\n", s.ConnBlob())

	if *flagVerbose {
		go func() {
			for {
				log.Printf("status = %v", logger.AsJSON(s.Status()))
				time.Sleep(5 * time.Second)
			}
		}()
	}
	select {}
}

func parsePortSet(s string) (set.Set[uint16], error) {
	if s == "" {
		return nil, nil
	}
	ret := set.Set[uint16]{}
	s = strings.TrimSpace(s)
	if s == "all" {
		for i := 1; i <= 65535; i++ {
			ret.Add(uint16(i))
		}
		return ret, nil
	}

	for _, r := range strings.Split(s, ",") {
		a, b, ok := strings.Cut(strings.TrimSpace(r), "-")

		lo, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid port number", a)
		}
		hi := lo
		if ok {
			hi, err = strconv.ParseUint(b, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid port number", b)
			}
		}
		if hi < lo {
			hi, lo = lo, hi
		}
		for i := lo; i <= hi; i++ {
			ret.Add(uint16(i))
		}
	}
	return ret, nil
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
		RegionID: 1,
		Nodes: []*tailcfg.DERPNode{
			{
				Name:             "t1",
				RegionID:         1,
				HostName:         "T",
				IPv4:             "127.0.0.1",
				IPv6:             "-",
				STUNPort:         -1,
				DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
				InsecureForTests: true,
			},
		},
	}
}
