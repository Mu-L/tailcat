package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"tailscale.com/derpcat"
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
	log.Printf("ports: %v", portSet)

	reg, err := derpcat.PickRegion()
	if err != nil {
		log.Fatalf("finding DERP region: %v", err)
	}
	priv := key.NewNode()
	s, err := derpcat.NewServer(priv, logf, reg)
	if err != nil {
		log.Fatalf("NewServer: %v", err)
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
