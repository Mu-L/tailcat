package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"tailscale.com/derpcat"
	"tailscale.com/types/logger"
)

var (
	flagPorts = flag.String("ports", "", "ports to serve. comma-separated list of port numbers, or \"all\". If empty, in server mode only port 0 listens, which then writes to stdout.")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage: dc [--ports={...,all}]
    dc <server> [port]
    dc ssh <server>
`)
	os.Exit(1)
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) > 0 && *flagPorts != "" {
		usage("No positional arguments are valid along with --ports")
	}
	serverMode := len(args) == 0
	if serverMode {
		lb, err := derpcat.BeServer()
		if err != nil {
			log.Fatal(err)
		}
		if err := lb.Start(); err != nil {
			log.Fatal(err)
		}
		log.Printf(">>> Listening on: %v", lb.ConnBlob())

		for {
			log.Printf("status = %v", logger.AsJSON(lb.Status()))
			time.Sleep(5 * time.Second)
		}
	}
	log.Fatalf("usage: ...")
}

func doTest() {
	lb, err := derpcat.BeServer()
	if err != nil {
		log.Fatal(err)
	}
	cb := lb.ConnBlob()
	log.Printf(">>> Listening on: %v", cb)
}
