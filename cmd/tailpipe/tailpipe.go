package main

// TODO: in dev derp mode: 2023/09/14 21:26:25 magicsock: last netcheck reported send error. Rebinding.

import (
	"cmp"
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
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"go4.org/mem"
	xmaps "golang.org/x/exp/maps"
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
	flagServe   = flag.String("serve", "", "comma-separated list of port numbers, port ranges, or service names to serve. Service names are: 'all' (serve all ports), 'exit' (run an exit node for all addresses), 'no-auth-ssh' (auth-free SSH server). If empty, it listens only on port 0 and writes to stdout.")
	flagKey     = flag.String("key", "", "'new' for an ephemeral one, '' for the 'default' key (if it exists), else a new key. Otherwise the path to a *.key.json or a name like 'foo' to read it from $CONFIG/tailpipe/keys/foo.key.json")
	flagAllow   = flag.String("allow", "", "comma-separated list of public keys to allow access to the server")
	flagVerbose = flag.Bool("verbose", false, "be verbose")
	flagJSON    = flag.Bool("json", false, "output JSON")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage:

Server mode, accept one connection (any port), write to stdout:

	tailpipe

Server mode, given ports:

	tailpipe --serve=22,80,443,8000-8999

Server mode, all ports:

	tailpipe --serve=all

Server mode, certain ports and Tailscale SSH (auth without
password or public key):

	tailpipe --serve=80,no-auth-ssh

Client mode, to default port 0 for stdin/stdout pipe:

	echo hello | tailpipe <addrblob>

Client mode to an explicit pipe:

	echo "GET / HTTP/1.1..." | tailpipe <addrblob> 80

Client mode, ssh:

	tailpipe ssh <addrblob>

Client mode, ssh to specific IP:port via addrblob's exit node:

	tailpipe ssh -p 10.0.0.1:22 <addrblob>

Client mode, run an ephemeral socks (socks5h) proxy and pass
its address as 'all_proxy' environment variable to a child
process:

	tailpipe socks <addrblob> <cmd> [args...]
	tailpipe socks <addrblob> curl http://server.tailpipe:8081/
`)
	os.Exit(1)
}

func main() {
	flag.Usage = func() { usage("") }
	flag.Parse()
	if *flagVerbose {
		derpcat.Verbose = true
	}
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
	case "genkey":
		genKey()
	case "printpub":
		fmt.Println(clientKey().Public().String())
	default:
		var addr string
		if strings.HasPrefix(args[0], "dc") {
			addr = args[0]
		} else if strings.Contains(args[0], ".") {
			// Maybe it's a DNS name with a TXT record?
			var r net.Resolver
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			txts, err := r.LookupTXT(ctx, args[0])
			if err != nil {
				log.Fatalf("argument %q doesn't start with 'dc' and not a DNS name with a tailpipe TXT record: %v", args[0], err)
			}
			for _, txt := range txts {
				if suf, ok := strings.CutPrefix(txt, "tailpipe="); ok {
					addr = strings.TrimSpace(suf)
					break
				}
			}
		}
		if addr == "" {
			log.Fatalf("argument %q doesn't start with 'dc' and not a DNS name with a tailpipe TXT record", args[0])
		}
		var dst string
		if len(args) == 2 {
			dst = args[1]
		}
		clientMode(logf, addr, dst)
	}
}

func clientKey() key.NodePrivate {
	if *flagKey == "" {
		path := keyPath("client-default")
		if _, err := os.Stat(path); err == nil {
			*flagKey = "client-default"
		} else {
			return key.NewNode()
		}
	}
	if *flagKey == "new" {
		return key.NewNode()
	}
	path := keyPath(*flagKey)
	j, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var conf derpcat.PrivateKey
	if err := json.Unmarshal(j, &conf); err != nil {
		log.Fatalf("failed to parse %v: %v", path, err)
	}
	return conf.Private
}

func clientMode(logf logger.Logf, connStr, optDest string) {
	priv := clientKey()
	cl, err := derpcat.NewClient(logf, derpcat.ConnBlob(connStr), priv)
	if err != nil {
		log.Fatalf("derpcat.NewClient: %v", err)
	}

	var dial func(context.Context) (net.Conn, error)
	switch {
	case optDest == "":
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, 1) }
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
		log.Fatalf("derpcat.Start: %v", err)
	}
	pi, err := cl.Ping(context.Background())
	if err != nil {
		log.Fatalf("tailpipe Ping: %v", err)
	}
	if *flagVerbose {
		logf("got ping: %+v", pi)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		log.Fatalf("Dial: %v", err)
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

	cl, err := derpcat.NewClient(logf, derpcat.ConnBlob(args[1]), key.NewNode())
	if err != nil {
		log.Fatal(err)
	}
	if err := cl.Start(); err != nil {
		log.Fatal(err)
	}
	pi, err := cl.Ping(context.Background())
	if err != nil {
		log.Fatalf("tailpipe Ping: %v", err)
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

func server(logf logger.Logf) {
	portSet, services, err := parsePortSet(*flagServe)
	if err != nil {
		log.Fatalf("invalid value in --serve: %v", err)
	}

	var reg *tailcfg.DERPRegion
	if envknob.Bool("TS_DEBUG_DC_LOCAL_DERP") {
		log.Printf("Local DERP mode.")
		reg = runDevDERP(logger.WithPrefix(logf, "[dev-derp] "))
	}

	var priv key.NodePrivate
	var ci *derpcat.ConnInfo

	if *flagKey == "" {
		if _, err := os.Stat(keyPath("default")); err == nil {
			*flagKey = "default"
		} else if os.IsNotExist(err) {
			*flagKey = "new"
		} else {
			log.Fatalf("failed to stat default key: %v", err)
		}
	}
	if *flagKey == "new" {
		priv = key.NewNode()
		ci = &derpcat.ConnInfo{RegionID: -1} // auto-detect
	} else {
		path := keyPath(*flagKey)
		j, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		var conf derpcat.PrivateKey
		if err := json.Unmarshal(j, &conf); err != nil {
			log.Fatalf("failed to parse %v: %v", path, err)
		}
		priv = conf.Private
		ci = &conf.Public
	}
	if reg == nil {
		if err := ci.Expand(context.Background(), true); err != nil {
			log.Fatalf("Expand: %v", err)
		}

		reg = ci.Region[0]
		if *flagKey == "new" {
			ci = &derpcat.ConnInfo{
				ServerPublic: derpcat.NodePublic{NodePublic: priv.Public()},
				RegionID:     reg.RegionID,
			}
		}
		clearUnnecessaryRegionFields(reg)
		fmt.Fprintf(os.Stderr, "# Selected bootstrap relay region %v, %v\n", reg.RegionID, reg.RegionName)
	}
	connStr := ci.ConnBlob()

	s, err := derpcat.NewServer(priv, logf, reg)
	if err != nil {
		log.Fatalf("NewServer: %v", err)
	}
	if services.Contains("no-auth-ssh") && !s.CanRunSSHServer() {
		log.Fatalf("Tailscale SSH server not supported on %v", runtime.GOOS)
	}
	if *flagAllow != "" {
		for _, ks := range strings.Split(*flagAllow, ",") {
			if ks == "none" {
				s.AddAllowedClient(key.NodePublic{})
				continue
			}
			var k key.NodePublic
			if err := k.UnmarshalText([]byte(ks)); err != nil {
				log.Fatalf("invalid key %q in --allow: %v", ks, err)
			}
			s.AddAllowedClient(k)
		}
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
		if port == 22 && services.Contains("no-auth-ssh") && tailPipeSSHEnabled {
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
	fmt.Fprintf(os.Stderr, "# Server listening at: %v\n", connStr)
	if *flagJSON {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"listenAddr": string(connStr)})
	}
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
		case "no-auth-ssh":
			if !tailPipeSSHEnabled {
				return nil, nil, fmt.Errorf("SSH support not included in binary per build tags")
			}
			services.Add(r)
			continue
		case "exit-node":
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

func keyIsPath(name string) bool {
	return strings.ContainsAny(name, `/\`)
}

func keyPath(name string) string {
	if keyIsPath(name) {
		return name
	}
	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(confDir, "tailpipe", "keys", name+".private.json")
}

func genKey() {
	if *flagKey != "" {
		log.Fatalf("genkey's --key argument must be after \"genkey\"")
	}
	args := flag.Args()
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)

	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	var (
		key          = fs.String("key", "default", "key path (if it contains a slash) or name (written to "+confDir+"/tailpipe/keys/<name>.private.json)")
		force        = fs.Bool("force", false, "force overwrite of existing key")
		delete       = fs.Bool("delete", false, "delete named key instead of generating it; only valid if key doesn't contain slashes")
		region       = fs.String("region", "auto", "region ID, code, or substring to use. Or a hostname(s) comma-separated to use a custom DERP server(s). If 'auto', one is picked based on latency. If 'list', list all regions.")
		embedDERPMap = fs.Bool("embed-derp-map", false, "embed the DERP map nodes in the connection string")
	)
	fs.Parse(args[1:]) // stripping off "genkey"
	switch len(fs.Args()) {
	case 0:
	default:
		fmt.Fprintf(os.Stderr, "derp genkey [-name=<name>] [-force] [name]\n")
		os.Exit(1)
	}

	if *delete {
		if keyIsPath(*key) {
			log.Fatalf("can't delete key %q; it's a path", *key)
		}
		os.Remove(keyPath(*key))
		return
	}
	if !keyIsPath(*key) {
		*key = keyPath(*key)
		if err := os.MkdirAll(filepath.Dir(*key), 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(*key); err == nil {
		if !*force && *region != "list" && *region != "auto" {
			log.Fatalf("%v already exists; use --force to overwrite", *key)
		}
	}

	priv := derpcat.NewPrivateKey()
	var match string
	if *region == "auto" {
		priv.Public.RegionID = -1
	} else if n, err := strconv.Atoi(*region); err == nil {
		priv.Public.RegionID = n
	} else if strings.Contains(*region, ".") {
		hosts := strings.Split(*region, ",")
		reg := &tailcfg.DERPRegion{}
		priv.Public.Region = append(priv.Public.Region, reg)
		for _, host := range hosts {
			reg.Nodes = append(reg.Nodes, &tailcfg.DERPNode{
				HostName: host,
			})
		}
	} else {
		match = *region
	}

	var dm tailcfg.DERPMap
	if match != "" || *region == "" || *embedDERPMap {
		res, err := http.Get("https://login.tailscale.com/derpmap/default")
		if err != nil {
			log.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			log.Fatalf("derpmap fetch: %v", res.Status)
		}
		if err := json.NewDecoder(res.Body).Decode(&dm); err != nil {
			log.Fatal(err)
		}
	}
	if *region == "" {
		log.Fatalf("TODO: pick a region automatically from netcheck over derpmap")
	}

	ci := &priv.Public
	if match != "" {
		ci.RegionID = findRegionIDFromSubstring(&dm, match)
		if ci.RegionID == 0 {
			regs := xmaps.Values(dm.Regions)
			slices.SortFunc(regs, func(a, b *tailcfg.DERPRegion) int { return cmp.Compare(a.RegionID, b.RegionID) })
			for _, reg := range regs {
				fmt.Fprintf(os.Stderr, "  %3d %s %s\n", reg.RegionID, reg.RegionCode, reg.RegionName)
			}
			if match == "list" {
				os.Exit(0)
			}
			log.Fatalf("\nno region found matching %q", match)
		}
	}
	if *embedDERPMap {
		reg := dm.Regions[ci.RegionID]
		reg.Nodes = reg.Nodes[:min(2, len(reg.Nodes))]
		for _, n := range reg.Nodes {
			n.IPv6 = ""
		}
		ci.Region = append(ci.Region, reg)
		ci.RegionID = 0
	}

	privj, err := json.MarshalIndent(priv, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*key, privj, 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "# wrote file to %v\n", *key)
	fmt.Println(priv.Public.ConnBlob())
}

// or returns 0 on no match
func findRegionIDFromSubstring(dm *tailcfg.DERPMap, s string) (regionID int) {
	if s == "list" {
		return 0
	}
	// First look my region code
	for _, r := range dm.Regions {
		if strings.EqualFold(r.RegionCode, s) {
			return r.RegionID
		}
	}
	// Then look by substring
	for _, r := range dm.Regions {
		if mem.ContainsFold(mem.S(r.RegionName), mem.S(s)) {
			return r.RegionID
		}
	}
	return 0
}

func clearUnnecessaryRegionFields(r *tailcfg.DERPRegion) {
	r.Latitude = 0
	r.Longitude = 0
	r.RegionCode = ""
	if len(r.Nodes) > 1 {
		r.Nodes = r.Nodes[:1]
	}
	for _, n := range r.Nodes {
		n.CanPort80 = false
		n.Name = ""
		n.RegionID = 0
	}
}
