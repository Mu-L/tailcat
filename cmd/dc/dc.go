package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

var (
	flagServer = flag.Bool("serve", false, "be server")
	flagTest   = flag.Bool("test", false, "self-test; be a server and connect to ourselves. lazy integration test in package main for now.")
)

func main() {
	flag.Parse()
	if *flagTest {
		doTest()
		return
	}
	if *flagServer {
		lb, err := beServer()
		if err != nil {
			log.Fatal(err)
		}
		if err := lb.Start(); err != nil {
			log.Fatal(err)
		}
		log.Printf(">>> Listening on: %v", lb.ConnBlob())

		mc := lb.sys.MagicSock.Get()
		eng := lb.sys.Engine.Get()
		for {
			var sb ipnstate.StatusBuilder
			mc.UpdateStatus(&sb)
			eng.UpdateStatus(&sb)
			log.Printf("status = %v", logger.AsJSON(sb.Status()))
			time.Sleep(5 * time.Second)
		}
	}
	log.Fatalf("usage: ...")
}

func doTest() {
	lb, err := beServer()
	if err != nil {
		log.Fatal(err)
	}
	cb := lb.ConnBlob()
	log.Printf(">>> Listening on: %v", cb)
}

// ConnBlob is the base64 encoded cbor of ConnInfo.
type ConnBlob string

type ConnInfo struct {
	ServerPub key.NodePublic      `cbor:"p"`
	Region    *tailcfg.DERPRegion `cbor:"r"`
}

// LocoBackend is like tailscaled's LocalBackend, but crazier.
// It serves a similar purpose (to be the hub of the world)
// but there's no controlclient involved, because there's
// no control plane.
type LocoBackend struct {
	sys        tsd.System
	priv       key.NodePrivate
	pub        key.NodePublic
	addr       netip.Addr
	addrPrefix netip.Prefix
	ns         *netstack.Impl
	dm         *tailcfg.DERPMap
}

func NewLocoBackend(priv key.NodePrivate) (*LocoBackend, error) {
	pub := priv.Public()
	addr := dcAddrForKey(pub)
	addrPrefix := netip.PrefixFrom(addr, addr.BitLen())
	lb := &LocoBackend{
		priv:       priv,
		pub:        pub,
		addr:       addr,
		addrPrefix: addrPrefix,
	}

	return lb, nil
}

// must be called before (not concurrently with) Start.
func (lb *LocoBackend) DiscoverDERPMap() error {
	// TODO: fetch/cache+test derpmap

	sea := &tailcfg.DERPRegion{
		RegionID:   10,
		RegionCode: "sea",
		Nodes: []*tailcfg.DERPNode{
			{
				HostName: "derp10b.tailscale.com",
				IPv4:     "192.73.240.161",
			},
			{
				HostName: "derp10c.tailscale.com",
				IPv4:     "192.73.240.121",
			},
		},
	}
	lb.dm = &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			sea.RegionID: sea,
		},
	}
	return nil
}

func (lb *LocoBackend) ConnBlob() ConnBlob {
	if lb.dm == nil {
		panic("no DERPMap set")
	}
	var ci ConnInfo
	ci.ServerPub = lb.pub
	for _, r := range lb.dm.Regions {
		ci.Region = r
	}
	if ci.Region == nil {
		panic("no regions in derpmap")
	}

	x, err := cbor.Marshal(&ci)
	if err != nil {
		panic(err)
	}
	return ConnBlob(base64.StdEncoding.EncodeToString(x))
}

func beServer() (*LocoBackend, error) {
	lb, err := NewLocoBackend(key.NewNode())
	if err != nil {
		return nil, fmt.Errorf("NewLocoBackend: %w", err)
	}
	if err := lb.DiscoverDERPMap(); err != nil {
		return nil, fmt.Errorf("DiscoverDERPMap: %w", err)
	}
	sys := &lb.sys
	var logf logger.Logf = log.Printf
	netMon, err := netmon.New(func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	var store ipn.StateStore = new(mem.Store)
	sys.Set(store)

	if err := createEngine(logf, sys); err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	ns, err := newNetstack(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	lb.ns = ns

	e := sys.Engine.Get()
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := e.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	return lb, nil
}

func (lb *LocoBackend) Start() error {

	if err := lb.ns.Start(nil /* no LocalBackend */); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}

	e := lb.sys.Engine.Get()
	mc := lb.sys.MagicSock.Get()
	log.Printf("disco pub key: %v", mc.DiscoPublicKey())

	mc.SetPrivateKey(lb.priv)
	e.SetDERPMap(lb.dm)

	nm := &netmap.NetworkMap{
		PrivateKey: lb.priv,
		SelfNode: (&tailcfg.Node{
			ID:        1,
			StableID:  "1",
			Name:      "server.derpcat.",
			User:      100,
			Key:       lb.pub,
			DiscoKey:  mc.DiscoPublicKey(), // TODO: change how disco works
			Addresses: []netip.Prefix{lb.addrPrefix},
		}).View(),
	}
	e.SetNetworkMap(nm)
	mc.SetNetworkUp(true)

	wgConf := &wgcfg.Config{
		Name:       "server",
		PrivateKey: lb.priv,
		Addresses:  []netip.Prefix{lb.addrPrefix},
		MTU:        1280,
		Peers:      []wgcfg.Peer{}, // TODO: add peers dynamically as they disco to us
	}
	routerConf := &router.Config{
		LocalAddrs: []netip.Prefix{lb.addrPrefix},
	}
	dnsConf := &dns.Config{}
	if err := e.Reconfig(wgConf, routerConf, dnsConf); err != nil {
		return fmt.Errorf("e.Reconfig: %w", err)
	}
	lb.sys.NetMon.Get().Start()

	return nil
}

func dcAddrForKey(k key.NodePublic) netip.Addr {
	var a [16]byte
	r := k.Raw32()
	copy(a[:], r[:])
	a[0] = 0xfc // ULA prefix. close enough. forcing final bit to 0.
	return netip.AddrFrom16(a)
}

func newNetstack(logf logger.Logf, sys *tsd.System) (*netstack.Impl, error) {
	return netstack.Create(logf, sys.Tun.Get(), sys.Engine.Get(), sys.MagicSock.Get(), sys.Dialer.Get(), sys.DNSManager.Get())
}

// createEngine tries to the wgengine.Engine based on the order of tunnels
// specified in the command line flags.
//
// onlyNetstack is true if the user has explicitly requested that we use netstack
// for all networking.
func createEngine(logf logger.Logf, sys *tsd.System) (err error) {
	conf := wgengine.Config{
		ListenPort:   0,
		NetMon:       sys.NetMon.Get(),
		Dialer:       sys.Dialer.Get(),
		SetSubsystem: sys.Set,
	}
	netns.SetEnabled(false)
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", "userspace-networking", err)
		return err
	}
	e = wgengine.NewWatchdog(e)
	sys.Set(e)
	sys.NetstackRouter.Set(true)
	return nil
}
