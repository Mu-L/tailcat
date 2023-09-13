package derpcat

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"

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
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// ConnBlob is the base64 encoded cbor of ConnInfo.
type ConnBlob string

type ConnInfo struct {
	ServerPub key.NodePublic        `cbor:"p"`
	Region    []*tailcfg.DERPRegion `cbor:"r"`
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
	logf       logger.Logf
}

func (b *LocoBackend) Close() error {
	if e, ok := b.sys.Engine.GetOK(); ok {
		e.Close()
	}
	if m, ok := b.sys.NetMon.GetOK(); ok {
		m.Close()
	}
	return nil
}

type Server struct {
	lb *LocoBackend

	// AllowProxy, if non-nil, reports whether
	// a TCP or UDP proxy is allowed for that target.
	AllowProxy func(netip.AddrPort) bool
}

func NewServer(priv key.NodePrivate, logf logger.Logf, regs ...*tailcfg.DERPRegion) (*Server, error) {
	lb := NewLocoBackend(priv)
	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	for _, r := range regs {
		mak.Set(&lb.dm.Regions, r.RegionID, r)
	}

	sys := &lb.sys
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

	return &Server{lb: lb}, nil
}

func (s *Server) Start() error { return s.lb.Start() }
func (s *Server) Close() error { return s.lb.Close() }

func (s *Server) ConnBlob() ConnBlob {
	return s.lb.ConnBlob()
}

func NewLocoBackend(priv key.NodePrivate) *LocoBackend {
	pub := priv.Public()
	addr := dcAddrForKey(pub)
	addrPrefix := netip.PrefixFrom(addr, addr.BitLen())
	lb := &LocoBackend{
		logf:       log.Printf,
		priv:       priv,
		pub:        pub,
		addr:       addr,
		addrPrefix: addrPrefix,
	}

	return lb
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
		ci.Region = append(ci.Region, r)
	}
	if len(ci.Region) == 0 {
		panic("no regions in derpmap")
	}

	x, err := cbor.Marshal(&ci)
	if err != nil {
		panic(err)
	}
	return "derpcat_" + ConnBlob(base64.URLEncoding.EncodeToString(x))
}

func (lb *LocoBackend) Start() error {

	if err := lb.ns.Start(nil /* no LocalBackend */); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}

	e := lb.sys.Engine.Get()
	mc := lb.sys.MagicSock.Get()
	lb.logf("disco pub key: %v", mc.DiscoPublicKey())

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

func (b *LocoBackend) Status() *ipnstate.Status {
	mc := b.sys.MagicSock.Get()
	eng := b.sys.Engine.Get()
	var sb ipnstate.StatusBuilder
	mc.UpdateStatus(&sb)
	eng.UpdateStatus(&sb)
	return sb.Status()
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
