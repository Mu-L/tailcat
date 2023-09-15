package derpcat

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	go4mem "go4.org/mem"
	"tailscale.com/envknob"
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
	"tailscale.com/util/cmpx"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// ConnBlob is the base64 encoded cbor of ConnInfo.
type ConnBlob string

type ConnInfo struct {
	ServerPubBytes [32]byte              `cbor:"p"` // a key.NodePublic
	Region         []*tailcfg.DERPRegion `cbor:"r"`
}

func (ci ConnInfo) ServerPublic() key.NodePublic {
	raw := go4mem.B(ci.ServerPubBytes[:])
	return key.NodePublicFromRaw32(raw)
}

// locoBackend is like tailscaled's LocalBackend, but crazier.
// It serves a similar purpose (to be the hub of the world)
// but there's no controlclient involved, because there's
// no control plane.
type locoBackend struct {
	sys        tsd.System
	priv       key.NodePrivate
	pub        key.NodePublic
	addr       netip.Addr
	addrPrefix netip.Prefix
	ns         *netstack.Impl
	dm         *tailcfg.DERPMap
	logf       logger.Logf
	serverPub  key.NodePublic // non-zero if we're a client (server's public key)

	mu      sync.Mutex
	clients map[key.NodePublic]*tailcfg.Node // for the server
}

func (b *locoBackend) Close() error {
	if e, ok := b.sys.Engine.GetOK(); ok {
		e.Close()
	}
	if m, ok := b.sys.NetMon.GetOK(); ok {
		m.Close()
	}
	return nil
}

type Server struct {
	lb *locoBackend

	// AllowProxy, if non-nil, reports whether
	// a TCP or UDP proxy is allowed for that target.
	AllowProxy func(netip.AddrPort) bool

	// OnTCP, if non-nil, specifies a func that returns a handler to handle
	// incoming connections to the provided port. If nil or if it returns nil,
	// then a RST is sent.
	//
	// This only applies to connections directly to the server node and not
	// when being a subnet router.
	//
	// Must be set before calling Start.
	OnTCP func(port uint16) (handler func(net.Conn))
}

func NewServer(priv key.NodePrivate, logf logger.Logf, regs ...*tailcfg.DERPRegion) (*Server, error) {
	lb := newLocoBackend(priv)
	srv := &Server{
		lb: lb,
	}

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
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		if srv.OnTCP == nil {
			return nil, true // send RST
		}
		return srv.OnTCP(dst.Port()), true
	}
	lb.ns = ns

	e := sys.Engine.Get()
	e.SetFilter(filter.NewAllowAllForTest(logf)) // TODO: trashy
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := e.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	return srv, nil
}

func (s *Server) Start() error { return s.lb.Start() }
func (s *Server) Close() error { return s.lb.Close() }

func (s *Server) ConnBlob() ConnBlob {
	return s.lb.ConnBlob()
}

func newLocoBackend(priv key.NodePrivate) *locoBackend {
	pub := priv.Public()
	addr := dcAddrForKey(pub)
	addrPrefix := netip.PrefixFrom(addr, addr.BitLen())
	lb := &locoBackend{
		logf:       log.Printf,
		priv:       priv,
		pub:        pub,
		addr:       addr,
		addrPrefix: addrPrefix,
	}
	return lb
}

func PickRegion() (*tailcfg.DERPRegion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = ctx // TODO: conditionally fetch/refresh derpmap?
	return &tailcfg.DERPRegion{
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
	}, nil
}

var debugConnBlob = envknob.Bool("TS_DEBUG_CONNBLOB")

func (lb *locoBackend) ConnBlob() ConnBlob {
	if lb.dm == nil {
		panic("no DERPMap set")
	}
	var ci ConnInfo
	ci.ServerPubBytes = lb.pub.Raw32()
	for _, r := range lb.dm.Regions {
		ci.Region = append(ci.Region, r)
	}
	if len(ci.Region) == 0 {
		panic("no regions in derpmap")
	}

	if debugConnBlob {
		log.Printf("ConnBlob: %v", logger.AsJSON(ci))
	}

	x, err := cbor.Marshal(&ci)
	if err != nil {
		panic(err)
	}
	if debugConnBlob {
		log.Printf("ConnBlob: %q", x)
	}
	return "derpcat_" + ConnBlob(base64.URLEncoding.EncodeToString(x))
}

func ParseConnBlob(cb ConnBlob) (ConnInfo, error) {
	var zero ConnInfo
	rest, ok := strings.CutPrefix(string(cb), "derpcat_")
	if !ok {
		return zero, errors.New("server doesn't start with \"derpcat_\"")
	}
	x, err := base64.URLEncoding.DecodeString(rest)
	if err != nil {
		return zero, fmt.Errorf("base64 decode: %w", err)
	}
	var ci ConnInfo
	if err := cbor.Unmarshal(x, &ci); err != nil {
		return zero, fmt.Errorf("CBOR unmarshal: %v", err)
	}
	return ci, nil
}

func (lb *locoBackend) Start() error {
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
	}
	if lb.serverPub.IsZero() {
		// We're the server. (hence the serverPub is zero)
		discoPriv := lb.priv.AsDiscoPrivate()
		mc.SetDisco(discoPriv)
		mc.BeDerpCatServer(lb.onMeow)

		nm.SelfNode = (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.derpcat.",
			User:       100,
			Key:        lb.pub,
			DiscoKey:   discoPriv.Public(),
			Addresses:  []netip.Prefix{lb.addrPrefix},
			AllowedIPs: []netip.Prefix{lb.addrPrefix},
			DERP:       "127.3.3.40:1",
		}).View()
	} else {
		// We're the client.
		serverAddr := dcAddrForKey(lb.serverPub)
		serverAddrPrefix := netip.PrefixFrom(serverAddr, serverAddr.BitLen())

		nm.SelfNode = (&tailcfg.Node{
			ID:        2,
			StableID:  "2",
			Name:      "client.derpcat.",
			User:      100,
			Key:       lb.pub,
			DiscoKey:  mc.DiscoPublicKey(),
			Addresses: []netip.Prefix{lb.addrPrefix},
			DERP:      "127.3.3.40:1",
		}).View()
		nm.Peers = append(nm.Peers, (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.derpcat.",
			User:       100,
			Key:        lb.serverPub,
			DiscoKey:   lb.serverPub.AsDiscoPublic(),
			Addresses:  []netip.Prefix{serverAddrPrefix},
			AllowedIPs: []netip.Prefix{serverAddrPrefix},
			DERP:       "127.3.3.40:1",
		}).View())
	}
	nm.Addresses = nm.SelfNode.Addresses().AsSlice() // dumb redundant field for now
	e.SetNetworkMap(nm)
	mc.SetNetworkUp(true)
	lb.logf("NetworkMap: %v", logger.AsJSON(nm))

	wgConf := &wgcfg.Config{
		Name:       "self",
		PrivateKey: lb.priv,
		Addresses:  []netip.Prefix{lb.addrPrefix},
		MTU:        1280,
		Peers:      []wgcfg.Peer{}, // TODO: add peers dynamically as they disco to us
	}
	if !lb.serverPub.IsZero() {
		// We're the client. Add our server as a peer.
		wgConf.Peers = append(wgConf.Peers, wgcfg.Peer{
			PublicKey:  lb.serverPub,
			AllowedIPs: nm.Peers[0].AllowedIPs().AsSlice(),
		})
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

func (b *locoBackend) onMeow(src key.NodePublic, discoPub key.DiscoPublic) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.clients[src]; ok {
		return
	}
	id := len(b.clients) + 2 // server id ID 1, clients are IDs 2, 3, ...
	mak.Set(&b.clients, src, &tailcfg.Node{
		ID:         tailcfg.NodeID(id),
		StableID:   tailcfg.StableNodeID(fmt.Sprint(id)),
		Name:       fmt.Sprintf("client%d.derpcat.", id),
		User:       100,
		Key:        src,
		DiscoKey:   discoPub,
		Addresses:  []netip.Prefix{pfxOf(dcAddrForKey(src))},
		AllowedIPs: []netip.Prefix{pfxOf(dcAddrForKey(src))},
		DERP:       "127.3.3.40:1",
	})

	nm := &netmap.NetworkMap{
		PrivateKey: b.priv,
		SelfNode: (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.derpcat.",
			User:       100,
			Key:        b.pub,
			DiscoKey:   b.priv.AsDiscoPrivate().Public(), // TODO: cache
			Addresses:  []netip.Prefix{b.addrPrefix},
			AllowedIPs: []netip.Prefix{b.addrPrefix},
			DERP:       "127.3.3.40:1",
		}).View(),
	}
	nm.Addresses = nm.SelfNode.Addresses().AsSlice() // dumb redundant field for now
	for _, n := range b.clients {
		nm.Peers = append(nm.Peers, n.View())
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmpx.Compare(a.ID(), b.ID())
	})
	eng := b.sys.Engine.Get()
	eng.SetNetworkMap(nm)

	wgConf := &wgcfg.Config{
		Name:       "self",
		PrivateKey: b.priv,
		Addresses:  []netip.Prefix{b.addrPrefix},
		MTU:        1280,
		Peers:      []wgcfg.Peer{}, // TODO: add peers dynamically as they disco to us
	}
	for _, p := range b.clients {
		wgConf.Peers = append(wgConf.Peers, wgcfg.Peer{
			PublicKey:  p.Key,
			AllowedIPs: p.AllowedIPs,
		})
	}
	routerConf := &router.Config{
		LocalAddrs: []netip.Prefix{b.addrPrefix},
	}
	dnsConf := &dns.Config{}
	if err := eng.Reconfig(wgConf, routerConf, dnsConf); err != nil {
		panic(fmt.Sprintf("e.Reconfig: %v", err))
	}
}

func (b *locoBackend) Status() *ipnstate.Status {
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

type Client struct {
	lb *locoBackend
	ci ConnInfo // of server
}

func NewClient(logf logger.Logf, server ConnBlob) (*Client, error) {
	ci, err := ParseConnBlob(server)
	if err != nil {
		return nil, err
	}

	priv := key.NewNode()
	lb := newLocoBackend(priv)
	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	lb.serverPub = ci.ServerPublic()
	for _, r := range ci.Region {
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
	ns.ProcessLocalIPs = true // required to even reply to TCP SYNs client sends out
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		return nil, true // don't accept any incoming connections to client
	}
	lb.ns = ns

	e := sys.Engine.Get()
	e.SetFilter(filter.NewAllowAllForTest(logf)) // TODO: trashy
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := e.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	return &Client{
		ci: ci,
		lb: lb,
	}, nil
}

func (c *Client) PublicKey() key.NodePublic { return c.lb.pub }
func (c *Client) Start() error              { return c.lb.Start() }
func (c *Client) Close() error              { return c.lb.Close() }

type PingResult struct {
	Latency time.Duration
}

func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var zero PingResult

	t0 := time.Now()
	mc := c.lb.sys.MagicSock.Get()

	resc := make(chan *ipnstate.PingResult, 1)
	res := &ipnstate.PingResult{}
	mc.DerpCatPing(c.ci.ServerPublic(), res, func(pr *ipnstate.PingResult) {
		resc <- pr
	})
	select {
	case pr := <-resc:
		if pr.Err != "" {
			return zero, errors.New(pr.Err)
		}
		return PingResult{time.Since(t0)}, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func pfxOf(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

func (s *Server) Status() *ipnstate.Status {
	return s.lb.Status()
}
