package derpcat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

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
	ServerPublic NodePublic `cbor:"p"` // a key.NodePublic

	// Region, if non-empty, lists the regions of a DERPMap.
	// Either Region or RegionID must be set. If Region is set
	// the client can avoid doing a lookup to discover the DERP map
	// but the ConnBlob is longer.
	//
	// As of 2023-09-22, a maximum of 1 region may be provided.
	Region []*tailcfg.DERPRegion `cbor:"r,omitempty"`

	// RegionID lists the number of one of Tailscale's provided
	// DERP servers. If set, Region may be omitted and the ConnBlob
	// is shorter, at the cost of the client needing to fetch
	// the derpmap from tailscale.com once at startup.
	RegionID int `cbor:"i,omitempty" json:",omitempty"`
}

// NodePublic is a wrapper around key.NodePublic just so we can have a slightly
// smaller CBOR representation without the "np" prefix.
type NodePublic struct {
	key.NodePublic
}

func (p NodePublic) MarshalBinary() ([]byte, error) {
	return p.NodePublic.AppendTo(nil), nil
}

func (p *NodePublic) UnmarshalBinary(x []byte) error {
	p.NodePublic = key.NodePublicFromRaw32(go4mem.B(x))
	return nil
}

func (a NodePublic) Equal(b NodePublic) bool {
	return a == b
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
	nm      *netmap.NetworkMap
}

func (b *locoBackend) derpRegionID() int {
	if b.dm == nil {
		panic("no derp map")
	}
	for _, r := range b.dm.Regions {
		return r.RegionID
	}
	panic("no derp regions in derp map")
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
	// when being a subnet router. See OnTCPForward for relayed connections.
	//
	// It must be set before calling Start.
	OnTCP func(port uint16) (handler func(net.Conn))

	// OnTCPForward, if non-nil, specifies a func that returns a handler to handle
	// incoming connections to the provided IP:port. If nil or if it returns nil,
	// then a RST is sent.
	//
	// This only applies to connections relayed through the server and not to the server
	// itself. See OnTCP for direct connections to the server.
	//
	// It must be set before calling Start.
	OnTCPForward func(netip.AddrPort) (handler func(net.Conn))
}

func NewServer(priv key.NodePrivate, logf logger.Logf, regs ...*tailcfg.DERPRegion) (*Server, error) {
	lb := newLocoBackend(priv)
	srv := &Server{
		lb: lb,
	}

	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	if len(regs) != 1 {
		return nil, fmt.Errorf("exactly 1 DERPRegion required for now, not %v", len(regs))
	}
	for _, r := range regs {
		if r.RegionID == 0 {
			return nil, fmt.Errorf("missing RegionID in %v", logger.AsJSON(r))
		}
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
		logf("GetTCPHandlerForFlow(%v, %v) ...", src, dst)
		if dst.Addr() == srv.Addr() {
			if srv.OnTCP == nil {
				return nil, true // send RST
			}
			return srv.OnTCP(dst.Port()), true
		}
		if srv.OnTCPForward == nil {
			return nil, true // send RST
		}
		if nat64Prefix.Contains(dst.Addr()) {
			var a4 [4]byte
			d6 := dst.Addr().As16()
			copy(a4[:], d6[12:16])
			dst = netip.AddrPortFrom(netip.AddrFrom4(a4), dst.Port())
		}
		return srv.OnTCPForward(dst), true
	}
	lb.ns = ns
	sys.Set(ns)

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

func (s *Server) Addr() netip.Addr { return s.lb.addr }
func (s *Server) Start() error     { return s.lb.Start() }
func (s *Server) Close() error     { return s.lb.Close() }

func (s *Server) ConnBlob(embedDERPMap bool) ConnBlob {
	return s.lb.ConnBlob(embedDERPMap)
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

func (lb *locoBackend) ConnBlob(embedDERPMap bool) ConnBlob {
	if lb.dm == nil {
		panic("no DERPMap set")
	}
	var ci ConnInfo
	ci.ServerPublic = NodePublic{lb.pub}
	for _, r := range lb.dm.Regions {
		if embedDERPMap {
			ci.Region = append(ci.Region, r)
		} else {
			ci.RegionID = r.RegionID
		}
	}
	if len(lb.dm.Regions) == 0 {
		panic("no regions in derpmap")
	}

	if debugConnBlob {
		log.Printf("ConnBlob: %v", logger.AsJSON(ci))
	}
	return ci.ConnBlob()
}

func (ci *ConnInfo) ConnBlob() ConnBlob {
	// Clone the DERPRegions (and their nodes) and mutate them to
	// zero out some fields before marshalling to save some space
	// and make the ConnBlob smaller. The same transforms are done on
	// the way back.
	mut := *ci
	mut.Region = make([]*tailcfg.DERPRegion, len(ci.Region))
	for i, r := range ci.Region {
		r2 := r.Clone()
		mut.Region[i] = r2

		// Remove some fields before encoding.
		r2.RegionID = 0
		r2.RegionCode = ""
		for _, n := range r2.Nodes {
			n.RegionID = 0
			implicitHost := "derp" + n.Name + ".tailscale.com"
			if n.HostName == implicitHost {
				n.HostName = ""
			}
		}
	}

	x, err := cbor.Marshal(&mut)
	if err != nil {
		panic(err)
	}
	if debugConnBlob {
		log.Printf("ConnBlob: %q", x)
		log.Printf("ConnBlob: %x", x)
	}
	return "derpcat-" + ConnBlob(base64.RawURLEncoding.EncodeToString(x))
}

func ParseConnBlob(cb ConnBlob) (ConnInfo, error) {
	var zero ConnInfo
	rest, ok := strings.CutPrefix(string(cb), "derpcat-")
	if !ok {
		return zero, errors.New("server doesn't start with \"derpcat-\"")
	}
	x, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return zero, fmt.Errorf("base64 decode: %w", err)
	}
	var ci ConnInfo
	if err := cbor.Unmarshal(x, &ci); err != nil {
		return zero, fmt.Errorf("CBOR unmarshal: %v", err)
	}
	for ri, r := range ci.Region {
		if r.RegionID == 0 {
			r.RegionID = ri + 1
		}
		if r.RegionCode == "" {
			r.RegionCode = fmt.Sprint(r.RegionID)
		}
		for _, n := range r.Nodes {
			if n.HostName == "" && n.Name != "" && unicode.IsNumber(rune(n.Name[0])) {
				n.HostName = "derp" + n.Name + ".tailscale.com"
			}
			if n.RegionID == 0 {
				n.RegionID = r.RegionID
			}
		}
	}
	return ci, nil
}

func (ci *ConnInfo) Expand(ctx context.Context) error {
	if len(ci.Region) > 0 || ci.RegionID == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://login.tailscale.com/derpmap/default", nil)
	if err != nil {
		return fmt.Errorf("fetching DERPMap for region %v: %w", ci.RegionID, err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching DERPMap for region %v: %w", ci.RegionID, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("fetching DERPMap for region %v: %v", ci.RegionID, res.Status)
	}
	var dm tailcfg.DERPMap
	if err := json.NewDecoder(res.Body).Decode(&dm); err != nil {
		return fmt.Errorf("fetching DERPMap for region %v, invalid JSON from %v: %w", ci.RegionID, req.URL, err)
	}
	r, ok := dm.Regions[ci.RegionID]
	if !ok {
		return fmt.Errorf("connection string said only DERP RegionID %v but no such region in %v", ci.RegionID, req.URL)
	}
	ci.Region = append(ci.Region, r)
	return nil
}

var allIPv6 = netip.MustParsePrefix("::/0")

func (lb *locoBackend) Start() error {
	if err := lb.ns.Start(nil /* no LocalBackend */); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}

	e := lb.sys.Engine.Get()
	mc := lb.sys.MagicSock.Get()
	lb.logf("disco pub key: %v", mc.DiscoPublicKey())

	mc.SetPrivateKey(lb.priv)
	mc.SetDERPMap(lb.dm)

	derpStr := fmt.Sprintf("127.3.3.40:%d", lb.derpRegionID())

	nm := &netmap.NetworkMap{
		PrivateKey: lb.priv,
	}
	if lb.serverPub.IsZero() {
		nm.SSHPolicy = lb.sshPolicy()
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
			AllowedIPs: []netip.Prefix{lb.addrPrefix, allIPv6},
			DERP:       derpStr,
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
			DERP:      derpStr,
		}).View()
		nm.Peers = append(nm.Peers, (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.derpcat.",
			User:       100,
			Key:        lb.serverPub,
			DiscoKey:   lb.serverPub.AsDiscoPublic(),
			Addresses:  []netip.Prefix{serverAddrPrefix},
			AllowedIPs: []netip.Prefix{serverAddrPrefix, allIPv6},
			DERP:       derpStr,
		}).View())
	}
	lb.mu.Lock()
	lb.nm = nm
	lb.mu.Unlock()

	e.SetNetworkMap(nm)
	lb.sys.Netstack.Get().UpdateNetstackIPs(nm)
	mc.SetNetworkUp(true)
	lb.logf("NetworkMap: %v", logger.AsJSON(nm))

	wgConf := &wgcfg.Config{
		Name:       "self",
		PrivateKey: lb.priv,
		Addresses:  []netip.Prefix{lb.addrPrefix},
		MTU:        1280,
		Peers:      []wgcfg.Peer{}, // TODO: add peers dynamically as they disco to us
	}
	if lb.serverPub.IsZero() {
		// We're the server.
		wgConf.Addresses = append(wgConf.Addresses, allIPv6)
	} else {
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
	derpStr := fmt.Sprintf("127.3.3.40:%d", b.derpRegionID())
	mak.Set(&b.clients, src, &tailcfg.Node{
		ID:         tailcfg.NodeID(id),
		StableID:   tailcfg.StableNodeID(fmt.Sprint(id)),
		Name:       fmt.Sprintf("client%d.derpcat.", id),
		User:       100,
		Key:        src,
		DiscoKey:   discoPub,
		Addresses:  []netip.Prefix{pfxOf(dcAddrForKey(src))},
		AllowedIPs: []netip.Prefix{pfxOf(dcAddrForKey(src))},
		DERP:       derpStr,
	})

	nm := &netmap.NetworkMap{
		PrivateKey: b.priv,
		SSHPolicy:  b.sshPolicy(),
		SelfNode: (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.derpcat.",
			User:       100,
			Key:        b.pub,
			DiscoKey:   b.priv.AsDiscoPrivate().Public(), // TODO: cache
			Addresses:  []netip.Prefix{b.addrPrefix},
			AllowedIPs: []netip.Prefix{b.addrPrefix, allIPv6},
			DERP:       derpStr,
		}).View(),
	}
	for _, n := range b.clients {
		nm.Peers = append(nm.Peers, n.View())
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmpx.Compare(a.ID(), b.ID())
	})
	b.nm = nm

	eng := b.sys.Engine.Get()
	eng.SetNetworkMap(nm)
	b.sys.Netstack.Get().UpdateNetstackIPs(nm)

	wgConf := &wgcfg.Config{
		Name:       "self",
		PrivateKey: b.priv,
		Addresses:  []netip.Prefix{b.addrPrefix, allIPv6},
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
	return netstack.Create(logf,
		sys.Tun.Get(),
		sys.Engine.Get(),
		sys.MagicSock.Get(),
		sys.Dialer.Get(),
		sys.DNSManager.Get(),
		sys.ProxyMapper(),
	)
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
	lb       *locoBackend
	ci       ConnInfo      // of server
	meowWait chan struct{} // closed on first meowed message from server

	serverAddr netip.Addr
}

func NewClient(logf logger.Logf, server ConnBlob) (*Client, error) {
	ci, err := ParseConnBlob(server)
	if err != nil {
		return nil, err
	}

	if err := ci.Expand(context.TODO()); err != nil {
		return nil, err
	}

	priv := key.NewNode()
	lb := newLocoBackend(priv)
	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	lb.serverPub = ci.ServerPublic.NodePublic
	for _, r := range ci.Region {
		mak.Set(&lb.dm.Regions, r.RegionID, r)
	}
	if len(ci.Region) == 0 {
		return nil, fmt.Errorf("no DERP regions in ConnBlob")
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
	sys.Set(ns)

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
		ci:         ci,
		lb:         lb,
		serverAddr: dcAddrForKey(ci.ServerPublic.NodePublic),
	}, nil
}

func (c *Client) PublicKey() key.NodePublic { return c.lb.pub }
func (c *Client) Close() error              { return c.lb.Close() }

type PingResult struct {
	Latency time.Duration
}

func (c *Client) Start() error {
	c.meowWait = make(chan struct{})
	c.lb.sys.MagicSock.Get().BeDerpCatClient(sync.OnceFunc(func() { close(c.meowWait) }))
	return c.lb.Start()
}

func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var zero PingResult

	t0 := time.Now()
	mc := c.lb.sys.MagicSock.Get()

	resc := make(chan *ipnstate.PingResult, 1)
	res := &ipnstate.PingResult{}
	mc.DerpCatPing(c.ci.ServerPublic.NodePublic, res, func(pr *ipnstate.PingResult) {
		resc <- pr
	})
	select {
	case pr := <-resc:
		if pr.Err != "" {
			return zero, errors.New(pr.Err)
		}
		select {
		case <-c.meowWait:
			return PingResult{time.Since(t0)}, nil
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (c *Client) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.lb.sys.Dialer.Get().UserDial(ctx, network, addr)
}

func (c *Client) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	return c.lb.sys.Dialer.Get().UserDial(ctx, "tcp", net.JoinHostPort(c.serverAddr.String(), fmt.Sprint(port)))
}

var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64PrefixBytes = nat64Prefix.Addr().As16()
)

func (c *Client) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if ap.Addr().Is4() {
		a := nat64PrefixBytes
		a4 := ap.Addr().As4()
		copy(a[12:], a4[:])
		ap = netip.AddrPortFrom(netip.AddrFrom16(a), ap.Port())
	}
	ns := c.lb.sys.Netstack.Get()
	return ns.DialContextTCP(ctx, ap)
}

func pfxOf(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

func (s *Server) Status() *ipnstate.Status {
	return s.lb.Status()
}

func (b *locoBackend) Dialer() *tsdial.Dialer {
	return b.sys.Dialer.Get()
}

func (b *locoBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	return nil, errors.New("not needed")
}

func (b *locoBackend) NetMap() *netmap.NetworkMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nm
}

func (b *locoBackend) NodeKey() key.NodePublic {
	return b.pub
}

func (b *locoBackend) TailscaleVarRoot() string {
	// only needed by tailssh.sshSession for recording
	// SSH sessions which isn't enabled.
	panic("unused")
}

func (b *locoBackend) WhoIs(ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	nv := (&tailcfg.Node{
		ID:       1,
		StableID: "one",
		User:     100,
	}).View()
	up := tailcfg.UserProfile{
		DisplayName: "Peer",
	}
	return nv, up, true
}

func (b *locoBackend) sshPolicy() *tailcfg.SSHPolicy {
	return &tailcfg.SSHPolicy{
		Rules: []*tailcfg.SSHRule{
			{
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers:   map[string]string{"*": os.Getenv("USER")},
				Action: &tailcfg.SSHAction{
					Message: "Welcome to DERPcat SSH.\n\n",
					Accept:  true,
				},
			},
		},
	}
}

// CanRunSSHServer reports whether the platform supports running a Tailscale SSH
// (auth-free) server.
func (s *Server) CanRunSSHServer() bool {
	return s.lb.ShouldRunSSH() // eh, reuse this method that ssh/tailssh needs of its ipnLocalBackend interface
}
