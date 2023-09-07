package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
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
		cb, sys, err := beServer()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf(">>> Listening on: %v", cb)

		mc := sys.MagicSock.Get()
		for {
			time.Sleep(5 * time.Second)
			var sb ipnstate.StatusBuilder
			mc.UpdateStatus(&sb)
			log.Printf("status = %v", logger.AsJSON(sb.Status()))
		}
	}
	log.Fatalf("usage: ...")
}

func doTest() {
	cb, sys, err := beServer()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf(">>> Listening on: %v", cb)
	_ = sys

}

// ConnBlob is the base64 encoded cbor of ConnInfo.
type ConnBlob string

type ConnInfo struct {
	ServerPub key.NodePublic      `cbor:"p"`
	Region    *tailcfg.DERPRegion `cbor:"r"`
}

func beServer() (ConnBlob, *tsd.System, error) {
	var ci ConnInfo
	priv := key.NewNode()
	ci.ServerPub = priv.Public()

	ci.Region = &tailcfg.DERPRegion{
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

	x, err := cbor.Marshal(&ci)
	if err != nil {
		return "", nil, fmt.Errorf("cbor.Marshal: %w", err)
	}
	connBlob := ConnBlob(base64.StdEncoding.EncodeToString(x))
	log.Printf(">>> Starting to listen on: %v", connBlob)

	var logf logger.Logf = log.Printf
	sys := new(tsd.System)
	netMon, err := netmon.New(func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return "", nil, fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	store, err := store.New(logf, filepath.Join(os.Getenv("HOME"), ".config", "tsdc.state"))
	if err != nil {
		return "", nil, fmt.Errorf("store.New: %w", err)
	}
	sys.Set(store)

	if err := createEngine(logf, sys); err != nil {
		return "", nil, fmt.Errorf("createEngine: %w", err)
	}
	ns, err := newNetstack(logf, sys)
	if err != nil {
		return "", nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true

	e := sys.Engine.Get()
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := e.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	if err := ns.Start(nil /* no LocalBackend */); err != nil {
		return "", nil, fmt.Errorf("failed to start netstack: %w", err)
	}

	mc := sys.MagicSock.Get()
	log.Printf("disco pub key: %v", mc.DiscoPublicKey())

	mc.SetPrivateKey(priv)
	e.SetDERPMap(&tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			ci.Region.RegionID: ci.Region,
		},
	})
	mc.SetNetworkUp(true)

	return connBlob, sys, nil
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
