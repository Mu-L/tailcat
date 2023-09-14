package derpcat

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func mkLogger(t testing.TB, name string) logger.Logf {
	return func(format string, args ...any) {
		t.Helper()
		if t.Failed() {
			return
		}
		t.Logf("        ["+name+"] "+format, args...)
	}
}

func TestDERPCat(t *testing.T) {
	derper, dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	t.Logf("DERPMap: %v", logger.AsJSON(dm))

	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	priv := key.NewNode()

	s, err := NewServer(priv, mkLogger(t, "server"), reg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	t.Logf("server: %v", s.ConnBlob())

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			io.WriteString(c, "Hello from port 80\n")
			c.Close()
		}
	}

	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	if err := tstest.WaitFor(5*time.Second, func() error {
		if derper.IsClientConnectedForTest(priv.Public()) {
			return nil
		}
		return errors.New("server not connected to derper")
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(mkLogger(t, "client"), s.ConnBlob())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if false {
		if err := tstest.WaitFor(5*time.Second, func() error {
			if derper.IsClientConnectedForTest(c.PublicKey()) {
				return nil
			}
			return errors.New("server not connected to derper")
		}); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("Client is %v", c.PublicKey())

	pi, err := c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	t.Logf("got ping: %+v", pi)

	time.Sleep(1 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.lb.sys.Dialer.Get().UserDial(ctx, "tcp", net.JoinHostPort(s.lb.addr.String(), "80"))
	if err != nil {
		t.Fatalf("UserDial = %v, %v", conn, err)
	}
	all, err := io.ReadAll(conn)
	t.Logf("Got: %q, %v", all, err)
}
