package derpcat

import (
	"context"
	"testing"

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
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
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

	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	c, err := NewClient(mkLogger(t, "client"), s.ConnBlob())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	pi, err := c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	t.Logf("got ping: %+v", pi)
}
