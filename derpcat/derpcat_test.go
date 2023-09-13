package derpcat

import (
	"testing"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestDERPCat(t *testing.T) {
	logf := logger.TestLogger(t)
	dm := integration.RunDERPAndSTUN(t, logf, "127.0.0.1")
	t.Logf("DERPMap: %v", logger.AsJSON(dm))

	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	priv := key.NewNode()

	s, err := NewServer(priv, logf, reg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	t.Logf("server: %v", s.ConnBlob())

	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
}
