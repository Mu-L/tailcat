package derpcat

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
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
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("UserDial = %v, %v", conn, err)
	}
	all, err := io.ReadAll(conn)
	t.Logf("Got: %q, %v", all, err)
}

func TestConnBlob(t *testing.T) {
	tests := []struct {
		name string
		ci   ConnInfo
		want ConnBlob
		back *ConnInfo // if non-nil, round-tripped form we want
	}{
		{
			name: "just_key",
			ci: ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
			},
			want: "derpcat_oWFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHw",
		},
		{
			name: "key_with_full_custom_region", // worst case (longest length)
			ci: ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						Nodes: []*tailcfg.DERPNode{
							{
								Name:     "1a",
								IPv4:     "400.400.400.400",
								HostName: "my-derp.custom.example",
							},
							{
								Name:     "1b",
								IPv4:     "400.400.400.400",
								HostName: "my-derp2.custom.example",
							},
						},
					},
				},
			},
			want: "derpcat_omFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FygaJiaWQAYW6Co2FuYjFhYmhudm15LWRlcnAuY3VzdG9tLmV4YW1wbGVhNG80MDAuNDAwLjQwMC40MDCjYW5iMWJiaG53bXktZGVycDIuY3VzdG9tLmV4YW1wbGVhNG80MDAuNDAwLjQwMC40MDA",
			back: &ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   1,
						RegionCode: "1",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 1,
								Name:     "1a",
								IPv4:     "400.400.400.400",
								HostName: "my-derp.custom.example",
							},
							{
								RegionID: 1,
								Name:     "1b",
								IPv4:     "400.400.400.400",
								HostName: "my-derp2.custom.example",
							},
						},
					},
				},
			},
		},

		{
			name: "ts_region",
			ci: ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						Nodes: []*tailcfg.DERPNode{
							{
								Name: "1a", // if no Hostname, implicitly "derp1a.tailscale.com"
							},
							{
								Name: "1b",
							},
						},
					},
				},
			},
			want: "derpcat_omFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FygaJiaWQAYW6CoWFuYjFhoWFuYjFi",
			back: &ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   1,
						RegionCode: "1",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 1,
								Name:     "1a",
								HostName: "derp1a.tailscale.com",
							},
							{
								RegionID: 1,
								Name:     "1b",
								HostName: "derp1b.tailscale.com",
							},
						},
					},
				},
			},
		},

		{
			name: "remove_implicit_fields_on_marshal",
			ci: ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						RegionID: 123, // gets scrubbed, changed to 1
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 123, // gets scrubbed, changed to 1
								Name:     "1a",
								HostName: "derp1a.tailscale.com",
							},
							{
								RegionID: 123, // gets scrubbed, changed to 1
								Name:     "1b",
								HostName: "derp1b-non-default-value.tailscale.com",
							},
						},
					},
				},
			},
			want: "derpcat_omFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FygaJiaWQAYW6CoWFuYjFhomFuYjFiYmhueCZkZXJwMWItbm9uLWRlZmF1bHQtdmFsdWUudGFpbHNjYWxlLmNvbQ",
			back: &ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   1,
						RegionCode: "1",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 1,
								Name:     "1a",
								HostName: "derp1a.tailscale.com",
							},
							{
								RegionID: 1,
								Name:     "1b",
								HostName: "derp1b-non-default-value.tailscale.com",
							},
						},
					},
				},
			},
		},

		{
			name: "region_id",
			ci: ConnInfo{
				ServerPubBytes: [32]byte{1: 1, 2: 2, 31: 31},
				RegionID:       10,
			},
			want: "derpcat_omFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ci.ConnBlob()
			t.Logf("length: %v (%v)", len(got), got)
			if got != tt.want {
				t.Fatalf("ConnInfo.ConnBlob marshal wrong.\n got: %s\nwant: %s\n", got, tt.want)
			}

			gotCI, err := ParseConnBlob(got)
			if err != nil {
				t.Fatalf("ParseConnBlob: %v", err)
			}
			want := tt.ci
			if tt.back != nil {
				want = *tt.back
			}
			if diff := cmp.Diff(want, gotCI); diff != "" {
				t.Errorf("ParseConnBlob result back diff:\n%s", diff)
			}
		})
	}
}
