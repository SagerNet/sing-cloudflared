package cloudflared

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/discovery"
)

func testEdgeAddr(addr string) *discovery.EdgeAddr {
	return &discovery.EdgeAddr{UDP: net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))}
}

func TestFlattenRegionsInterleaves(t *testing.T) {
	regions := [][]*discovery.EdgeAddr{
		{testEdgeAddr("10.1.0.1:7844"), testEdgeAddr("10.1.0.2:7844"), testEdgeAddr("10.1.0.3:7844")},
		{testEdgeAddr("10.2.0.1:7844"), testEdgeAddr("10.2.0.2:7844")},
	}
	got := flattenRegions(regions)
	want := []string{"10.1.0.1:7844", "10.2.0.1:7844", "10.1.0.2:7844", "10.2.0.2:7844", "10.1.0.3:7844"}
	if len(got) != len(want) {
		t.Fatalf("got %d addresses, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].UDP.String() != want[i] {
			t.Fatalf("index %d: got %s, want %s", i, got[i].UDP, want[i])
		}
	}
}

func TestDefaultHAConnectionsSpanRegions(t *testing.T) {
	var r1, r2 []*discovery.EdgeAddr
	for i := 1; i <= 10; i++ {
		r1 = append(r1, testEdgeAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, 0, byte(i)}), 7844).String()))
		r2 = append(r2, testEdgeAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 2, 0, byte(i)}), 7844).String()))
	}
	addrs := flattenRegions([][]*discovery.EdgeAddr{r1, r2})
	perRegion := map[byte]int{}
	for connIndex := uint8(0); connIndex < 4; connIndex++ {
		addr := addrs[initialEdgeAddrIndex(connIndex, len(addrs))]
		perRegion[addr.UDP.IP.To4()[1]]++
	}
	if perRegion[1] != 2 || perRegion[2] != 2 {
		t.Fatalf("want 2 connections per region, got %v", perRegion)
	}
	// A failed connection rotates to the next index, which is in the other region.
	first := addrs[initialEdgeAddrIndex(0, len(addrs))]
	next := addrs[rotateEdgeAddrIndex(initialEdgeAddrIndex(0, len(addrs)), len(addrs))]
	if first.UDP.IP.To4()[1] == next.UDP.IP.To4()[1] {
		t.Fatalf("retry stayed in region %d", first.UDP.IP.To4()[1])
	}
}
