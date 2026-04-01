package cloudflared

import (
	"context"
	"errors"
	"net"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

func restoreEdgeDiscoveryHooks(t *testing.T) {
	t.Helper()

	originalLookup := lookupEdgeSRVFn
	originalLookupDoT := lookupEdgeSRVWithDoTFn
	originalNetLookupSRV := edgeLookupSRV
	originalNetLookupIP := edgeLookupIP
	t.Cleanup(func() {
		lookupEdgeSRVFn = originalLookup
		lookupEdgeSRVWithDoTFn = originalLookupDoT
		edgeLookupSRV = originalNetLookupSRV
		edgeLookupIP = originalNetLookupIP
	})
}

func TestDiscoverEdgeFallsBackToDoT(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	expected := [][]*EdgeAddr{{
		{TCP: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, IPVersion: 4},
	}}
	lookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, errors.New("system dns failed")
	}
	lookupEdgeSRVWithDoTFn = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		if region != "us" {
			t.Fatalf("unexpected region %q", region)
		}
		return expected, nil
	}

	regions, err := DiscoverEdge(context.Background(), "us", N.SystemDialer)
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 || len(regions[0]) != 1 || regions[0][0].IPVersion != 4 {
		t.Fatalf("unexpected regions %#v", regions)
	}
}

func TestDiscoverEdgeReturnsFallbackError(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	lookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, errors.New("system dns failed")
	}
	lookupEdgeSRVWithDoTFn = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		return nil, errors.New("dot failed")
	}

	_, err := DiscoverEdge(context.Background(), "", N.SystemDialer)
	if err == nil || err.Error() != "edge discovery: dot failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestDiscoverEdgeRejectsEmptyRegions(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	lookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, nil
	}

	_, err := DiscoverEdge(context.Background(), "", N.SystemDialer)
	if err == nil || err.Error() != "edge discovery: no edge addresses found" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestResolveSRVRecordsPropagatesLookupError(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	edgeLookupIP = func(host string) ([]net.IP, error) {
		return nil, errors.New("lookup ip failed")
	}

	_, err := resolveSRVRecords([]*net.SRV{{Target: "edge.example.com", Port: 7844}})
	if err == nil || err.Error() != "resolve SRV target: edge.example.com: lookup ip failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestResolveSRVRecordsSkipsEmptyTargets(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	edgeLookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "empty.example.com":
			return nil, nil
		case "edge.example.com":
			return []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("2001:db8::1")}, nil
		default:
			t.Fatalf("unexpected host %q", host)
			return nil, nil
		}
	}

	regions, err := resolveSRVRecords([]*net.SRV{
		{Target: "empty.example.com", Port: 7844},
		{Target: "edge.example.com", Port: 7844},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 || len(regions[0]) != 2 {
		t.Fatalf("unexpected resolved regions %#v", regions)
	}
	if regions[0][0].IPVersion != 4 || regions[0][1].IPVersion != 6 {
		t.Fatalf("unexpected IP versions %#v", regions[0])
	}
}
