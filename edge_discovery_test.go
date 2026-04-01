package cloudflared

import (
	"context"
	"net"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

func TestDiscoverEdge(t *testing.T) {
	t.Parallel()
	regions, err := DiscoverEdge(context.Background(), "", N.SystemDialer)
	if err != nil {
		t.Fatal("DiscoverEdge: ", err)
	}
	if len(regions) == 0 {
		t.Fatal("expected at least 1 region")
	}
	for i, region := range regions {
		if len(region) == 0 {
			t.Errorf("region %d is empty", i)
			continue
		}
		for j, addr := range region {
			if addr.TCP == nil {
				t.Errorf("region %d addr %d: TCP is nil", i, j)
			}
			if addr.UDP == nil {
				t.Errorf("region %d addr %d: UDP is nil", i, j)
			}
			if addr.IPVersion != 4 && addr.IPVersion != 6 {
				t.Errorf("region %d addr %d: invalid IPVersion %d", i, j, addr.IPVersion)
			}
		}
	}
}

func TestFilterByIPVersion(t *testing.T) {
	t.Parallel()
	v4Addr := &EdgeAddr{
		TCP:       &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 7844},
		UDP:       &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 7844},
		IPVersion: 4,
	}
	v6Addr := &EdgeAddr{
		TCP:       &net.TCPAddr{IP: net.ParseIP("2606:4700::1"), Port: 7844},
		UDP:       &net.UDPAddr{IP: net.ParseIP("2606:4700::1"), Port: 7844},
		IPVersion: 6,
	}
	mixed := [][]*EdgeAddr{{v4Addr, v6Addr}}

	tests := []struct {
		name     string
		version  int
		expected int
	}{
		{"auto", 0, 2},
		{"v4 only", 4, 1},
		{"v6 only", 6, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := FilterByIPVersion(mixed, tt.version)
			total := 0
			for _, region := range result {
				total += len(region)
			}
			if total != tt.expected {
				t.Errorf("expected %d addrs, got %d", tt.expected, total)
			}
		})
	}

	t.Run("no match", func(t *testing.T) {
		t.Parallel()
		v4Only := [][]*EdgeAddr{{v4Addr}}
		result := FilterByIPVersion(v4Only, 6)
		if len(result) != 0 {
			t.Error("expected empty result for no match")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		result := FilterByIPVersion(nil, 4)
		if len(result) != 0 {
			t.Error("expected empty result for nil input")
		}
	})
}

func TestGetRegionalServiceName(t *testing.T) {
	t.Parallel()
	if got := getRegionalServiceName(""); got != edgeSRVService {
		t.Fatalf("expected global service %s, got %s", edgeSRVService, got)
	}
	if got := getRegionalServiceName("us"); got != "us-"+edgeSRVService {
		t.Fatalf("expected regional service us-%s, got %s", edgeSRVService, got)
	}
}

func TestInitialEdgeAddrIndex(t *testing.T) {
	t.Parallel()
	if got := initialEdgeAddrIndex(0, 4); got != 0 {
		t.Fatalf("expected conn 0 to get index 0, got %d", got)
	}
	if got := initialEdgeAddrIndex(3, 4); got != 3 {
		t.Fatalf("expected conn 3 to get index 3, got %d", got)
	}
	if got := initialEdgeAddrIndex(5, 4); got != 1 {
		t.Fatalf("expected conn 5 to wrap to index 1, got %d", got)
	}
	if got := initialEdgeAddrIndex(2, 1); got != 0 {
		t.Fatalf("expected single-address pool to always return 0, got %d", got)
	}
}

func TestRotateEdgeAddrIndex(t *testing.T) {
	t.Parallel()
	if got := rotateEdgeAddrIndex(0, 4); got != 1 {
		t.Fatalf("expected index 0 to rotate to 1, got %d", got)
	}
	if got := rotateEdgeAddrIndex(3, 4); got != 0 {
		t.Fatalf("expected last index to wrap to 0, got %d", got)
	}
	if got := rotateEdgeAddrIndex(0, 1); got != 0 {
		t.Fatalf("expected single-address pool to stay at 0, got %d", got)
	}
}

func TestEffectiveHAConnections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		requested int
		available int
		expected  int
	}{
		{name: "requested below available", requested: 2, available: 4, expected: 2},
		{name: "requested equals available", requested: 4, available: 4, expected: 4},
		{name: "requested above available", requested: 5, available: 3, expected: 3},
		{name: "no available edges", requested: 4, available: 0, expected: 0},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if actual := effectiveHAConnections(testCase.requested, testCase.available); actual != testCase.expected {
				t.Fatalf("effectiveHAConnections(%d, %d) = %d, want %d", testCase.requested, testCase.available, actual, testCase.expected)
			}
		})
	}
}
