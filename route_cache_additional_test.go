package cloudflared

import (
	"net/netip"
	"testing"
	"time"
)

func TestRouteCacheClearClosesAllEntries(t *testing.T) {
	t.Parallel()

	cache := newRouteCache(time.Minute)
	first := &fakeICMPRouteDestination{}
	second := &fakeICMPRouteDestination{}
	firstSession := ICMPRouteSession{
		Source:      netip.MustParseAddr("198.18.0.1"),
		Destination: netip.MustParseAddr("1.1.1.1"),
	}
	secondSession := ICMPRouteSession{
		Source:      netip.MustParseAddr("198.18.0.2"),
		Destination: netip.MustParseAddr("1.0.0.1"),
	}

	cache.Store(firstSession, first)
	cache.Store(secondSession, second)
	cache.Clear()

	if !first.IsClosed() || !second.IsClosed() {
		t.Fatalf("expected all destinations to be closed")
	}
	if _, loaded := cache.Lookup(firstSession); loaded {
		t.Fatal("expected cache to be empty after clear")
	}
}
