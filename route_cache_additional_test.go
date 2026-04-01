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

func TestRouteCacheLookupExpiredClosesDestination(t *testing.T) {
	t.Parallel()

	cache := newRouteCache(5 * time.Millisecond)
	destination := &fakeICMPRouteDestination{}
	session := ICMPRouteSession{
		Source:      netip.MustParseAddr("198.18.0.10"),
		Destination: netip.MustParseAddr("1.1.1.1"),
	}

	cache.Store(session, destination)
	time.Sleep(10 * time.Millisecond)

	if _, loaded := cache.Lookup(session); loaded {
		t.Fatal("expected expired cache entry to be evicted")
	}
	if !destination.IsClosed() {
		t.Fatal("expected expired destination to be closed")
	}
}

func TestRouteCacheStoreReplacesExistingDestination(t *testing.T) {
	t.Parallel()

	cache := newRouteCache(time.Minute)
	first := &fakeICMPRouteDestination{}
	second := &fakeICMPRouteDestination{}
	session := ICMPRouteSession{
		Source:      netip.MustParseAddr("198.18.0.20"),
		Destination: netip.MustParseAddr("1.0.0.1"),
	}

	cache.Store(session, first)
	cache.Store(session, second)

	if !first.IsClosed() {
		t.Fatal("expected replaced destination to be closed")
	}
	loadedDestination, loaded := cache.Lookup(session)
	if !loaded || loadedDestination != second {
		t.Fatalf("unexpected cache entry %#v loaded=%v", loadedDestination, loaded)
	}
}
