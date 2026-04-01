package cloudflared

import (
	"sync"
	"time"
)

type routeCache struct {
	access  sync.Mutex
	entries map[ICMPRouteSession]*routeCacheEntry
	timeout time.Duration
}

type routeCacheEntry struct {
	destination ICMPRouteDestination
	lastAccess  time.Time
}

func newRouteCache(timeout time.Duration) *routeCache {
	return &routeCache{
		entries: make(map[ICMPRouteSession]*routeCacheEntry),
		timeout: timeout,
	}
}

func (c *routeCache) Lookup(session ICMPRouteSession) (ICMPRouteDestination, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	entry, loaded := c.entries[session]
	if !loaded {
		return nil, false
	}
	if time.Since(entry.lastAccess) > c.timeout {
		delete(c.entries, session)
		entry.destination.Close()
		return nil, false
	}
	entry.lastAccess = time.Now()
	return entry.destination, true
}

func (c *routeCache) Store(session ICMPRouteSession, destination ICMPRouteDestination) {
	c.access.Lock()
	defer c.access.Unlock()
	existing, loaded := c.entries[session]
	if loaded {
		existing.destination.Close()
	}
	c.entries[session] = &routeCacheEntry{
		destination: destination,
		lastAccess:  time.Now(),
	}
}

func (c *routeCache) Clear() {
	c.access.Lock()
	defer c.access.Unlock()
	for session, entry := range c.entries {
		entry.destination.Close()
		delete(c.entries, session)
	}
}
