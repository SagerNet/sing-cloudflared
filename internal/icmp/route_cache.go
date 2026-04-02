package icmp

import (
	"sync"
	"time"
)

type RouteCache struct {
	access  sync.Mutex
	entries map[RouteSession]*routeCacheEntry
	timeout time.Duration
}

type routeCacheEntry struct {
	destination RouteDestination
	lastAccess  time.Time
}

func NewRouteCache(timeout time.Duration) *RouteCache {
	return &RouteCache{
		entries: make(map[RouteSession]*routeCacheEntry),
		timeout: timeout,
	}
}

func (c *RouteCache) Lookup(session RouteSession) (RouteDestination, bool) {
	c.access.Lock()
	entry, loaded := c.entries[session]
	if !loaded {
		c.access.Unlock()
		return nil, false
	}
	if time.Since(entry.lastAccess) > c.timeout {
		delete(c.entries, session)
		c.access.Unlock()
		entry.destination.Close()
		return nil, false
	}
	entry.lastAccess = time.Now()
	c.access.Unlock()
	return entry.destination, true
}

func (c *RouteCache) Store(session RouteSession, destination RouteDestination) {
	c.access.Lock()
	existing, loaded := c.entries[session]
	c.entries[session] = &routeCacheEntry{
		destination: destination,
		lastAccess:  time.Now(),
	}
	c.access.Unlock()
	if loaded {
		existing.destination.Close()
	}
}

func (c *RouteCache) Clear() {
	c.access.Lock()
	entries := c.entries
	c.entries = make(map[RouteSession]*routeCacheEntry)
	c.access.Unlock()
	for _, entry := range entries {
		entry.destination.Close()
	}
}
