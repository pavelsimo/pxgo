// Package dnscache provides a small TTL cache in front of net.LookupIP so hot
// paths (noproxy matching, PAC dnsResolve) do not hit the resolver on every
// request.
package dnscache

import (
	"net"
	"sync"
	"time"
)

const (
	positiveTTL = 60 * time.Second
	negativeTTL = 5 * time.Second
	maxEntries  = 4096
)

// lookupIP is swappable in tests.
var lookupIP = net.LookupIP

type entry struct {
	ips     []net.IP
	expires time.Time
}

var (
	mu    sync.RWMutex
	cache = map[string]entry{}
)

// Lookup resolves host, serving repeated lookups from a TTL cache. It returns
// nil when resolution fails; failures are cached briefly so a broken resolver
// is not hammered.
func Lookup(host string) []net.IP {
	now := time.Now()
	mu.RLock()
	e, ok := cache[host]
	mu.RUnlock()
	if ok && now.Before(e.expires) {
		return e.ips
	}
	ips, err := lookupIP(host)
	ttl := positiveTTL
	if err != nil {
		ips = nil
		ttl = negativeTTL
	}
	mu.Lock()
	if len(cache) >= maxEntries {
		evictLocked(now)
	}
	cache[host] = entry{ips: ips, expires: now.Add(ttl)}
	mu.Unlock()
	return ips
}

// evictLocked drops expired entries; if nothing has expired the whole cache is
// reset, which is cheap and keeps the map bounded without extra bookkeeping.
func evictLocked(now time.Time) {
	for host, e := range cache {
		if now.After(e.expires) {
			delete(cache, host)
		}
	}
	if len(cache) >= maxEntries {
		cache = map[string]entry{}
	}
}

// ResetForTest clears the cache.
func ResetForTest() {
	mu.Lock()
	cache = map[string]entry{}
	mu.Unlock()
}
