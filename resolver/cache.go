package resolver

import (
	"context"
	"net"
	"sync"
	"time"
)

type cachingEntry struct {
	ip      net.IP
	expires time.Time
}

// CachingResolver wraps another NameResolver and caches results
// for a configurable TTL.
type CachingResolver struct {
	resolver NameResolver
	ttl      time.Duration
	mu       sync.Mutex
	cache    map[string]cachingEntry
}

// NewCachingResolver creates a resolver that caches DNS lookups.
// If the provided resolver is nil, DNSResolver is used.
func NewCachingResolver(res NameResolver, ttl time.Duration) *CachingResolver {
	if res == nil {
		res = DNSResolver{}
	}
	return &CachingResolver{
		resolver: res,
		ttl:      ttl,
		cache:    make(map[string]cachingEntry),
	}
}

// Resolve resolves the name and caches the result until the TTL expires.
func (c *CachingResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	now := time.Now()
	c.mu.Lock()
	if entry, ok := c.cache[name]; ok && now.Before(entry.expires) {
		ip := make(net.IP, len(entry.ip))
		copy(ip, entry.ip)
		c.mu.Unlock()
		return ctx, ip, nil
	}
	c.mu.Unlock()

	ctx, ip, err := c.resolver.Resolve(ctx, name)
	if err != nil {
		return ctx, ip, err
	}

	c.mu.Lock()
	c.cache[name] = cachingEntry{ip: ip, expires: now.Add(c.ttl)}
	c.mu.Unlock()

	return ctx, ip, nil
}
