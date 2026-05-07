package scanner

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolver caches DNS lookups.
type Resolver struct {
	cache   map[string][]string
	mu      sync.RWMutex
	timeout time.Duration
}

// NewResolver creates a resolver.
func NewResolver(timeout int) *Resolver {
	if timeout <= 0 {
		timeout = 5
	}

	return &Resolver{
		cache:   make(map[string][]string),
		timeout: time.Duration(timeout) * time.Second,
	}
}

// ResolveIP resolves a domain to IP addresses.
func (r *Resolver) ResolveIP(domain string) ([]string, error) {
	r.mu.RLock()
	if ips, ok := r.cache[domain]; ok {
		r.mu.RUnlock()
		return ips, nil
	}
	r.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache[domain] = ips
	r.mu.Unlock()

	return ips, nil
}

// ReverseLookup performs a PTR lookup for an IP address.
func (r *Resolver) ReverseLookup(ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	return net.DefaultResolver.LookupAddr(ctx, ip)
}
