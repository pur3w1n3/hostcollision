package scanner

import (
	"context"
	"fmt"
	"sync"
)

// Scanner coordinates collision probing.
type Scanner struct {
	config      *Config
	resolver    *Resolver
	prober      *Prober
	limiter     *RateLimiter
	results     []*CollisionResult
	mu          sync.Mutex
	guiCallback func(*CollisionResult)
}

// NewScanner creates a scanner.
func NewScanner(config *Config) *Scanner {
	if config.Threads <= 0 {
		config.Threads = 1
	}
	if len(config.Ports) == 0 {
		config.Ports = []int{80, 443}
	}

	return &Scanner{
		config:   config,
		resolver: NewResolver(config.Timeout),
		prober:   NewProber(config.Timeout),
		limiter:  NewRateLimiter(config.QPS),
		results:  make([]*CollisionResult, 0),
	}
}

// ScanIPToDomains probes one IP against many host names.
func (s *Scanner) ScanIPToDomains(ip string, domains []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Threads)

	for _, domain := range domains {
		for _, port := range s.config.Ports {
			wg.Add(1)
			go func(d string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ctx := context.Background()
				_ = s.limiter.Wait(ctx)

				result := s.prober.Probe(ctx, ip, p, d)
				s.addResult(result)
				fmt.Printf("[+] %s:%d -> %s [%d] %dms\n", ip, p, d, result.StatusCode, result.ResponseTime)
			}(domain, port)
		}
	}
	wg.Wait()
}

// ScanDomainToIPs probes one host name against many IPs.
func (s *Scanner) ScanDomainToIPs(domain string, ips []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Threads)

	for _, ip := range ips {
		for _, port := range s.config.Ports {
			wg.Add(1)
			go func(i string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ctx := context.Background()
				_ = s.limiter.Wait(ctx)

				result := s.prober.Probe(ctx, i, p, domain)
				s.addResult(result)
				fmt.Printf("[+] %s:%d -> %s [%d] %dms\n", i, p, domain, result.StatusCode, result.ResponseTime)
			}(ip, port)
		}
	}
	wg.Wait()
}

func (s *Scanner) addResult(result *CollisionResult) {
	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	if s.guiCallback != nil {
		s.guiCallback(result)
	}
}

// SetGUICallback registers a callback invoked for each result.
func (s *Scanner) SetGUICallback(cb func(*CollisionResult)) {
	s.guiCallback = cb
}

// GetResults returns all collected results.
func (s *Scanner) GetResults() []*CollisionResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]*CollisionResult, len(s.results))
	copy(results, s.results)
	return results
}
