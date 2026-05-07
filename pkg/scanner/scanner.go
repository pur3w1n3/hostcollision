package scanner

import (
	"context"
	"fmt"
	"sync"
)

// Scanner coordinates collision probing.
type Scanner struct {
	config      *Config
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
		config:  config,
		prober:  NewProberWithHeaders(config.Timeout, config.Headers),
		limiter: NewRateLimiter(config.QPS),
		results: make([]*CollisionResult, 0),
	}
}

// ScanTargets probes every IP, host header, and port combination.
func (s *Scanner) ScanTargets(ips []string, hosts []string) {
	s.ScanHostTargets(ips, ParseHostTargets(hosts, s.config.Path))
}

// ScanHostTargets probes every IP, parsed host target, and port combination.
func (s *Scanner) ScanHostTargets(ips []string, targets []HostTarget) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Threads)

	for _, ip := range ips {
		for _, target := range targets {
			for _, port := range s.config.Ports {
				wg.Add(1)
				go func(i string, t HostTarget, p int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					ctx := context.Background()
					_ = s.limiter.Wait(ctx)

					result := s.prober.Probe(ctx, i, p, t)
					s.addResult(result)
					fmt.Printf("[+] %s:%d%s -> Host: %s [%d] %dms\n", i, p, t.Path, t.Host, result.StatusCode, result.ResponseTime)
				}(ip, target, port)
			}
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
