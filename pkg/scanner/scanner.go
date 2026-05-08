package scanner

import (
	"context"
	"fmt"
	"sync"
)

// Scanner coordinates collision probing.
type Scanner struct {
	config          *Config
	prober          *Prober
	limiter         *RateLimiter
	results         []*CollisionResult
	resultCount     int
	skippedCount    int
	timeoutCount    int
	storeResults    bool
	mu              sync.Mutex
	resultCallback  func(*CollisionResult)
	timeoutCallback func(*CollisionResult)
	logCallback     func(string)
	skipCallback    func(string, int, HostTarget) bool
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
		config:       config,
		prober:       NewProberWithHeaders(config.Timeout, config.Headers),
		limiter:      NewRateLimiter(config.QPS),
		results:      make([]*CollisionResult, 0),
		storeResults: true,
	}
}

// ScanTargets probes every IP, host header, and port combination.
func (s *Scanner) ScanTargets(ips []string, hosts []string) {
	s.ScanHostTargets(ips, ParseHostTargets(hosts, s.config.Path))
}

// ScanHostTargets probes every IP, parsed host target, and port combination.
func (s *Scanner) ScanHostTargets(ips []string, targets []HostTarget) {
	s.ScanHostTargetsContext(context.Background(), ips, targets)
}

// ScanHostTargetsContext probes every IP, parsed host target, and port combination until done or canceled.
func (s *Scanner) ScanHostTargetsContext(ctx context.Context, ips []string, targets []HostTarget) {
	if ctx == nil {
		ctx = context.Background()
	}

	var wg sync.WaitGroup
	jobs := make(chan probeJob, s.config.Threads)

	for worker := 0; worker < s.config.Threads; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					if err := s.limiter.Wait(ctx); err != nil {
						return
					}

					result := s.prober.Probe(ctx, job.ip, job.port, job.target)
					if ctx.Err() != nil {
						return
					}
					if shouldFilterTimeout(result) {
						s.addTimeout(result)
						s.logf("[~] Timeout %s:%d%s -> Host: %s | %s", job.ip, job.port, job.target.Path, job.target.Host, result.Error)
						continue
					}
					s.addResult(result)
					s.logf("[+] %s:%d%s -> Host: %s [%d] %dms", job.ip, job.port, job.target.Path, job.target.Host, result.StatusCode, result.ResponseTime)
				}
			}
		}()
	}

	for _, ip := range ips {
		for _, target := range targets {
			for _, port := range s.config.Ports {
				if ctx.Err() != nil {
					close(jobs)
					wg.Wait()
					return
				}
				if s.shouldSkip(ip, port, target) {
					s.addSkipped()
					s.logf("[=] Skipped completed %s:%d%s -> Host: %s", ip, port, target.Path, target.Host)
					continue
				}
				select {
				case <-ctx.Done():
					close(jobs)
					wg.Wait()
					return
				case jobs <- probeJob{ip: ip, target: target, port: port}:
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *Scanner) shouldSkip(ip string, port int, target HostTarget) bool {
	s.mu.Lock()
	cb := s.skipCallback
	s.mu.Unlock()

	return cb != nil && cb(ip, port, target)
}

func (s *Scanner) addSkipped() {
	s.mu.Lock()
	s.skippedCount++
	s.mu.Unlock()
}

func (s *Scanner) addResult(result *CollisionResult) {
	s.mu.Lock()
	s.resultCount++
	if s.storeResults {
		s.results = append(s.results, result)
	}
	cb := s.resultCallback
	s.mu.Unlock()

	if cb != nil {
		cb(result)
	}
}

func (s *Scanner) addTimeout(result *CollisionResult) {
	s.mu.Lock()
	s.timeoutCount++
	cb := s.timeoutCallback
	s.mu.Unlock()

	if cb != nil {
		cb(result)
	}
}

func (s *Scanner) logf(format string, args ...any) {
	s.mu.Lock()
	cb := s.logCallback
	s.mu.Unlock()

	if cb != nil {
		cb(fmt.Sprintf(format, args...))
	}
}

func shouldFilterTimeout(result *CollisionResult) bool {
	return result != nil && result.StatusCode == 0 && result.IsTimeout
}

type probeJob struct {
	ip     string
	target HostTarget
	port   int
}

// SetResultCallback registers a callback invoked for each result.
func (s *Scanner) SetResultCallback(cb func(*CollisionResult)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resultCallback = cb
}

// SetTimeoutCallback registers a callback invoked for timeout probes filtered out of results.
func (s *Scanner) SetTimeoutCallback(cb func(*CollisionResult)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.timeoutCallback = cb
}

// SetLogCallback registers a callback invoked for scanner log lines.
func (s *Scanner) SetLogCallback(cb func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logCallback = cb
}

// SetSkipCallback registers a callback that decides whether a probe should be skipped.
func (s *Scanner) SetSkipCallback(cb func(string, int, HostTarget) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.skipCallback = cb
}

// SetGUICallback registers a callback invoked for each result.
func (s *Scanner) SetGUICallback(cb func(*CollisionResult)) {
	s.SetResultCallback(cb)
}

// SetStoreResults controls whether results are retained in memory.
func (s *Scanner) SetStoreResults(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.storeResults = enabled
	if !enabled {
		s.results = nil
	}
}

// GetResults returns all collected results.
func (s *Scanner) GetResults() []*CollisionResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]*CollisionResult, len(s.results))
	copy(results, s.results)
	return results
}

// GetResultCount returns the number of completed probes.
func (s *Scanner) GetResultCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.resultCount
}

// GetSkippedCount returns the number of skipped probes.
func (s *Scanner) GetSkippedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.skippedCount
}

// GetTimeoutCount returns the number of timeout probes filtered out of results.
func (s *Scanner) GetTimeoutCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.timeoutCount
}
