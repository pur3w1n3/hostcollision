package scanner

import (
	"context"

	"golang.org/x/time/rate"
)

// RateLimiter controls request throughput.
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(qps int) *RateLimiter {
	if qps <= 0 {
		qps = 1
	}

	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(qps), qps*2),
	}
}

// Wait blocks until the next token is available.
func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}
