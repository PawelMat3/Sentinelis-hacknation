// Package ratelimit provides a small context-aware token bucket used to cap
// probe intensity (connections / HTTP requests per second).
package ratelimit

import (
	"context"
	"sync"
	"time"
)

type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// New returns a limiter; rate <= 0 means unlimited (nil limiter).
func New(perSecond float64, burst int) *Limiter {
	if perSecond <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: perSecond, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

// Wait blocks until a token is available or ctx ends. A nil limiter never waits.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (l *Limiter) Rate() float64 {
	if l == nil {
		return 0
	}
	return l.rate
}
