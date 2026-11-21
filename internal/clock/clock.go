// Package clock abstracts time so the scheduler, time windows and the demo
// seeder can run against a virtual clock (deterministic tests, demo data
// spanning several "days" generated in seconds).
package clock

import (
	"context"
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done. A fake clock advances instantly.
	Sleep(ctx context.Context, d time.Duration) error
	// Virtual reports whether time is simulated.
	Virtual() bool
}

type Real struct{}

func (Real) Now() time.Time { return time.Now() }
func (Real) Virtual() bool  { return false }
func (Real) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Fake is a manually advanced clock.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

func NewFake(t time.Time) *Fake { return &Fake{now: t} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	f.now = t
	f.mu.Unlock()
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *Fake) Virtual() bool { return true }

func (f *Fake) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.Advance(d)
	return nil
}
