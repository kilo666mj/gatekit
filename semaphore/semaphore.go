// Package semaphore provides a counting semaphore for bounding the number of
// connections a gate processes concurrently.
package semaphore

// Semaphore bounds the number of connections processed concurrently,
// regardless of source IP. The per-IP rate limiter stops a single address from
// flooding; this caps the total goroutines, file descriptors, and backend dials
// in flight so a distributed flood (e.g. many IPv6 source addresses, each below
// the per-IP ceiling) cannot exhaust them.
//
// A nil *Semaphore is valid and unbounded, so callers can treat "no limit" as
// the zero configuration without branching.
type Semaphore struct {
	slots chan struct{}
}

// New returns a semaphore with n slots.
func New(n int) *Semaphore {
	return &Semaphore{slots: make(chan struct{}, n)}
}

// Acquire takes a slot without blocking and reports whether one was free.
// A nil Semaphore is unbounded and always succeeds.
func (s *Semaphore) Acquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot. It must be called exactly once per successful
// Acquire. A nil Semaphore is a no-op.
func (s *Semaphore) Release() {
	if s == nil {
		return
	}
	select {
	case <-s.slots:
	default:
	}
}
