// Package ratelimit provides the per-source-IP token bucket a gate uses to cap
// how fast a single client can have connections processed.
package ratelimit

import (
	"net"
	"sync"
	"time"
)

// DefaultMaxBuckets bounds the bucket map so a flood of distinct source keys
// cannot exhaust memory between sweeps. When the cap is hit, new keys are
// allowed without tracking (the caller's global concurrency semaphore still
// applies).
const DefaultMaxBuckets = 1 << 20

// Limiter caps how frequently a single source IP can have connections
// processed. This bounds two things at once: connection-flood load, and the
// velocity of unbounded fingerprint-row growth from randomized handshakes (a
// single attacker IP can only ever persist new rows at the refill rate).
//
// It is a per-key token bucket. A key (source IP) starts with burst tokens;
// each accepted connection spends one; tokens refill at rate per second up to
// burst. Idle buckets are evicted by Sweep so the map itself cannot grow
// without bound. ttl must be >= burst/rate so that an evicted bucket would
// already have refilled to full — eviction is then indistinguishable from
// keeping a full bucket, and never resets a still-throttled attacker.
//
// A nil *Limiter allows everything.
type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       float64 // tokens added per second
	burst      float64 // bucket capacity
	ttl        time.Duration
	maxBuckets int
	now        func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter refilling at rate tokens/sec, capacity burst, evicting
// buckets idle longer than ttl.
func New(rate, burst float64, ttl time.Duration) *Limiter {
	return &Limiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		ttl:        ttl,
		maxBuckets: DefaultMaxBuckets,
		now:        time.Now,
	}
}

// Key normalizes a source IP into a bucket key. IPv6 addresses are masked to
// their /64 so a client with a routed prefix cannot bypass the limit (or
// balloon the bucket map) by rotating through addresses it controls.
func Key(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ip
	}
	if addr.To4() != nil {
		return ip
	}
	return addr.Mask(net.CIDRMask(64, 128)).String()
}

// Allow consumes a token for the source IP and reports whether the event may
// proceed. The IP is normalized with Key.
func (l *Limiter) Allow(ip string) bool {
	if l == nil {
		return true
	}
	key := Key(ip)
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if l.maxBuckets > 0 && len(l.buckets) >= l.maxBuckets {
			// Map full: allow without tracking to bound memory.
			return true
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep evicts buckets idle longer than ttl. Safe because such a bucket has
// refilled to burst and is identical to a freshly created one.
func (l *Limiter) Sweep() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.ttl)
	for key, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// RunSweeper evicts idle buckets every interval until stop is closed. Callers
// typically run it in its own goroutine for the life of the process.
func (l *Limiter) RunSweeper(interval time.Duration, stop <-chan struct{}) {
	if l == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			l.Sweep()
		}
	}
}
