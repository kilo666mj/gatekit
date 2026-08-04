package ratelimit

import (
	"testing"
	"time"
)

func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	if !l.Allow("192.0.2.1") {
		t.Error("nil limiter denied")
	}
	l.Sweep() // must not panic
}

func TestBurstThenThrottle(t *testing.T) {
	l := New(1, 3, time.Minute)
	for i := range 3 {
		if !l.Allow("192.0.2.1") {
			t.Fatalf("denied within burst at %d", i)
		}
	}
	if l.Allow("192.0.2.1") {
		t.Error("allowed beyond burst")
	}
}

func TestRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1, time.Minute)
	l.now = func() time.Time { return now }

	if !l.Allow("192.0.2.1") {
		t.Fatal("first denied")
	}
	if l.Allow("192.0.2.1") {
		t.Fatal("second allowed without refill")
	}
	now = now.Add(time.Second)
	if !l.Allow("192.0.2.1") {
		t.Error("denied after a full second of refill")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	l := New(1, 1, time.Minute)
	if !l.Allow("192.0.2.1") || !l.Allow("192.0.2.2") {
		t.Error("one IP's budget affected another")
	}
}

// A client with a routed IPv6 prefix must not escape the limit by rotating
// through addresses it already controls.
func TestIPv6MaskedTo64(t *testing.T) {
	l := New(1, 1, time.Minute)
	if !l.Allow("2001:db8:1:2::1") {
		t.Fatal("first denied")
	}
	if l.Allow("2001:db8:1:2::dead:beef") {
		t.Error("same /64 got a fresh bucket")
	}
	if !l.Allow("2001:db8:1:3::1") {
		t.Error("different /64 was throttled")
	}
}

func TestKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.1", "192.0.2.1"},
		{"2001:db8:1:2::1", "2001:db8:1:2::"},
		{"not-an-ip", "not-an-ip"},
	} {
		if got := Key(tc.in); got != tc.want {
			t.Errorf("Key(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSweepEvictsIdle(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1, time.Minute)
	l.now = func() time.Time { return now }

	l.Allow("192.0.2.1")
	if len(l.buckets) != 1 {
		t.Fatalf("buckets = %d", len(l.buckets))
	}
	now = now.Add(2 * time.Minute)
	l.Sweep()
	if len(l.buckets) != 0 {
		t.Errorf("idle bucket survived sweep: %d", len(l.buckets))
	}
}

// The bucket map is attacker-controlled, so it must stop growing at the cap
// rather than consuming memory until the next sweep.
func TestMaxBucketsCap(t *testing.T) {
	l := New(1, 1, time.Minute)
	l.maxBuckets = 2
	if !l.Allow("192.0.2.1") || !l.Allow("192.0.2.2") {
		t.Fatal("denied under cap")
	}
	if !l.Allow("192.0.2.3") {
		t.Error("over-cap key should be allowed untracked, not denied")
	}
	if len(l.buckets) != 2 {
		t.Errorf("buckets = %d, want cap of 2", len(l.buckets))
	}
}

func TestRunSweeperStops(t *testing.T) {
	l := New(1, 1, time.Millisecond)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		l.RunSweeper(time.Millisecond, stop)
		close(done)
	}()
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunSweeper did not stop")
	}
}
