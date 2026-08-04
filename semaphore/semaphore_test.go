package semaphore

import "testing"

func TestNilIsUnbounded(t *testing.T) {
	var s *Semaphore
	for range 100 {
		if !s.Acquire() {
			t.Fatal("nil semaphore denied")
		}
	}
	s.Release() // must not panic
}

func TestAcquireBounds(t *testing.T) {
	s := New(2)
	if !s.Acquire() || !s.Acquire() {
		t.Fatal("denied within capacity")
	}
	if s.Acquire() {
		t.Error("allowed beyond capacity")
	}
	s.Release()
	if !s.Acquire() {
		t.Error("denied after release freed a slot")
	}
}

// Release is called from deferred cleanup paths that can run when no slot was
// held; an extra Release must not create capacity out of nothing.
func TestReleaseWithoutAcquire(t *testing.T) {
	s := New(1)
	s.Release()
	s.Release()
	if !s.Acquire() {
		t.Fatal("denied on empty semaphore")
	}
	if s.Acquire() {
		t.Error("stray releases inflated capacity")
	}
}
