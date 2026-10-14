package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.michaelspost.com/gatekit/store"
)

type observationReceiver struct {
	mu       sync.Mutex
	batches  []observationBatch
	fail     bool
	policies int
}

func (r *observationReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path == "/v1/policy" {
		r.policies++
		if err := json.NewEncoder(w).Encode(policyResponse{}); err != nil {
			panic(err)
		}
		return
	}
	var batch observationBatch
	if err := json.NewDecoder(req.Body).Decode(&batch); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	r.batches = append(r.batches, batch)
	if r.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}
func (r *observationReceiver) take() []observationBatch {
	r.mu.Lock()
	defer r.mu.Unlock()
	batches := r.batches
	r.batches = nil
	return batches
}
func (r *observationReceiver) setFailure(fail bool) { r.mu.Lock(); defer r.mu.Unlock(); r.fail = fail }
func observe(t *testing.T, st *store.Store, fp string) {
	t.Helper()
	if _, err := st.Observe(store.Observation{Fingerprint: fp, IP: "192.0.2.1", Port: 443}, false); err != nil {
		t.Fatal(err)
	}
}
func push(t *testing.T, s *Syncer) {
	t.Helper()
	if err := s.PushObservations(); err != nil {
		t.Fatal(err)
	}
}
func batchFingerprints(batches []observationBatch) []string {
	var result []string
	for _, batch := range batches {
		for _, obs := range batch.Observations {
			result = append(result, obs.Fingerprint)
		}
	}
	return result
}
func TestIncrementalUploadsHeartbeatChangesAndRecovery(t *testing.T) {
	st := openStore(t)
	for i := 0; i < 35; i++ {
		observe(t, st, fmt.Sprintf("fp%03d", i))
	}
	receiver := &observationReceiver{}
	srv := httptest.NewTLSServer(receiver)
	defer srv.Close()
	cfg := testTLSConfig(t, srv, "dummy")
	s, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	push(t, s)
	initial := receiver.take()
	if len(initial) != 3 || len(batchFingerprints(initial)) != 35 {
		t.Fatalf("initial snapshot: %+v", initial)
	}
	push(t, s)
	quiet := receiver.take()
	if len(quiet) != 1 || len(quiet[0].Observations) != 0 {
		t.Fatalf("quiet cycle: %+v", quiet)
	}
	observe(t, st, "fp003")
	observe(t, st, "fp035")
	push(t, s)
	if got := fmt.Sprint(batchFingerprints(receiver.take())); got != "[fp003 fp035]" {
		t.Fatalf("changed upload: %s", got)
	}
	// A server restore needs no explicit signal: the periodic full snapshot repairs it.
	s.lastFullSync = time.Now().Add(-FullSyncInterval)
	push(t, s)
	if got := len(batchFingerprints(receiver.take())); got != 36 {
		t.Fatalf("recovery snapshot: %d", got)
	}
	restarted, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	push(t, restarted)
	if got := len(batchFingerprints(receiver.take())); got != 36 {
		t.Fatalf("restart snapshot: %d", got)
	}
}
func TestFailedIncrementalUploadIsRetried(t *testing.T) {
	st := openStore(t)
	observe(t, st, "fp")
	receiver := &observationReceiver{}
	srv := httptest.NewTLSServer(receiver)
	defer srv.Close()
	s, err := New(st, testTLSConfig(t, srv, "dummy"))
	if err != nil {
		t.Fatal(err)
	}
	push(t, s)
	receiver.take()
	observe(t, st, "fp")
	receiver.setFailure(true)
	if err := s.PushObservations(); err == nil {
		t.Fatal("failed batch accepted")
	}
	receiver.take()
	receiver.setFailure(false)
	push(t, s)
	if got := fmt.Sprint(batchFingerprints(receiver.take())); got != "[fp]" {
		t.Fatalf("retry: %s", got)
	}
	push(t, s)
	if got := batchFingerprints(receiver.take()); len(got) != 0 {
		t.Fatalf("accepted batch resent: %v", got)
	}
	// Failed full snapshots remain due, even if incremental hashes are current.
	s.lastFullSync = time.Now().Add(-FullSyncInterval)
	receiver.setFailure(true)
	if err := s.PushObservations(); err == nil {
		t.Fatal("failed full snapshot accepted")
	}
	receiver.take()
	receiver.setFailure(false)
	push(t, s)
	if got := len(batchFingerprints(receiver.take())); got != 1 {
		t.Fatalf("full retry: %d", got)
	}
}
func TestIncrementalCacheForgetsDeletedFingerprints(t *testing.T) {
	st := openStore(t)
	observe(t, st, "fp")
	receiver := &observationReceiver{}
	srv := httptest.NewTLSServer(receiver)
	defer srv.Close()
	s, err := New(st, testTLSConfig(t, srv, "dummy"))
	if err != nil {
		t.Fatal(err)
	}
	push(t, s)
	receiver.take()
	if err := st.Delete("fp"); err != nil {
		t.Fatal(err)
	}
	push(t, s)
	if len(s.acknowledged) != 0 {
		t.Fatal("deleted fingerprint retained in cache")
	}
	batches := receiver.take()
	if len(batches) != 1 || len(batches[0].Observations) != 0 {
		t.Fatalf("empty store heartbeat: %+v", batches)
	}
}
func TestPolicyPollingContinuesForQuietAndFailedUploads(t *testing.T) {
	st := openStore(t)
	observe(t, st, "fp")
	receiver := &observationReceiver{}
	srv := httptest.NewTLSServer(receiver)
	defer srv.Close()
	s, err := New(st, testTLSConfig(t, srv, "dummy"))
	if err != nil {
		t.Fatal(err)
	}
	s.SyncOnce()
	s.SyncOnce()
	observe(t, st, "fp")
	receiver.setFailure(true)
	s.SyncOnce()
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	if receiver.policies != 3 {
		t.Fatalf("policy polls: %d", receiver.policies)
	}
	if len(receiver.batches) != 3 || len(receiver.batches[1].Observations) != 0 {
		t.Fatalf("batches: %+v", receiver.batches)
	}
}
