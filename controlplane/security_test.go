package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kilo666mj/gatekit/store"
)

func TestRejectInsecureURLs(t *testing.T) {
	for _, url := range []string{"http://example.com", "http://127.0.0.1", "/relative", "https:///path", "https://user:password@example.com"} {
		cfg := Config{URL: url, InstanceID: "mx", Token: "dummy"}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted %q", url)
		}
		if _, err := New(nil, cfg); err == nil {
			t.Errorf("New accepted %q", url)
		}
	}
}

func TestRedirectCannotTransmitCredentialsOrApplyPolicy(t *testing.T) {
	st := openStore(t)
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte(`{"decisions":[{"fingerprint":"injected","status":"approved"}]}`))
	}))
	defer target.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, code) }))
			defer srv.Close()
			s, err := New(st, testTLSConfig(t, srv, "dummy"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.PullPolicy(); err == nil {
				t.Fatal("redirected policy accepted")
			}
			if err := s.PushObservations(); err == nil {
				t.Fatal("redirected push accepted")
			}
			if reached.Load() {
				t.Fatal("redirect destination received request")
			}
			if _, err := st.Get("injected"); err == nil {
				t.Fatal("redirected policy applied")
			}
		})
	}
}

func TestPushObservationsUsesBoundedPages(t *testing.T) {
	st := openStore(t)
	for i := 0; i < 35; i++ {
		if _, err := st.Observe(store.Observation{Fingerprint: fmt.Sprintf("fp%03d", i)}, true); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[string]bool)
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch observationBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		if len(batch.Observations) > 16 {
			t.Error("page exceeded bound")
		}
		requests++
		for _, e := range batch.Observations {
			if seen[e.Fingerprint] {
				t.Error("duplicate observation")
			}
			seen[e.Fingerprint] = true
		}
	}))
	defer srv.Close()
	s, err := New(st, testTLSConfig(t, srv, "dummy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PushObservations(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 35 || requests != 3 {
		t.Fatalf("seen %d in %d requests", len(seen), requests)
	}
}

func TestCancelledSyncDoesNotMakeRequest(t *testing.T) {
	st := openStore(t)
	var reached atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer srv.Close()
	s, err := New(st, testTLSConfig(t, srv, "dummy"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.pushObservations(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if reached.Load() {
		t.Fatal("cancelled sync sent a request")
	}
}
