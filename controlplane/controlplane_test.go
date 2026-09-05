package controlplane

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/kilo666mj/gatekit/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConfigValidate(t *testing.T) {
	base := Config{URL: "https://gatehub.example.com", InstanceID: "mx", Token: "t"}
	if err := base.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	noID := base
	noID.InstanceID = ""
	if err := noID.Validate(); err == nil {
		t.Error("missing instance_id accepted")
	}
	noAuth := base
	noAuth.Token = ""
	if err := noAuth.Validate(); err == nil {
		t.Error("config with no token and no client cert accepted")
	}
	mtls := Config{URL: base.URL, InstanceID: "mx", ClientCert: "c", ClientKey: "k", CA: "ca"}
	if err := mtls.Validate(); err != nil {
		t.Errorf("mTLS config rejected: %v", err)
	}
	badURL := base
	badURL.URL = "://nope"
	if err := badURL.Validate(); err == nil {
		t.Error("bad url accepted")
	}
	for _, rawURL := range []string{
		"http://gatehub.example.com",
		"/gatehub",
		"https:///gatehub",
		"ftp://gatehub.example.com",
	} {
		insecure := base
		insecure.URL = rawURL
		if err := insecure.Validate(); err == nil {
			t.Errorf("insecure control-plane URL %q accepted", rawURL)
		}
	}
	badInterval := base
	badInterval.SyncInterval = "soon"
	if err := badInterval.Validate(); err == nil {
		t.Error("bad sync_interval accepted")
	}
}

func TestConfigInterval(t *testing.T) {
	if got := (Config{}).Interval(); got != DefaultSyncInterval {
		t.Errorf("empty = %v", got)
	}
	if got := (Config{SyncInterval: "5s"}).Interval(); got != 5*time.Second {
		t.Errorf("5s = %v", got)
	}
	// A nonsense or non-positive value must fall back, not busy-loop.
	if got := (Config{SyncInterval: "-1s"}).Interval(); got != DefaultSyncInterval {
		t.Errorf("negative = %v", got)
	}
}

func TestPushObservations(t *testing.T) {
	st := openStore(t)
	if _, err := st.Observe(store.Observation{
		Fingerprint: "fp1",
		IP:          "192.0.2.1",
		Port:        993,
		Meta:        map[string]any{"sni": "mail.example.com"},
	}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	var got observationBatch
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Query().Get("instance_id") != "mx" {
			t.Errorf("instance_id = %q", r.URL.Query().Get("instance_id"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New(st, testTLSConfig(t, srv, "secret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.PushObservations(); err != nil {
		t.Fatalf("PushObservations: %v", err)
	}
	if auth != "Bearer secret" {
		t.Errorf("auth header = %q", auth)
	}
	if len(got.Observations) != 1 {
		t.Fatalf("observations = %d", len(got.Observations))
	}
	obs := got.Observations[0]
	if obs.Fingerprint != "fp1" || obs.Status != store.StatusPending {
		t.Errorf("obs = %+v", obs)
	}
	if obs.Count != 1 || len(obs.Ports) != 1 || obs.Ports[0] != 993 {
		t.Errorf("count/ports = %d/%v", obs.Count, obs.Ports)
	}
	if len(obs.Sightings) != 1 || obs.Sightings[0].IP != "192.0.2.1" || obs.Sightings[0].Port != 993 {
		t.Errorf("sightings = %+v", obs.Sightings)
	}
	// The metadata bag rides through untouched — this is what lets one syncer
	// serve every gate without knowing the protocol.
	if obs.Metadata["sni"] != "mail.example.com" {
		t.Errorf("metadata = %v", obs.Metadata)
	}
}

// A 403 almost always means the instance was never registered with gatehub;
// the error has to say so or the operator is left staring at a status code.
func TestPushObservationsForbiddenMessage(t *testing.T) {
	st := openStore(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s, _ := New(st, testTLSConfig(t, srv, "t"))
	err := s.PushObservations()
	if err == nil {
		t.Fatal("want error")
	}
	if want := "not registered with gatehub"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want it to mention %q", err, want)
	}
}

func TestPullPolicyAppliesDecisions(t *testing.T) {
	st := openStore(t)
	if _, err := st.Observe(store.Observation{Fingerprint: "known", IP: "192.0.2.1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	var sawCursor string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCursor = r.URL.Query().Get("since")
		json.NewEncoder(w).Encode(policyResponse{
			Cursor: "cursor-2",
			Decisions: []decision{
				{Fingerprint: "known", Status: store.StatusBlocked, Label: "bad"},
				{Fingerprint: "unseen", Status: store.StatusApproved, Label: "preapproved"},
				{Fingerprint: "", Status: store.StatusApproved},
				{Fingerprint: "junk", Status: store.Status("nonsense")},
			},
		})
	}))
	defer srv.Close()

	s, _ := New(st, testTLSConfig(t, srv, "t"))
	if err := s.PullPolicy(); err != nil {
		t.Fatalf("PullPolicy: %v", err)
	}
	if sawCursor != "" {
		t.Errorf("first pull sent cursor %q", sawCursor)
	}

	known, err := st.Get("known")
	if err != nil {
		t.Fatalf("Get known: %v", err)
	}
	if known.Status != store.StatusBlocked || known.Label != "bad" {
		t.Errorf("known = %+v", known)
	}
	// A decision for a fingerprint this gate has never seen must land as a
	// placeholder, so the verdict is in force before the client first connects.
	unseen, err := st.Get("unseen")
	if err != nil {
		t.Fatalf("Get unseen: %v", err)
	}
	if unseen.Status != store.StatusApproved {
		t.Errorf("unseen = %+v", unseen)
	}
	// An unparseable status is skipped, not applied and not fatal.
	if _, err := st.Get("junk"); err == nil {
		t.Error("invalid status was applied")
	}

	if err := s.PullPolicy(); err != nil {
		t.Fatalf("second PullPolicy: %v", err)
	}
	if sawCursor != "cursor-2" {
		t.Errorf("cursor not advanced: %q", sawCursor)
	}
}

func TestPullPolicyAppliesTrustedRangesWhenPresent(t *testing.T) {
	st := openStore(t)
	ranges := []string{"192.0.2.4/32", "2001:db8:1234::/64"}
	var applied []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(policyResponse{TrustedRanges: &ranges})
	}))
	defer srv.Close()

	s, _ := New(st, Config{
		URL: srv.URL, InstanceID: "web", Token: "t", CA: testTLSConfig(t, srv, "t").CA,
		ApplyTrustedRanges: func(got []string) error {
			applied = append([]string(nil), got...)
			return nil
		},
	})
	if err := s.PullPolicy(); err != nil {
		t.Fatalf("PullPolicy: %v", err)
	}
	if !slices.Equal(applied, ranges) {
		t.Fatalf("trusted ranges = %v, want %v", applied, ranges)
	}
}

func TestPullPolicyOmittedTrustedRangesPreservesLocalState(t *testing.T) {
	st := openStore(t)
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(policyResponse{})
	}))
	defer srv.Close()

	s, _ := New(st, Config{
		URL: srv.URL, InstanceID: "web", Token: "t", CA: testTLSConfig(t, srv, "t").CA,
		ApplyTrustedRanges: func([]string) error { called = true; return nil },
	})
	if err := s.PullPolicy(); err != nil {
		t.Fatalf("PullPolicy: %v", err)
	}
	if called {
		t.Fatal("omitted trusted_ranges unexpectedly replaced local state")
	}
}

func TestStartNoopWithoutURL(t *testing.T) {
	if err := Start(t.Context(), openStore(t), Config{}); err != nil {
		t.Errorf("Start with no control plane = %v, want nil", err)
	}
}

func TestStartValidatesConfig(t *testing.T) {
	if err := Start(t.Context(), openStore(t), Config{URL: "https://example.com"}); err == nil {
		t.Error("Start accepted config with no instance_id")
	}
}

func TestLimited(t *testing.T) {
	if got := limited([]string{"a", "b", "c"}, 2); len(got) != 2 {
		t.Errorf("len = %d", len(got))
	}
	if got := limited([]int{1, 2}, 5); len(got) != 2 {
		t.Errorf("len = %d", len(got))
	}
	if got := limited([]string{"a"}, 0); len(got) != 1 {
		t.Errorf("max<=0 should not truncate, got %v", got)
	}
}

func TestEndpointURL(t *testing.T) {
	got, err := endpointURL("https://gatehub.example.com/base/", "/v1/policy", "mx", "cur")
	if err != nil {
		t.Fatalf("endpointURL: %v", err)
	}
	want := "https://gatehub.example.com/base/v1/policy?instance_id=mx&since=cur"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func testTLSConfig(t *testing.T, srv *httptest.Server, token string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{URL: srv.URL, InstanceID: "mx", Token: token, CA: path}
}
