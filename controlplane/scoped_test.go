package controlplane

import (
	"go.michaelspost.com/gatekit/store"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScopedPolicyCapabilityAndAtomicRejection(t *testing.T) {
	st := openStore(t)
	body := `{"cursor":"1","decisions":[{"fingerprint":"one","status":"approved","approval_ranges":["192.0.2.0/24"]}]}`
	var capability string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capability = r.Header.Get("X-Gatekit-Capabilities")
		if _, err := io.WriteString(w, body); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	cfg := testTLSConfig(t, srv, "t")
	s, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PullPolicy(); err == nil {
		t.Fatal("unsupported gate accepted scope")
	}
	cfg.SupportsApprovalRanges = true
	s, err = New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PullPolicy(); err != nil {
		t.Fatal(err)
	}
	if capability != "approval_ranges_v1" {
		t.Fatal(capability)
	}
	e, err := st.Get("one")
	if err != nil || e.ApprovalRanges == nil {
		t.Fatalf("missing scope %+v %v", e, err)
	}
	for _, bad := range []string{`{"fingerprint":"two","status":"approved","approval_ranges":[]}`, `{"fingerprint":"two","status":"invalid"}`, `{"fingerprint":"","status":"approved"}`} {
		body = `{"cursor":"2","decisions":[{"fingerprint":"one","status":"blocked"},` + bad + `]}`
		if err := s.PullPolicy(); err == nil {
			t.Fatal("accepted invalid batch")
		}
		e, err = st.Get("one")
		if err != nil || e.Status != store.StatusApproved || e.ApprovalRanges == nil {
			t.Fatalf("partially applied: %+v %v", e, err)
		}
		if s.cursor != "1" {
			t.Fatal(s.cursor)
		}
	}
	restarted, err := New(st, cfg)
	if err != nil || restarted.cursor != "1" {
		t.Fatalf("cursor not persisted: %v", err)
	}
}
