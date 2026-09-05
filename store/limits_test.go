package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservationLimitsAndLegacyCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.db")
	st, err := Open(Options{Path: path, MaxFingerprints: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.UpsertStatus("approved", StatusApproved, "keep"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxObservationValues+10; i++ {
		e, err := st.Observe(Observation{Fingerprint: "blocked", IP: fmt.Sprintf("2001:db8::%x", i), Port: i + 1}, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.IPs) > MaxObservationValues || len(e.Ports) > MaxObservationValues || len(e.Sightings) > MaxObservationValues {
			t.Fatal("unbounded history")
		}
	}
	if _, err := st.Observe(Observation{Fingerprint: "too-big", Meta: map[string]any{"raw": strings.Repeat("x", MaxMetadataBytes)}}, true); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	if _, err := st.Get("too-big"); err == nil {
		t.Fatal("rejected metadata persisted")
	}
	if _, err := st.Observe(Observation{Fingerprint: "new"}, true); err != nil {
		t.Fatal(err)
	}
	entries, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries["approved"].Label != "keep" {
		t.Fatalf("row cap/approval lost: %v", entries)
	}
	// Simulate the unbounded data an old binary could have left behind.
	if _, err := st.db.Exec(`UPDATE fingerprints SET meta = ? WHERE fp = 'approved'`, `{"raw":"`+strings.Repeat("x", MaxMetadataBytes)+`"}`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxObservationValues+10; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		if _, err := st.db.Exec(`INSERT INTO fingerprint_ips(fp,ip) VALUES('approved',?)`, ip); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`INSERT INTO fingerprint_ports(fp,port) VALUES('approved',?)`, i+1); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`INSERT INTO fingerprint_sightings(fp,ip,port,last_seen) VALUES('approved',?,?,'2026-01-01T00:00:00Z')`, ip, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	e, err := st.Get("approved")
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusApproved || e.Label != "keep" || len(e.Meta) != 0 || len(e.IPs) != 128 || len(e.Ports) != 128 || len(e.Sightings) != 128 {
		t.Fatalf("legacy bounds failed: %+v", e)
	}
}

func TestListPageStableBoundary(t *testing.T) {
	st, err := Open(Options{Path: filepath.Join(t.TempDir(), "gate.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, fp := range []string{"a", "b", "c"} {
		if _, err := st.Observe(Observation{Fingerprint: fp, IP: "192.0.2.1", Port: 22}, false); err != nil {
			t.Fatal(err)
		}
	}
	through, err := st.LastFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Observe(Observation{Fingerprint: "z"}, false); err != nil {
		t.Fatal(err)
	}
	var got []string
	after := ""
	for {
		page, err := st.ListPage(after, through, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			got = append(got, e.Fingerprint)
			if len(e.IPs) != 1 || len(e.Ports) != 1 || len(e.Sightings) != 1 {
				t.Fatal("missing history")
			}
		}
		after = page[len(page)-1].Fingerprint
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("page coverage: %v", got)
	}
}
