package store

import (
	"database/sql"
	"go.michaelspost.com/gatekit/approval"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestScopedDecisionPersistsAndLegacySettersCannotBroaden(t *testing.T) {
	s := openTest(t)
	scope, err := approval.New([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{Fingerprint: "shared", Status: StatusApproved, Label: "client", ApprovalRanges: scope}
	if err := s.ApplyDecisions([]Decision{d}, "cursor", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus("shared", StatusApproved); err == nil {
		t.Fatal("SetStatus broadened scope")
	}
	if err := s.UpsertStatus("shared", StatusApproved, "new"); err == nil {
		t.Fatal("UpsertStatus broadened scope")
	}
	e, err := s.Observe(Observation{Fingerprint: "shared", IP: "198.51.100.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.ApprovalRanges == nil || e.ApprovalRanges.Allows(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("observation lost scope")
	}
	reopened, err := Open(Options{Path: s.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	e, err = reopened.Get("shared")
	if err != nil || e.ApprovalRanges == nil {
		t.Fatalf("restart: %+v %v", e, err)
	}
	if err := s.SetStatus("shared", StatusBlocked); err != nil {
		t.Fatal(err)
	}
	e, err = s.Get("shared")
	if err != nil || e.ApprovalRanges != nil {
		t.Fatalf("block scope: %+v %v", e, err)
	}
	if err := s.ApplyDecisions([]Decision{d}, "", ""); err != nil {
		t.Fatal(err)
	}
	d.ApprovalRanges = nil
	if err := s.ApplyDecisions([]Decision{d}, "", ""); err != nil {
		t.Fatal(err)
	}
	e, err = s.Get("shared")
	if err != nil || e.ApprovalRanges != nil {
		t.Fatalf("explicit removal: %+v %v", e, err)
	}
}
func TestDecisionBatchAndCursorRollback(t *testing.T) {
	s := openTest(t)
	if err := s.ApplyDecisions([]Decision{{Fingerprint: "one", Status: StatusBlocked}}, "cursor", "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_second BEFORE INSERT ON fingerprints WHEN NEW.fp='two' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.ApplyDecisions([]Decision{{Fingerprint: "one", Status: StatusApproved}, {Fingerprint: "two", Status: StatusApproved}}, "cursor", "new")
	if err == nil {
		t.Fatal("expected database failure")
	}
	e, err := s.Get("one")
	if err != nil || e.Status != StatusBlocked {
		t.Fatalf("partial policy: %+v %v", e, err)
	}
	cursor, err := s.GetMeta("cursor")
	if err != nil || cursor != "old" {
		t.Fatalf("cursor: %q %v", cursor, err)
	}
}
func TestLegacyScopeMigrationAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE fingerprints(fp TEXT PRIMARY KEY,status TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,count INTEGER NOT NULL DEFAULT 0,meta TEXT NOT NULL DEFAULT '{}'); INSERT INTO fingerprints(fp,status,first_seen,last_seen) VALUES('legacy','approved','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	e, err := s.Get("legacy")
	if err != nil || e.Status != StatusApproved || e.ApprovalRanges != nil {
		t.Fatalf("legacy changed: %+v %v", e, err)
	}
	for _, bad := range []string{"[]", "null", "broken"} {
		if _, err := s.db.Exec(`UPDATE fingerprints SET approval_ranges=? WHERE fp='legacy'`, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("legacy"); err == nil {
			t.Fatalf("accepted corrupt scope %s", bad)
		}
	}
}
