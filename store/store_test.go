package store

import (
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestObserveFirstSighting(t *testing.T) {
	s := openTest(t)
	entry, err := s.Observe(Observation{
		Fingerprint: "fp1",
		IP:          "192.0.2.1",
		Port:        443,
		Meta:        map[string]any{"sni": "example.com"},
	}, false)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if entry.Status != StatusPending {
		t.Errorf("status = %q, want pending", entry.Status)
	}
	if entry.Count != 1 {
		t.Errorf("count = %d, want 1", entry.Count)
	}
	if got := entry.Meta["sni"]; got != "example.com" {
		t.Errorf("meta[sni] = %v, want example.com", got)
	}
	if len(entry.IPs) != 1 || entry.IPs[0] != "192.0.2.1" {
		t.Errorf("ips = %v", entry.IPs)
	}
	if len(entry.Ports) != 1 || entry.Ports[0] != 443 {
		t.Errorf("ports = %v", entry.Ports)
	}
	if len(entry.Sightings) != 1 || entry.Sightings[0].IP != "192.0.2.1" || entry.Sightings[0].Port != 443 || entry.Sightings[0].LastSeen.IsZero() {
		t.Errorf("sightings = %+v", entry.Sightings)
	}
}

func TestObserveBlockUnknown(t *testing.T) {
	s := openTest(t)
	entry, err := s.Observe(Observation{Fingerprint: "fp1", IP: "192.0.2.1"}, true)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if entry.Status != StatusBlocked {
		t.Errorf("status = %q, want blocked", entry.Status)
	}
}

// A repeat sighting must not resurrect a fingerprint an operator has already
// judged: status, label and first_seen stay put while the sighting data moves.
func TestObservePreservesVerdict(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "fp1", IP: "192.0.2.1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := s.SetStatus("fp1", StatusApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := s.SetLabel("fp1", "laptop"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	first, err := s.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	entry, err := s.Observe(Observation{Fingerprint: "fp1", IP: "192.0.2.2", Port: 22}, true)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if entry.Status != StatusApproved {
		t.Errorf("status = %q, want approved to survive re-observation", entry.Status)
	}
	if entry.Label != "laptop" {
		t.Errorf("label = %q, want laptop", entry.Label)
	}
	if !entry.FirstSeen.Equal(first.FirstSeen.Time) {
		t.Errorf("first_seen moved: %v -> %v", first.FirstSeen, entry.FirstSeen)
	}
	if entry.Count != 2 {
		t.Errorf("count = %d, want 2", entry.Count)
	}
	if len(entry.IPs) != 2 {
		t.Errorf("ips = %v, want both sightings", entry.IPs)
	}
}

// UpsertStatus writes a placeholder for a fingerprint that has never been
// seen; the first real sighting must adopt that verdict rather than reset it
// to pending. This is how gatehub pre-approves a fingerprint on a fresh gate.
func TestUpsertStatusPlaceholderSurvivesFirstSighting(t *testing.T) {
	s := openTest(t)
	if err := s.UpsertStatus("fp1", StatusApproved, "preapproved"); err != nil {
		t.Fatalf("UpsertStatus: %v", err)
	}
	entry, err := s.Observe(Observation{Fingerprint: "fp1", IP: "192.0.2.1"}, true)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if entry.Status != StatusApproved {
		t.Errorf("status = %q, want approved", entry.Status)
	}
	if entry.Label != "preapproved" {
		t.Errorf("label = %q", entry.Label)
	}
}

// Changing a verdict must not disturb the label. An operator who re-approves
// a fingerprint without repeating its label would otherwise lose the only
// thing making that row identifiable later.
func TestSetStatusPreservesLabel(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "fp1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := s.SetLabel("fp1", "michael-laptop"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	if err := s.SetStatus("fp1", StatusApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	entry, err := s.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Label != "michael-laptop" {
		t.Errorf("label = %q, want it preserved across a status change", entry.Label)
	}
	if entry.Status != StatusApproved {
		t.Errorf("status = %q", entry.Status)
	}
}

func TestSetStatusUnknownFingerprint(t *testing.T) {
	s := openTest(t)
	if err := s.SetStatus("nope", StatusApproved); err == nil {
		t.Fatal("SetStatus on unknown fingerprint: want error")
	}
}

func TestSetStatusRejectsInvalid(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "fp1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := s.SetStatus("fp1", Status("wat")); err == nil {
		t.Fatal("want error for invalid status")
	}
}

func TestListAttachesSightings(t *testing.T) {
	s := openTest(t)
	for _, obs := range []Observation{
		{Fingerprint: "fp1", IP: "192.0.2.1", Port: 22},
		{Fingerprint: "fp1", IP: "192.0.2.2", Port: 2222},
		{Fingerprint: "fp2", IP: "192.0.2.3", Port: 443},
	} {
		if _, err := s.Observe(obs, false); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	if got := all["fp1"]; len(got.IPs) != 2 || len(got.Ports) != 2 {
		t.Errorf("fp1 ips=%v ports=%v", got.IPs, got.Ports)
	}
	if got := all["fp2"].Fingerprint; got != "fp2" {
		t.Errorf("entry.Fingerprint = %q", got)
	}
}

// Pruning is the defence against unbounded disk growth from unauthenticated
// scanners, so it must evict the stalest unknowns and never an approval.
func TestPruneToLimitKeepsApproved(t *testing.T) {
	s := openTest(t)
	for _, fp := range []string{"a", "b", "c", "d"} {
		if _, err := s.Observe(Observation{Fingerprint: fp, IP: "192.0.2.1"}, false); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	if err := s.SetStatus("a", StatusApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	deleted, err := s.PruneToLimit(2)
	if err != nil {
		t.Fatalf("PruneToLimit: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := all["a"]; !ok {
		t.Error("approved entry was pruned")
	}
	if len(all) != 2 {
		t.Errorf("remaining = %d, want 2", len(all))
	}
}

func TestPruneToLimitDisabled(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "a"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	n, err := s.PruneToLimit(0)
	if err != nil || n != 0 {
		t.Fatalf("PruneToLimit(0) = %d, %v", n, err)
	}
}

func TestDeleteCascadesSightings(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "fp1", IP: "192.0.2.1", Port: 22}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := s.Delete("fp1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	var n int
	if err := s.reader.QueryRow(`SELECT COUNT(*) FROM fingerprint_ips`).Scan(&n); err != nil {
		t.Fatalf("count ips: %v", err)
	}
	if n != 0 {
		t.Errorf("orphaned ip rows: %d", n)
	}
}

func TestResolveFingerprint(t *testing.T) {
	s := openTest(t)
	for _, fp := range []string{"abcdef123", "abcxyz789", "zzz111"} {
		if _, err := s.Observe(Observation{Fingerprint: fp}, false); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	got, err := s.ResolveFingerprint("zzz")
	if err != nil || got != "zzz111" {
		t.Errorf("ResolveFingerprint(zzz) = %q, %v", got, err)
	}
	if got, err := s.ResolveFingerprint("abcdef123"); err != nil || got != "abcdef123" {
		t.Errorf("exact match = %q, %v", got, err)
	}
	if _, err := s.ResolveFingerprint("abc"); err == nil {
		t.Error("want ambiguous-prefix error")
	}
	if _, err := s.ResolveFingerprint("qqq"); err == nil {
		t.Error("want no-match error")
	}
}

// A LIKE wildcard in the query must be treated literally, or "%" would match
// an arbitrary fingerprint and an operator could approve the wrong client.
func TestResolveFingerprintEscapesWildcards(t *testing.T) {
	s := openTest(t)
	if _, err := s.Observe(Observation{Fingerprint: "abcdef"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := s.ResolveFingerprint("%"); err == nil {
		t.Error("wildcard query matched; want no-match error")
	}
	if _, err := s.ResolveFingerprint("_bcdef"); err == nil {
		t.Error("underscore wildcard matched; want no-match error")
	}
}

func TestMetaRoundTrip(t *testing.T) {
	s := openTest(t)
	got, err := s.GetMeta("absent")
	if err != nil || got != "" {
		t.Fatalf("GetMeta(absent) = %q, %v", got, err)
	}
	if err := s.SetMeta("k", "v1"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := s.SetMeta("k", "v2"); err != nil {
		t.Fatalf("SetMeta overwrite: %v", err)
	}
	if got, _ := s.GetMeta("k"); got != "v2" {
		t.Errorf("GetMeta = %q, want v2", got)
	}
}

// Switching fingerprint method changes the keyspace, so every stored approval
// becomes meaningless. Refuse to start unless the caller opts into the wipe.
func TestReconcileFingerprintMethod(t *testing.T) {
	s := openTest(t)
	if _, err := s.ReconcileFingerprintMethod("ja3", false); err != nil {
		t.Fatalf("adopt on fresh db: %v", err)
	}
	if got, _ := s.GetMeta(MetaFingerprintMethod); got != "ja3" {
		t.Fatalf("method = %q, want ja3", got)
	}
	if _, err := s.Observe(Observation{Fingerprint: "fp1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := s.ReconcileFingerprintMethod("ja4", false); err == nil {
		t.Fatal("switching method without reset: want error")
	}
	deleted, err := s.ReconcileFingerprintMethod("ja4", true)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	if got, _ := s.GetMeta(MetaFingerprintMethod); got != "ja4" {
		t.Errorf("method = %q, want ja4", got)
	}
}

func TestBlockedRangeAlertDedupe(t *testing.T) {
	s := openTest(t)
	first, err := s.RecordBlockedRangeAlert("office", "192.0.2.1", "fp1")
	if err != nil || !first {
		t.Fatalf("first record = %v, %v; want true", first, err)
	}
	again, err := s.RecordBlockedRangeAlert("office", "192.0.2.1", "fp1")
	if err != nil || again {
		t.Fatalf("second record = %v, %v; want false", again, err)
	}
	has, err := s.HasBlockedRangeAlert("office", "192.0.2.1")
	if err != nil || !has {
		t.Fatalf("HasBlockedRangeAlert = %v, %v", has, err)
	}
	if err := s.ForgetBlockedRangeAlert("office", "192.0.2.1"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if has, _ := s.HasBlockedRangeAlert("office", "192.0.2.1"); has {
		t.Error("alert still recorded after forget")
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "test.db")
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("want error for empty path")
	}
}
