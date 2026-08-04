package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// The schemas below are copied verbatim from the pre-gatekit gates, so these
// tests exercise the real shape of the databases in service on mx and the
// sshgate hosts — not an idealized one.

const sshgateLegacySchema = `
CREATE TABLE fingerprints (
	fp TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	client_id TEXT NOT NULL DEFAULT '',
	raw TEXT NOT NULL DEFAULT '',
	kex TEXT NOT NULL DEFAULT '',
	host_key TEXT NOT NULL DEFAULT '',
	cipher_c2s TEXT NOT NULL DEFAULT '',
	cipher_s2c TEXT NOT NULL DEFAULT '',
	mac_c2s TEXT NOT NULL DEFAULT '',
	mac_s2c TEXT NOT NULL DEFAULT '',
	compress_c2s TEXT NOT NULL DEFAULT '',
	compress_s2c TEXT NOT NULL DEFAULT '',
	first_kex_guess INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE fingerprint_ips (
	fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
	ip TEXT NOT NULL,
	PRIMARY KEY (fp, ip)
);
`

const tlsgateLegacySchema = `
CREATE TABLE fingerprints (
	fp TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	count INTEGER NOT NULL DEFAULT 0,
	ja3 TEXT NOT NULL DEFAULT '',
	ja4 TEXT NOT NULL DEFAULT '',
	sni TEXT NOT NULL DEFAULT '',
	alpn TEXT NOT NULL DEFAULT '[]',
	supported_versions TEXT NOT NULL DEFAULT '[]',
	signature_algorithms TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE fingerprint_ips (
	fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
	ip TEXT NOT NULL,
	PRIMARY KEY (fp, ip)
);
CREATE TABLE fingerprint_ports (
	fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
	port INTEGER NOT NULL,
	PRIMARY KEY (fp, port)
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`

// SSHLegacyColumns / TLSLegacyColumns mirror what each gate will pass to Open.
var sshLegacyColumns = []LegacyColumn{
	{Column: "client_id", MetaKey: "client_id"},
	{Column: "raw", MetaKey: "raw"},
	{Column: "kex", MetaKey: "kex"},
	{Column: "host_key", MetaKey: "host_key"},
	{Column: "cipher_c2s", MetaKey: "cipher_c2s"},
	{Column: "cipher_s2c", MetaKey: "cipher_s2c"},
	{Column: "mac_c2s", MetaKey: "mac_c2s"},
	{Column: "mac_s2c", MetaKey: "mac_s2c"},
	{Column: "compress_c2s", MetaKey: "compress_c2s"},
	{Column: "compress_s2c", MetaKey: "compress_s2c"},
	{Column: "first_kex_guess", MetaKey: "first_kex_guess", Kind: KindBool},
}

var tlsLegacyColumns = []LegacyColumn{
	{Column: "ja3", MetaKey: "ja3"},
	{Column: "ja4", MetaKey: "ja4"},
	{Column: "sni", MetaKey: "sni"},
	{Column: "alpn", MetaKey: "alpn", Kind: KindJSON},
	{Column: "supported_versions", MetaKey: "supported_versions", Kind: KindJSON},
	{Column: "signature_algorithms", MetaKey: "signature_algorithms", Kind: KindJSON},
}

func seedLegacy(t *testing.T, schema string, seed func(*sql.DB)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	seed(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}
	return path
}

func TestMigrateSSHgateDatabase(t *testing.T) {
	path := seedLegacy(t, sshgateLegacySchema, func(db *sql.DB) {
		if _, err := db.Exec(`
			INSERT INTO fingerprints (fp, status, label, first_seen, last_seen,
				client_id, raw, kex, host_key, cipher_c2s, cipher_s2c,
				mac_c2s, mac_s2c, compress_c2s, compress_s2c, first_kex_guess)
			VALUES ('fp1', 'approved', 'laptop', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z',
				'SSH-2.0-OpenSSH_9.6', 'rawblob', 'curve25519-sha256', 'ssh-ed25519',
				'aes256-gcm', 'aes256-gcm', 'hmac-sha2-256', 'hmac-sha2-256',
				'none', 'none', 1)`); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO fingerprint_ips (fp, ip) VALUES ('fp1', '192.0.2.10')`); err != nil {
			t.Fatalf("seed ips: %v", err)
		}
	})

	s, err := Open(Options{Path: path, Legacy: sshLegacyColumns})
	if err != nil {
		t.Fatalf("Open legacy sshgate db: %v", err)
	}
	defer s.Close()

	entry, err := s.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The verdict and its history are the whole point of the migration.
	if entry.Status != StatusApproved {
		t.Errorf("status = %q, want approved to survive migration", entry.Status)
	}
	if entry.Label != "laptop" {
		t.Errorf("label = %q", entry.Label)
	}
	if got := entry.FirstSeen.UTC().Format("2006-01-02"); got != "2026-01-01" {
		t.Errorf("first_seen = %v", got)
	}
	if len(entry.IPs) != 1 || entry.IPs[0] != "192.0.2.10" {
		t.Errorf("ips = %v", entry.IPs)
	}
	if got := entry.Meta["client_id"]; got != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("meta[client_id] = %v", got)
	}
	if got := entry.Meta["kex"]; got != "curve25519-sha256" {
		t.Errorf("meta[kex] = %v", got)
	}
	if got := entry.Meta["first_kex_guess"]; got != true {
		t.Errorf("meta[first_kex_guess] = %v (%T), want bool true", got, got)
	}

	// The gate must keep working against the migrated database.
	updated, err := s.Observe(Observation{
		Fingerprint: "fp1",
		IP:          "192.0.2.11",
		Meta:        map[string]any{"client_id": "SSH-2.0-OpenSSH_9.7"},
	}, false)
	if err != nil {
		t.Fatalf("Observe after migration: %v", err)
	}
	if updated.Status != StatusApproved {
		t.Errorf("status = %q after re-observation", updated.Status)
	}
	if got := updated.Meta["client_id"]; got != "SSH-2.0-OpenSSH_9.7" {
		t.Errorf("meta not refreshed: %v", got)
	}
}

func TestMigrateTLSgateDatabase(t *testing.T) {
	path := seedLegacy(t, tlsgateLegacySchema, func(db *sql.DB) {
		if _, err := db.Exec(`
			INSERT INTO fingerprints (fp, status, label, first_seen, last_seen, count,
				ja3, ja4, sni, alpn, supported_versions, signature_algorithms)
			VALUES ('fp1', 'blocked', 'scanner', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z', 42,
				'aabbcc', 't13d1516h2_8daaf6152771_b186095e22b6', 'mail.example.com',
				'["h2","http/1.1"]', '[772,771]', '[2052,1027]')`); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO fingerprint_ports (fp, port) VALUES ('fp1', 993)`); err != nil {
			t.Fatalf("seed ports: %v", err)
		}
	})

	s, err := Open(Options{Path: path, Legacy: tlsLegacyColumns})
	if err != nil {
		t.Fatalf("Open legacy tlsgate db: %v", err)
	}
	defer s.Close()

	entry, err := s.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Status != StatusBlocked {
		t.Errorf("status = %q, want blocked", entry.Status)
	}
	if entry.Count != 42 {
		t.Errorf("count = %d, want 42 preserved", entry.Count)
	}
	if len(entry.Ports) != 1 || entry.Ports[0] != 993 {
		t.Errorf("ports = %v", entry.Ports)
	}
	if got := entry.Meta["sni"]; got != "mail.example.com" {
		t.Errorf("meta[sni] = %v", got)
	}
	// JSON-valued legacy columns must decode into real lists, not strings, or
	// gatehub receives quoted JSON blobs where it expects arrays.
	alpn, ok := entry.Meta["alpn"].([]any)
	if !ok {
		t.Fatalf("meta[alpn] = %#v, want []any", entry.Meta["alpn"])
	}
	if len(alpn) != 2 || alpn[0] != "h2" {
		t.Errorf("meta[alpn] = %v", alpn)
	}
	versions, ok := entry.Meta["supported_versions"].([]any)
	if !ok || len(versions) != 2 {
		t.Fatalf("meta[supported_versions] = %#v", entry.Meta["supported_versions"])
	}
}

// Re-opening must not re-run the fold, or metadata the gate has refreshed
// since would be reverted to whatever the legacy columns still hold.
func TestMigrateIsIdempotent(t *testing.T) {
	path := seedLegacy(t, sshgateLegacySchema, func(db *sql.DB) {
		if _, err := db.Exec(`
			INSERT INTO fingerprints (fp, status, first_seen, last_seen, client_id)
			VALUES ('fp1', 'approved', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'old-client')`); err != nil {
			t.Fatalf("seed: %v", err)
		}
	})

	s, err := Open(Options{Path: path, Legacy: sshLegacyColumns})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := s.Observe(Observation{Fingerprint: "fp1", Meta: map[string]any{"client_id": "new-client"}}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	s.Close()

	s2, err := Open(Options{Path: path, Legacy: sshLegacyColumns})
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s2.Close()
	entry, err := s2.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := entry.Meta["client_id"]; got != "new-client" {
		t.Errorf("meta[client_id] = %v, want refreshed value to survive reopen", got)
	}
}

// A fresh database has none of the legacy columns; the fold must be a no-op
// rather than an error.
func TestMigrateFreshDatabase(t *testing.T) {
	s, err := Open(Options{
		Path:   filepath.Join(t.TempDir(), "fresh.db"),
		Legacy: sshLegacyColumns,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := s.Observe(Observation{Fingerprint: "fp1"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
}

// Inserting a fingerprint the legacy database has never seen is the first
// thing a migrated gate does in production. gatekit's INSERT names only its
// own columns, so every leftover legacy column must supply a default —
// otherwise a NOT NULL violation takes the gate down on the first new client.
func TestObserveNewFingerprintOnMigratedDatabase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema string
		legacy []LegacyColumn
	}{
		{"sshgate", sshgateLegacySchema, sshLegacyColumns},
		{"tlsgate", tlsgateLegacySchema, tlsLegacyColumns},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := seedLegacy(t, tc.schema, func(db *sql.DB) {
				if _, err := db.Exec(`
					INSERT INTO fingerprints (fp, status, first_seen, last_seen)
					VALUES ('old', 'approved', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
					t.Fatalf("seed: %v", err)
				}
			})
			s, err := Open(Options{Path: path, Legacy: tc.legacy})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer s.Close()
			entry, err := s.Observe(Observation{
				Fingerprint: "brandnew",
				IP:          "192.0.2.99",
				Port:        22,
				Meta:        map[string]any{"k": "v"},
			}, false)
			if err != nil {
				t.Fatalf("Observe new fingerprint: %v", err)
			}
			if entry.Status != StatusPending || entry.Count != 1 {
				t.Errorf("entry = %+v", entry)
			}
		})
	}
}

// Rolling back to the pre-gatekit binary must still find its schema, so the
// legacy columns have to survive the migration untouched.
func TestMigrateLeavesLegacyColumnsIntact(t *testing.T) {
	path := seedLegacy(t, sshgateLegacySchema, func(db *sql.DB) {
		if _, err := db.Exec(`
			INSERT INTO fingerprints (fp, status, first_seen, last_seen, kex)
			VALUES ('fp1', 'approved', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'curve25519-sha256')`); err != nil {
			t.Fatalf("seed: %v", err)
		}
	})
	s, err := Open(Options{Path: path, Legacy: sshLegacyColumns})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen raw: %v", err)
	}
	defer db.Close()
	var kex string
	if err := db.QueryRow(`SELECT kex FROM fingerprints WHERE fp = 'fp1'`).Scan(&kex); err != nil {
		t.Fatalf("legacy column gone: %v", err)
	}
	if kex != "curve25519-sha256" {
		t.Errorf("kex = %q", kex)
	}
}
