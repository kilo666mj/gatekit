// Package store is the SQLite fingerprint store shared by gatekit gates.
//
// A gate records one row per observed fingerprint, keyed by an opaque
// fingerprint string, along with the source IPs and ports it was seen from, a
// sighting count, and a protocol-specific metadata bag. Protocol fields are
// deliberately untyped here: SSH stores kex/cipher/MAC lists, TLS stores
// SNI/ALPN/versions, and the store treats both as JSON so a new gate needs no
// schema change.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Status is a fingerprint's verdict.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusBlocked  Status = "blocked"
)

// Valid reports whether s is a recognized status.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusBlocked:
		return true
	}
	return false
}

// Entry is a stored fingerprint and everything observed about it.
type Entry struct {
	Fingerprint string         `json:"fingerprint"`
	Status      Status         `json:"status"`
	Label       string         `json:"label,omitempty"`
	FirstSeen   Time           `json:"first_seen"`
	LastSeen    Time           `json:"last_seen"`
	Count       int            `json:"count"`
	IPs         []string       `json:"ips,omitempty"`
	Ports       []int          `json:"ports,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
}

// Observation is one sighting of a fingerprint on the gate's hot path.
type Observation struct {
	Fingerprint string
	IP          string
	Port        int
	// Meta replaces the stored metadata bag wholesale on every sighting, so
	// the row always reflects the most recent handshake.
	Meta map[string]any
}

// Store is the fingerprint database.
type Store struct {
	path string
	// db is the writer handle, pinned to a single connection so writes
	// serialize cleanly under SQLite. reader is a separate WAL read pool so
	// hot-path lookups don't queue behind the writer.
	db     *sql.DB
	reader *sql.DB
}

// maxReaders bounds the read pool. WAL allows many concurrent readers
// alongside the single writer.
const maxReaders = 8

// Options configures Open.
type Options struct {
	// Path is the SQLite file. Its parent directory is created if missing.
	Path string
	// Legacy describes typed protocol columns from a pre-gatekit schema that
	// should be folded into the Meta bag on first open. See LegacyColumn.
	Legacy []LegacyColumn
}

// dsn builds a modernc sqlite DSN that applies the given pragmas on every
// connection in the pool. PRAGMAs are per-connection state, so setting them
// with a one-off Exec against a pooled *sql.DB only configures whichever
// connection happens to serve it — they must go through the DSN.
func dsn(path string, pragmas ...string) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	return path + "?" + q.Encode()
}

// Open opens (creating if needed) the fingerprint database at opts.Path.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("empty database path")
	}
	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	writerDSN := dsn(opts.Path, "busy_timeout=5000", "foreign_keys=ON", "journal_mode=WAL", "synchronous=NORMAL")
	db, err := sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, err
	}
	// A single writer connection: SQLite serializes writes anyway, and pinning
	// one connection keeps transactions off a pool that could hand a later
	// statement to a different connection.
	db.SetMaxOpenConns(1)

	reader, err := sql.Open("sqlite", dsn(opts.Path, "busy_timeout=5000", "foreign_keys=ON", "journal_mode=WAL"))
	if err != nil {
		db.Close()
		return nil, err
	}
	reader.SetMaxOpenConns(maxReaders)

	s := &Store{path: opts.Path, db: db, reader: reader}
	if err := s.init(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.migrateLegacy(opts.Legacy); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate legacy columns: %w", err)
	}
	return s, nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

func (s *Store) Close() error {
	var errs []error
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
	}
	if s.db != nil {
		errs = append(errs, s.db.Close())
	}
	return errors.Join(errs...)
}

func (s *Store) init() error {
	ctx := context.Background()
	// Connection pragmas are applied via the DSN so every pooled connection
	// gets them; init only owns schema.
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS fingerprints (
			fp TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 0,
			meta TEXT NOT NULL DEFAULT '{}'
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_ips (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			PRIMARY KEY (fp, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_ports (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			port INTEGER NOT NULL,
			PRIMARY KEY (fp, port)
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_range_alerts (
			range_name TEXT NOT NULL,
			ip TEXT NOT NULL,
			fp TEXT NOT NULL,
			first_seen TEXT NOT NULL,
			PRIMARY KEY (range_name, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON fingerprints(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_ips_ip ON fingerprint_ips(ip)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	// Columns added to the fingerprints table after the original gate schemas
	// shipped. Databases created by sshgate or tlsgate before gatekit predate
	// one or both of these.
	for _, column := range []struct{ name, def string }{
		{"count", "INTEGER NOT NULL DEFAULT 0"},
		{"meta", "TEXT NOT NULL DEFAULT '{}'"},
	} {
		if err := s.addColumnIfMissing(ctx, "fingerprints", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, table, column, def string) error {
	has, err := s.hasColumn(ctx, table, column)
	if err != nil || has {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

func (s *Store) hasColumn(ctx context.Context, table, column string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notNull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}

const entryColumns = `fp, status, label, first_seen, last_seen, count, meta`

type scanner interface {
	Scan(dest ...any) error
}

// scanEntry decodes entryColumns (without IPs/ports) from a row.
func scanEntry(sc scanner) (Entry, error) {
	var firstSeen, lastSeen, metaJSON string
	var e Entry
	if err := sc.Scan(&e.Fingerprint, &e.Status, &e.Label, &firstSeen, &lastSeen, &e.Count, &metaJSON); err != nil {
		return Entry{}, err
	}
	parsedFirstSeen, err := decodeTime(firstSeen)
	if err != nil {
		return Entry{}, fmt.Errorf("decode first_seen: %w", err)
	}
	parsedLastSeen, err := decodeTime(lastSeen)
	if err != nil {
		return Entry{}, fmt.Errorf("decode last_seen: %w", err)
	}
	e.FirstSeen = Time{Time: parsedFirstSeen}
	e.LastSeen = Time{Time: parsedLastSeen}
	if strings.TrimSpace(metaJSON) != "" {
		if err := json.Unmarshal([]byte(metaJSON), &e.Meta); err != nil {
			return Entry{}, fmt.Errorf("decode meta: %w", err)
		}
	}
	return e, nil
}

func encodeMeta(meta map[string]any) (string, error) {
	if len(meta) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Observe records a sighting and returns the resulting entry.
//
// On first sight the row is inserted with status pending, or blocked when
// blockUnknown is set. On a repeat sighting only last_seen, count, and the
// metadata bag are refreshed — status, label, and first_seen are left intact,
// which preserves a prior verdict (and any pre-approved placeholder row
// created by UpsertStatus) while still recording the latest handshake.
func (s *Store) Observe(obs Observation, blockUnknown bool) (Entry, error) {
	if obs.Fingerprint == "" {
		return Entry{}, errors.New("empty fingerprint")
	}
	metaJSON, err := encodeMeta(obs.Meta)
	if err != nil {
		return Entry{}, err
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback()

	now := encodeTime(time.Now())
	status := StatusPending
	if blockUnknown {
		status = StatusBlocked
	}
	// Scan the upserted row (status/label may differ from what we inserted,
	// e.g. a pre-approved placeholder) before committing.
	row := tx.QueryRowContext(ctx, `
		INSERT INTO fingerprints (fp, status, label, first_seen, last_seen, count, meta)
		VALUES (?, ?, '', ?, ?, 1, ?)
		ON CONFLICT(fp) DO UPDATE SET
			last_seen = excluded.last_seen,
			count = fingerprints.count + 1,
			meta = excluded.meta
		RETURNING `+entryColumns,
		obs.Fingerprint, status, now, now, metaJSON,
	)
	entry, err := scanEntry(row)
	if err != nil {
		return Entry{}, err
	}
	if obs.IP != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fingerprint_ips (fp, ip) VALUES (?, ?)`, obs.Fingerprint, obs.IP); err != nil {
			return Entry{}, err
		}
	}
	if obs.Port != 0 {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fingerprint_ports (fp, port) VALUES (?, ?)`, obs.Fingerprint, obs.Port); err != nil {
			return Entry{}, err
		}
	}
	ips, err := listStringsFrom(ctx, tx, `SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip`, obs.Fingerprint)
	if err != nil {
		return Entry{}, err
	}
	ports, err := listIntsFrom(ctx, tx, `SELECT port FROM fingerprint_ports WHERE fp = ? ORDER BY port`, obs.Fingerprint)
	if err != nil {
		return Entry{}, err
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, err
	}
	entry.IPs = ips
	entry.Ports = ports
	return entry, nil
}

// Get loads a single entry by fingerprint via the read pool. Used on the proxy
// hot path so each lookup is one indexed read off the writer.
func (s *Store) Get(fp string) (Entry, error) {
	ctx := context.Background()
	e, err := scanEntry(s.reader.QueryRowContext(ctx, `SELECT `+entryColumns+` FROM fingerprints WHERE fp = ?`, fp))
	if err != nil {
		return Entry{}, err
	}
	if e.IPs, err = listStringsFrom(ctx, s.reader, `SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip`, fp); err != nil {
		return Entry{}, err
	}
	if e.Ports, err = listIntsFrom(ctx, s.reader, `SELECT port FROM fingerprint_ports WHERE fp = ? ORDER BY port`, fp); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// List returns every entry keyed by fingerprint, with IPs and ports attached.
func (s *Store) List() (map[string]Entry, error) {
	ctx := context.Background()
	rows, err := s.reader.QueryContext(ctx, `SELECT `+entryColumns+` FROM fingerprints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]Entry)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out[e.Fingerprint] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Fetch the sighting lists in two sweeps rather than per entry, so List is
	// three queries regardless of how many fingerprints are stored.
	ips, err := allStrings(ctx, s.reader, `SELECT fp, ip FROM fingerprint_ips ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	ports, err := allInts(ctx, s.reader, `SELECT fp, port FROM fingerprint_ports ORDER BY port`)
	if err != nil {
		return nil, err
	}
	for fp, e := range out {
		e.IPs = ips[fp]
		e.Ports = ports[fp]
		out[fp] = e
	}
	return out, nil
}

// SetStatus updates an existing fingerprint's status and label. It fails if
// the fingerprint is not present; use UpsertStatus to pre-seed a verdict for a
// fingerprint that has not been seen yet.
func (s *Store) SetStatus(fp string, status Status, label string) error {
	if !status.Valid() {
		return fmt.Errorf("invalid status %q", status)
	}
	res, err := s.db.Exec(`UPDATE fingerprints SET status = ?, label = ? WHERE fp = ?`, status, label, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

// UpsertStatus sets a verdict, creating a placeholder row if the fingerprint
// has never been observed. Observe preserves the status of an existing row, so
// a placeholder written here survives the first real sighting.
func (s *Store) UpsertStatus(fp string, status Status, label string) error {
	if !status.Valid() {
		return fmt.Errorf("invalid status %q", status)
	}
	now := encodeTime(time.Now())
	_, err := s.db.Exec(`
		INSERT INTO fingerprints (fp, status, label, first_seen, last_seen, count, meta)
		VALUES (?, ?, ?, ?, ?, 0, '{}')
		ON CONFLICT(fp) DO UPDATE SET status = excluded.status, label = excluded.label`,
		fp, status, label, now, now)
	return err
}

// SetLabel updates only the label of an existing fingerprint.
func (s *Store) SetLabel(fp, label string) error {
	res, err := s.db.Exec(`UPDATE fingerprints SET label = ? WHERE fp = ?`, label, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

// Delete removes a fingerprint. Its IPs and ports cascade.
func (s *Store) Delete(fp string) error {
	res, err := s.db.Exec(`DELETE FROM fingerprints WHERE fp = ?`, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

// PruneToLimit enforces a cap on the number of stored fingerprints, bounding
// disk growth from unauthenticated unknown clients. When the count exceeds
// max, it deletes the oldest non-approved entries (by last_seen) until the
// count is back at or below max, or until only approved entries remain.
// Approved fingerprints are authoritative and never evicted. max <= 0 disables
// pruning. Returns the number of entries deleted (ips/ports cascade).
func (s *Store) PruneToLimit(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fingerprints`).Scan(&total); err != nil {
		return 0, err
	}
	excess := total - max
	if excess <= 0 {
		return 0, nil
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM fingerprints WHERE fp IN (
			SELECT fp FROM fingerprints
			WHERE status != ?
			ORDER BY last_seen ASC
			LIMIT ?
		)`, StatusApproved, excess)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// ResolveFingerprint maps a user-supplied query to exactly one stored
// fingerprint, accepting either the full value or an unambiguous prefix so
// CLIs don't force operators to paste full hashes.
func (s *Store) ResolveFingerprint(query string) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", errors.New("empty fingerprint")
	}
	var exact string
	err := s.reader.QueryRow(`SELECT fp FROM fingerprints WHERE fp = ?`, query).Scan(&exact)
	if err == nil {
		return exact, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	// LIKE with an escaped prefix: _ and % are wildcards in SQLite.
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query)
	rows, err := s.reader.Query(`SELECT fp FROM fingerprints WHERE fp LIKE ? ESCAPE '\' ORDER BY fp LIMIT 2`, escaped+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var matches []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return "", err
		}
		matches = append(matches, fp)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no fingerprint matching %q", query)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("fingerprint prefix %q is ambiguous", query)
	}
}

// GetMeta reads a key from the meta table, returning "" when absent.
func (s *Store) GetMeta(key string) (string, error) {
	var value string
	err := s.reader.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// SetMeta writes a key to the meta table.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ResetFingerprints deletes every fingerprint row. Used when a gate's
// fingerprint method changes and the existing keyspace is invalidated.
func (s *Store) ResetFingerprints() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM fingerprints`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MetaFingerprintMethod is the meta key recording which fingerprint method the
// stored keys were computed with. The fingerprint is method-specific, so
// switching methods changes the keyspace and silently invalidates every
// approval and block; gates record the method here to detect that.
const MetaFingerprintMethod = "fingerprint_method"

// ReconcileFingerprintMethod compares the stored fingerprint method against
// method. When they differ it either wipes the now-meaningless rows (reset) or
// reports how many entries were computed with the old method so the caller can
// refuse to start. It returns the number of rows deleted.
func (s *Store) ReconcileFingerprintMethod(method string, reset bool) (int64, error) {
	stored, err := s.GetMeta(MetaFingerprintMethod)
	if err != nil {
		return 0, err
	}
	if stored == method {
		return 0, nil
	}
	if stored == "" {
		// Fresh database, or one predating the marker: adopt the method
		// without touching rows.
		return 0, s.SetMeta(MetaFingerprintMethod, method)
	}
	if !reset {
		var stale int64
		if err := s.reader.QueryRow(`SELECT COUNT(*) FROM fingerprints`).Scan(&stale); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("database holds %d fingerprints computed with method %q, but %q is configured; approvals and blocks do not carry over", stale, stored, method)
	}
	deleted, err := s.ResetFingerprints()
	if err != nil {
		return 0, err
	}
	return deleted, s.SetMeta(MetaFingerprintMethod, method)
}

// RecordBlockedRangeAlert notes that a blocked fingerprint was seen from ip
// inside a watched range, and reports whether this was the first such sighting
// — i.e. whether the caller should actually alert. Deduping lives here so an
// alerting gate doesn't re-notify on every reconnect.
func (s *Store) RecordBlockedRangeAlert(rangeName, ip, fp string) (bool, error) {
	res, err := s.db.Exec(`
		INSERT OR IGNORE INTO blocked_range_alerts (range_name, ip, fp, first_seen)
		VALUES (?, ?, ?, ?)`, rangeName, ip, fp, encodeTime(time.Now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// HasBlockedRangeAlert reports whether an alert was already recorded.
func (s *Store) HasBlockedRangeAlert(rangeName, ip string) (bool, error) {
	var one int
	err := s.reader.QueryRow(`SELECT 1 FROM blocked_range_alerts WHERE range_name = ? AND ip = ?`, rangeName, ip).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ForgetBlockedRangeAlert clears the dedupe record so a future sighting alerts
// again.
func (s *Store) ForgetBlockedRangeAlert(rangeName, ip string) error {
	_, err := s.db.Exec(`DELETE FROM blocked_range_alerts WHERE range_name = ? AND ip = ?`, rangeName, ip)
	return err
}

func requireAffected(res sql.Result, fp string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("unknown fingerprint %q", fp)
	}
	return nil
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listStringsFrom(ctx context.Context, q querier, query, fp string) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func listIntsFrom(ctx context.Context, q querier, query, fp string) ([]int, error) {
	rows, err := q.QueryContext(ctx, query, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func allStrings(ctx context.Context, q querier, query string) (map[string][]string, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]string)
	for rows.Next() {
		var fp, v string
		if err := rows.Scan(&fp, &v); err != nil {
			return nil, err
		}
		out[fp] = append(out[fp], v)
	}
	return out, rows.Err()
}

func allInts(ctx context.Context, q querier, query string) (map[string][]int, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]int)
	for rows.Next() {
		var fp string
		var v int
		if err := rows.Scan(&fp, &v); err != nil {
			return nil, err
		}
		out[fp] = append(out[fp], v)
	}
	for _, v := range out {
		sort.Ints(v)
	}
	return out, rows.Err()
}
