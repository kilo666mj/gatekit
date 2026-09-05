package store

import (
	"context"
	"database/sql"
	"fmt"
)

const (
	// MaxMetadataBytes bounds one stored metadata bag, including its JSON encoding.
	MaxMetadataBytes = 64 * 1024
	// MaxObservationValues bounds each fingerprint's IP, port and sighting history.
	MaxObservationValues = 128
)

// trimHistory runs inside Observe's transaction, before history is read back.
func trimHistory(ctx context.Context, tx *sql.Tx, fp string) error {
	for _, stmt := range []string{
		`DELETE FROM fingerprint_sightings WHERE fp = ? AND (ip, port) IN (SELECT ip, port FROM fingerprint_sightings WHERE fp = ? ORDER BY last_seen DESC, ip, port LIMIT -1 OFFSET ?)`,
		`DELETE FROM fingerprint_ips WHERE fp = ? AND ip IN (SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip LIMIT -1 OFFSET ?)`,
		`DELETE FROM fingerprint_ports WHERE fp = ? AND port IN (SELECT port FROM fingerprint_ports WHERE fp = ? ORDER BY port LIMIT -1 OFFSET ?)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, fp, fp, MaxObservationValues); err != nil {
			return err
		}
	}
	return nil
}

// boundExistingHistory also handles databases created by older releases. Verdicts
// and labels survive; oversized metadata is discarded rather than truncated into
// invalid JSON. SQLite may retain freed pages for reuse.
func (s *Store) boundExistingHistory() error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE fingerprints SET meta = '{}' WHERE length(CAST(meta AS BLOB)) > ?`, MaxMetadataBytes); err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM fingerprint_sightings WHERE (fp,ip,port) IN (SELECT fp,ip,port FROM (SELECT fp,ip,port,ROW_NUMBER() OVER (PARTITION BY fp ORDER BY last_seen DESC,ip,port) AS n FROM fingerprint_sightings) WHERE n > ?)`,
		`DELETE FROM fingerprint_ips WHERE (fp,ip) IN (SELECT fp,ip FROM (SELECT fp,ip,ROW_NUMBER() OVER (PARTITION BY fp ORDER BY ip) AS n FROM fingerprint_ips) WHERE n > ?)`,
		`DELETE FROM fingerprint_ports WHERE (fp,port) IN (SELECT fp,port FROM (SELECT fp,port,ROW_NUMBER() OVER (PARTITION BY fp ORDER BY port) AS n FROM fingerprint_ports) WHERE n > ?)`,
	} {
		if _, err := tx.Exec(stmt, MaxObservationValues); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LastFingerprint provides a fixed upper bound for a paginated sync, preventing
// a continuous stream of new fingerprints from making one cycle run forever.
func (s *Store) LastFingerprint() (string, error) {
	var fp string
	err := s.reader.QueryRow(`SELECT COALESCE(MAX(fp),'') FROM fingerprints`).Scan(&fp)
	return fp, err
}

// ListPage reads a bounded, sorted page and only that page's observation history.
// It is an eventually consistent view; concurrent observations are picked up by
// the next synchronization cycle.
func (s *Store) ListPage(after, through string, limit int) ([]Entry, error) {
	if limit < 1 || limit > 128 {
		return nil, fmt.Errorf("page size must be between 1 and 128")
	}
	rows, err := s.reader.Query(`SELECT `+entryColumns+` FROM fingerprints WHERE fp > ? AND fp <= ? ORDER BY fp LIMIT ?`, after, through, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	ctx := context.Background()
	for i := range entries {
		e := &entries[i]
		if e.IPs, err = listStringsFrom(ctx, s.reader, `SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip`, e.Fingerprint); err != nil {
			return nil, err
		}
		if e.Ports, err = listIntsFrom(ctx, s.reader, `SELECT port FROM fingerprint_ports WHERE fp = ? ORDER BY port`, e.Fingerprint); err != nil {
			return nil, err
		}
		if e.Sightings, err = listSightingsFrom(ctx, s.reader, `SELECT ip,port,last_seen FROM fingerprint_sightings WHERE fp = ? ORDER BY last_seen DESC,ip,port`, e.Fingerprint); err != nil {
			return nil, err
		}
	}
	return entries, nil
}
