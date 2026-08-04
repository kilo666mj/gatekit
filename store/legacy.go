package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Kind describes how a legacy column's text value should be decoded when it is
// folded into the Meta bag.
type Kind int

const (
	// KindString stores the column verbatim.
	KindString Kind = iota
	// KindBool stores a 0/1 integer column as a JSON boolean.
	KindBool
	// KindJSON stores a column that already holds JSON text (a list, say) as
	// the decoded value rather than as a quoted string.
	KindJSON
)

// LegacyColumn maps one typed column from a pre-gatekit gate schema onto a key
// in the Meta bag.
//
// sshgate and tlsgate both predate gatekit and have live databases with
// protocol fields in dedicated columns (client_id, kex, ja3, sni, …). Open
// folds those values into meta once, so an in-service database keeps its
// approvals, blocks, labels and history across the migration. The old columns
// are left in place — they all carry defaults, so new inserts ignore them —
// which keeps the change reversible: rolling back to the pre-gatekit binary
// finds its schema intact.
type LegacyColumn struct {
	Column  string
	MetaKey string
	Kind    Kind
}

// metaLegacyMigrated marks that the one-time fold has run, so a later restart
// cannot overwrite metadata that gates have refreshed since.
const metaLegacyMigrated = "gatekit_legacy_migrated"

func (s *Store) migrateLegacy(cols []LegacyColumn) error {
	if len(cols) == 0 {
		return nil
	}
	done, err := s.GetMeta(metaLegacyMigrated)
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	ctx := context.Background()
	// Only fold columns this database actually has: a gate may add legacy
	// mappings for columns that never existed in some deployments, and a fresh
	// database has none of them.
	var present []LegacyColumn
	for _, c := range cols {
		has, err := s.hasColumn(ctx, "fingerprints", c.Column)
		if err != nil {
			return err
		}
		if has {
			present = append(present, c)
		}
	}
	if len(present) == 0 {
		return s.SetMeta(metaLegacyMigrated, "1")
	}

	names := make([]string, len(present))
	for i, c := range present {
		names[i] = c.Column
	}
	rows, err := s.reader.QueryContext(ctx, `SELECT fp, meta, `+strings.Join(names, ", ")+` FROM fingerprints`)
	if err != nil {
		return err
	}
	type update struct {
		fp   string
		meta string
	}
	var updates []update
	for rows.Next() {
		var fp, metaJSON string
		raw := make([]sql.NullString, len(present))
		dest := make([]any, 0, len(present)+2)
		dest = append(dest, &fp, &metaJSON)
		for i := range raw {
			dest = append(dest, &raw[i])
		}
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		meta := map[string]any{}
		if strings.TrimSpace(metaJSON) != "" {
			if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
				rows.Close()
				return fmt.Errorf("fingerprint %s: decode existing meta: %w", fp, err)
			}
		}
		for i, c := range present {
			if !raw[i].Valid {
				continue
			}
			// Don't clobber a key the gate has already written under gatekit.
			if _, exists := meta[c.MetaKey]; exists {
				continue
			}
			value, err := decodeLegacy(raw[i].String, c.Kind)
			if err != nil {
				rows.Close()
				return fmt.Errorf("fingerprint %s: column %s: %w", fp, c.Column, err)
			}
			if value == nil {
				continue
			}
			meta[c.MetaKey] = value
		}
		encoded, err := encodeMeta(meta)
		if err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, update{fp: fp, meta: encoded})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `UPDATE fingerprints SET meta = ? WHERE fp = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range updates {
		if _, err := stmt.ExecContext(ctx, u.meta, u.fp); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO meta (key, value) VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, metaLegacyMigrated); err != nil {
		return err
	}
	return tx.Commit()
}

func decodeLegacy(raw string, kind Kind) (any, error) {
	switch kind {
	case KindBool:
		// Legacy booleans are 0/1 integers read as text.
		return raw != "" && raw != "0", nil
	case KindJSON:
		if strings.TrimSpace(raw) == "" {
			return nil, nil
		}
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("decode json: %w", err)
		}
		return v, nil
	default:
		if raw == "" {
			return nil, nil
		}
		return raw, nil
	}
}
