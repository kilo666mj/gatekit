package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kilo666mj/gatekit/approval"
	"time"
)

// Decision explicitly replaces status, label and approval scope together.
// Nil ApprovalRanges deliberately removes a prior restriction.
type Decision struct {
	Fingerprint    string          `json:"fingerprint"`
	Status         Status          `json:"status"`
	Label          string          `json:"label,omitempty"`
	ApprovalRanges *approval.Scope `json:"approval_ranges,omitempty"`
}

func (d Decision) Validate() error {
	if d.Fingerprint == "" || !d.Status.Valid() {
		return fmt.Errorf("invalid fingerprint decision")
	}
	if d.ApprovalRanges != nil && d.Status != StatusApproved {
		return fmt.Errorf("approval_ranges requires approved status")
	}
	return d.ApprovalRanges.Validate()
}

// ApplyDecisions commits a validated batch and its optional sync cursor atomically.
// An invalid member or database failure changes neither decisions nor cursor.
func (s *Store) ApplyDecisions(decisions []Decision, cursorKey, cursor string) (err error) {
	scopes := make([]any, len(decisions))
	for i, d := range decisions {
		if err := d.Validate(); err != nil {
			return err
		}
		if d.ApprovalRanges != nil {
			b, err := json.Marshal(d.ApprovalRanges)
			if err != nil {
				return err
			}
			scopes[i] = string(b)
		}
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollbackTransaction(tx, &err)
	now := encodeTime(time.Now())
	for i, d := range decisions {
		if _, err := tx.Exec(`INSERT INTO fingerprints (fp,status,label,first_seen,last_seen,count,meta,approval_ranges)
   VALUES (?,?,?,?,?,0,'{}',?) ON CONFLICT(fp) DO UPDATE SET status=excluded.status,
   label=excluded.label, approval_ranges=excluded.approval_ranges`, d.Fingerprint, d.Status, d.Label, now, now, scopes[i]); err != nil {
			return err
		}
	}
	if cursorKey != "" && cursor != "" {
		if _, err := tx.Exec(`INSERT INTO meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, cursorKey, cursor); err != nil {
			return err
		}
	}
	return tx.Commit()
}
