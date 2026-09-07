package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// closeError runs a cleanup function and labels its failure, so a close error
// that reaches a caller says which resource failed to close.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

// closeWithError joins a cleanup failure onto a function's named error return
// without discarding the primary error. Use it as:
//
//	defer closeWithError(&err, "close fingerprint rows", rows.Close)
func closeWithError(errp *error, context string, closeFn func() error) {
	*errp = errors.Join(*errp, closeError(context, closeFn))
}

// rollbackTransaction joins a rollback failure onto a named error return.
// A transaction that already committed reports sql.ErrTxDone, which is the
// expected outcome of the usual `defer rollbackTransaction(tx, &err)` guard
// and is not a failure.
func rollbackTransaction(tx *sql.Tx, errp *error) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		*errp = errors.Join(*errp, fmt.Errorf("rollback transaction: %w", err))
	}
}
