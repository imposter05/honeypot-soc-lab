/*
Hiten | 2026
cleanup.go

`hive cleanup --older-than 720h` shows what would be removed.
`--apply` removes it in one transaction.

Events linked to any case (through a detection or added by hand) are
kept, whatever their age, so case evidence never disappears. Other
events older than the cutoff are removed together with their evidence
links; detections and observables left with no evidence are removed
too, except observables an analyst has marked.
*/

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

func newCleanupCmd() *cobra.Command {
	var olderThan time.Duration
	var apply bool
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Preview or remove old events that no case refers to",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if olderThan < 24*time.Hour {
				return fmt.Errorf("--older-than must be at least 24h")
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			pool, err := pgxpool.New(cmd.Context(), cfg.Database.DSN)
			if err != nil {
				return err
			}
			defer pool.Close()
			return runCleanup(cmd.Context(), pool, time.Now().UTC().Add(-olderThan), apply)
		},
	}
	cmd.Flags().DurationVar(&olderThan, "older-than", 30*24*time.Hour, "age cutoff, for example 720h")
	cmd.Flags().BoolVar(&apply, "apply", false, "remove the records instead of only counting them")
	return cmd
}

const eligibleSQL = `
	CREATE TEMP TABLE cleanup_events ON COMMIT DROP AS
	SELECT e.id, e.timestamp FROM events e
	WHERE e.timestamp < $1
	  AND NOT EXISTS (SELECT 1 FROM case_events ce
		WHERE ce.event_id = e.id AND ce.event_timestamp = e.timestamp)
	  AND NOT EXISTS (SELECT 1 FROM detection_evidence de
		JOIN case_detections cd ON cd.detection_id = de.detection_id
		WHERE de.event_id = e.id AND de.event_timestamp = e.timestamp)`

func runCleanup(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time, apply bool) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, eligibleSQL, cutoff); err != nil {
		return fmt.Errorf("selecting events: %w", err)
	}
	var older, eligible, credentials, sessions int64
	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE timestamp < $1`, cutoff).Scan(&older)
	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM cleanup_events`).Scan(&eligible)
	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM credentials WHERE timestamp < $1`, cutoff).Scan(&credentials)
	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE started_at < $1 AND ended_at IS NOT NULL`, cutoff).Scan(&sessions)

	fmt.Printf("Cutoff: %s\n", cutoff.Format(time.RFC3339))
	fmt.Printf("Events older than cutoff:        %d\n", older)
	fmt.Printf("  kept because a case uses them: %d\n", older-eligible)
	fmt.Printf("  removable:                     %d\n", eligible)
	fmt.Printf("Credential records:              %d\n", credentials)
	fmt.Printf("Finished sessions:               %d\n", sessions)
	fmt.Println("Session replays and uploaded files on disk are not touched.")

	if !apply {
		fmt.Println("\nPreview only. Run again with --apply to remove these records.")
		return nil
	}

	steps := []struct{ name, sql string }{
		{"detection evidence", `DELETE FROM detection_evidence de USING cleanup_events c
			WHERE de.event_id = c.id AND de.event_timestamp = c.timestamp`},
		{"detections without evidence", `DELETE FROM detections d
			WHERE NOT EXISTS (SELECT 1 FROM detection_evidence de WHERE de.detection_id = d.id)
			  AND NOT EXISTS (SELECT 1 FROM case_detections cd WHERE cd.detection_id = d.id)`},
		{"observable evidence", `DELETE FROM observable_evidence oe USING cleanup_events c
			WHERE oe.event_id = c.id AND oe.event_timestamp = c.timestamp`},
		{"observables without evidence", `DELETE FROM iocs i WHERE i.status = 'observed'
			AND NOT EXISTS (SELECT 1 FROM observable_evidence oe WHERE oe.ioc_id = i.id)`},
		{"captured file records", `DELETE FROM captured_files f USING cleanup_events c
			WHERE f.event_id = c.id AND f.event_timestamp = c.timestamp`},
		{"events", `DELETE FROM events e USING cleanup_events c
			WHERE e.id = c.id AND e.timestamp = c.timestamp`},
		{"credentials", `DELETE FROM credentials WHERE timestamp < $1`},
		{"sessions", `DELETE FROM sessions WHERE started_at < $1 AND ended_at IS NOT NULL`},
	}
	for _, s := range steps {
		var args []any
		if s.name == "credentials" || s.name == "sessions" {
			args = []any{cutoff}
		}
		tag, err := tx.Exec(ctx, s.sql, args...)
		if err != nil {
			return fmt.Errorf("removing %s: %w", s.name, err)
		}
		fmt.Printf("removed %-30s %d\n", s.name, tag.RowsAffected())
	}
	return tx.Commit(ctx)
}
