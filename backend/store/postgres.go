package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinelx/backend/correlate"
)

// PG is a Postgres-backed store bundle. It implements the same EventStore /
// InvestigationStore interfaces as the in-memory stores (ADR-0001): the graph
// working set stays in memory, durability comes from persisted events + rewarm.
type PG struct {
	pool *pgxpool.Pool
}

// runtime DDL: idempotent subset of deploy/schema.sql (the file is the canonical
// reference; this keeps the columns the stores actually read/write).
const pgDDL = `
CREATE TABLE IF NOT EXISTS event (
  event_id  text PRIMARY KEY,
  host_id   text NOT NULL,
  ts        timestamptz NOT NULL,
  type      text NOT NULL,
  proc_guid text NOT NULL,
  raw       jsonb NOT NULL,
  raw_hash  text NOT NULL
);
CREATE INDEX IF NOT EXISTS event_host_ts ON event (host_id, ts);
CREATE TABLE IF NOT EXISTS investigation (
  inv_id        bigint PRIMARY KEY,
  host_id       text NOT NULL,
  root_guid     text NOT NULL,
  status        text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  risk_score    int NOT NULL,
  score_factors jsonb NOT NULL,
  technique_set text[] NOT NULL,
  detection_ids bigint[] NOT NULL,
  event_ids     text[] NOT NULL
);`

// OpenPG connects and runs migrations.
func OpenPG(ctx context.Context, dsn string) (*PG, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	// Serialize migrations with an advisory lock: concurrent CREATE TABLE IF NOT
	// EXISTS otherwise races on the pg_type catalog.
	tx, err := pool.Begin(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(775348211)`); err != nil {
		tx.Rollback(ctx)
		pool.Close()
		return nil, fmt.Errorf("migrate lock: %w", err)
	}
	if _, err := tx.Exec(ctx, pgDDL); err != nil {
		tx.Rollback(ctx)
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate commit: %w", err)
	}
	return &PG{pool: pool}, nil
}

// Close releases the pool.
func (p *PG) Close() { p.pool.Close() }

// Events returns the Postgres EventStore.
func (p *PG) Events() *PGEventStore { return &PGEventStore{p.pool} }

// Investigations returns the Postgres InvestigationStore.
func (p *PG) Investigations() *PGInvestigationStore { return &PGInvestigationStore{p.pool} }

// PGEventStore implements EventStore over Postgres.
type PGEventStore struct{ pool *pgxpool.Pool }

func (s *PGEventStore) Put(e correlate.Event) {
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	_, _ = s.pool.Exec(context.Background(),
		`INSERT INTO event (event_id, host_id, ts, type, proc_guid, raw, raw_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (event_id) DO NOTHING`,
		e.ID, e.HostID, e.TS, string(e.Type), e.ProcGUID, raw, hex.EncodeToString(sum[:]))
}

func (s *PGEventStore) Get(id string) (correlate.Event, bool) {
	var raw []byte
	err := s.pool.QueryRow(context.Background(), `SELECT raw FROM event WHERE event_id=$1`, id).Scan(&raw)
	if err != nil {
		return correlate.Event{}, false
	}
	var e correlate.Event
	if json.Unmarshal(raw, &e) != nil {
		return correlate.Event{}, false
	}
	return e, true
}

func (s *PGEventStore) Count() int {
	var n int
	_ = s.pool.QueryRow(context.Background(), `SELECT count(*) FROM event`).Scan(&n)
	return n
}

// All returns every event ordered by time — the rewarm source of truth.
func (s *PGEventStore) All() ([]correlate.Event, error) {
	rows, err := s.pool.Query(context.Background(), `SELECT raw FROM event ORDER BY ts, event_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []correlate.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e correlate.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PGInvestigationStore implements InvestigationStore over Postgres.
type PGInvestigationStore struct{ pool *pgxpool.Pool }

func (s *PGInvestigationStore) Upsert(inv *correlate.Investigation) {
	factors, _ := json.Marshal(inv.ScoreFactors)
	eventIDs := make([]string, 0, len(inv.EventIDs))
	for id := range inv.EventIDs {
		eventIDs = append(eventIDs, id)
	}
	_, _ = s.pool.Exec(context.Background(),
		`INSERT INTO investigation
		   (inv_id, host_id, root_guid, status, first_seen, last_seen, risk_score,
		    score_factors, technique_set, detection_ids, event_ids)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (inv_id) DO UPDATE SET
		   status=EXCLUDED.status, last_seen=EXCLUDED.last_seen, risk_score=EXCLUDED.risk_score,
		   score_factors=EXCLUDED.score_factors, technique_set=EXCLUDED.technique_set,
		   detection_ids=EXCLUDED.detection_ids, event_ids=EXCLUDED.event_ids`,
		inv.ID, inv.HostID, inv.RootGUID, inv.Status, inv.FirstSeen, inv.LastSeen, inv.RiskScore,
		factors, inv.TechniqueSet, inv.Detections, eventIDs)
}

func (s *PGInvestigationStore) Get(id int64) (*correlate.Investigation, bool) {
	row := s.pool.QueryRow(context.Background(),
		`SELECT inv_id, host_id, root_guid, status, first_seen, last_seen, risk_score,
		        score_factors, technique_set, detection_ids, event_ids
		 FROM investigation WHERE inv_id=$1`, id)
	inv, err := scanInv(row)
	if err != nil {
		return nil, false
	}
	return inv, true
}

func (s *PGInvestigationStore) List() []*correlate.Investigation {
	rows, err := s.pool.Query(context.Background(),
		`SELECT inv_id, host_id, root_guid, status, first_seen, last_seen, risk_score,
		        score_factors, technique_set, detection_ids, event_ids
		 FROM investigation ORDER BY inv_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*correlate.Investigation
	for rows.Next() {
		if inv, err := scanInv(rows); err == nil {
			out = append(out, inv)
		}
	}
	return out
}

// scanInv reconstructs an Investigation from a row. The live provenance graph
// (Nodes) is not restored from Postgres — it is rebuilt in memory by Rewarm; the
// timeline is served by joining EventIDs against the EventStore.
func scanInv(row pgx.Row) (*correlate.Investigation, error) {
	var (
		inv     correlate.Investigation
		factors []byte
		evIDs   []string
	)
	err := row.Scan(&inv.ID, &inv.HostID, &inv.RootGUID, &inv.Status, &inv.FirstSeen, &inv.LastSeen,
		&inv.RiskScore, &factors, &inv.TechniqueSet, &inv.Detections, &evIDs)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(factors, &inv.ScoreFactors)
	inv.EventIDs = make(map[string]bool, len(evIDs))
	for _, id := range evIDs {
		inv.EventIDs[id] = true
	}
	inv.Nodes = map[string]*correlate.Node{}
	return &inv, nil
}
