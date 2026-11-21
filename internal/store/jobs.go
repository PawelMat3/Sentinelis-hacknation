package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"asi/internal/analysis"
	"asi/internal/scanner"
	"asi/internal/targets"
	"asi/internal/window"
)

// Job is a recurring scan configuration.
type Job struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Enabled          bool   `json:"enabled"`
	Engine           string `json:"engine"`
	Ports            string `json:"ports"`
	Exclusions       string `json:"exclusions"`
	RatePPS          int    `json:"rate_pps"`
	HTTPRPS          int    `json:"http_rps"`
	Concurrency      int    `json:"concurrency"`
	ChunkSize        int    `json:"chunk_size"`
	ChunkTargetSec   int    `json:"chunk_target_sec"`
	Timing           string `json:"timing"`
	ServiceDetection bool   `json:"service_detection"`
	HTTPFingerprint  bool   `json:"http_fingerprint"`
	PathProbes       bool   `json:"path_probes"`
	NmapExtra        string `json:"nmap_extra"`
	WindowAlways     bool   `json:"window_always"`
	WindowDays       string `json:"window_days"`
	WindowStart      string `json:"window_start"`
	WindowEnd        string `json:"window_end"`
	Timezone         string `json:"timezone"`
	IntervalMinutes  int    `json:"interval_minutes"`
	InactiveAfter    int    `json:"inactive_after"`
	ReprobeAttempts  int    `json:"reprobe_attempts"`
	ReprobeDelaySec  int    `json:"reprobe_delay_sec"`
	Quick            bool   `json:"quick"`
	VulnLookup       bool   `json:"vuln_lookup"`
	NextRunAt        int64  `json:"next_run_at"`
	LastRunAt        int64  `json:"last_run_at"`
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
	// computed
	TargetCount  int    `json:"target_count"`
	AddressCount int64  `json:"address_count"`
	WindowText   string `json:"window_text"`
	WindowOpen   bool   `json:"window_open"`
}

func (j *Job) Window() (window.Window, error) {
	return window.Parse(j.WindowDays, j.WindowStart, j.WindowEnd, j.Timezone, j.WindowAlways)
}

func (j *Job) Policy() analysis.Policy {
	p := analysis.DefaultPolicy()
	if j.InactiveAfter > 0 {
		p.InactiveAfter = j.InactiveAfter
	}
	return p
}

// Defaults fills zero values with safe defaults.
func (j *Job) Defaults() {
	if j.Engine == "" {
		j.Engine = "nmap"
	}
	if j.Ports == "" {
		j.Ports = "top:100"
	}
	if j.RatePPS <= 0 {
		j.RatePPS = 300
	}
	if j.HTTPRPS <= 0 {
		j.HTTPRPS = 10
	}
	if j.Concurrency <= 0 {
		j.Concurrency = 4
	}
	if j.ChunkTargetSec <= 0 {
		j.ChunkTargetSec = 60
	}
	if j.Timing == "" {
		j.Timing = "T3"
	}
	if j.WindowDays == "" {
		j.WindowDays = "1111111"
	}
	if j.WindowStart == "" {
		j.WindowStart = "22:00"
	}
	if j.WindowEnd == "" {
		j.WindowEnd = "06:00"
	}
	if j.Timezone == "" {
		j.Timezone = "Europe/Warsaw"
	}
	if j.InactiveAfter <= 0 {
		j.InactiveAfter = 3
	}
	if j.ReprobeAttempts < 0 {
		j.ReprobeAttempts = 0
	}
	if j.ReprobeDelaySec <= 0 {
		j.ReprobeDelaySec = 30
	}
}

// Validate enforces safety limits on job configuration.
func (j *Job) Validate(maxRate int) error {
	if strings.TrimSpace(j.Name) == "" {
		return errors.New("name required")
	}
	if err := scanner.ValidatePorts(j.Ports); err != nil {
		return err
	}
	if err := scanner.ValidateTiming(j.Timing); err != nil {
		return err
	}
	if _, err := scanner.ParseExtra(j.NmapExtra); err != nil {
		return err
	}
	if maxRate > 0 && j.RatePPS > maxRate {
		return fmt.Errorf("rate %d pps exceeds global safety cap %d (ASI_MAX_RATE)", j.RatePPS, maxRate)
	}
	if j.HTTPRPS > 200 {
		return errors.New("http_rps max 200")
	}
	if j.Concurrency > 32 {
		return errors.New("concurrency max 32")
	}
	if j.ChunkSize < 0 || j.ChunkSize > 65536 {
		return errors.New("chunk_size 0 (auto) .. 65536")
	}
	if j.IntervalMinutes < 0 {
		return errors.New("interval must be >= 0 (0 = manual only)")
	}
	switch j.Engine {
	case "nmap", "native", "sim":
	default:
		return fmt.Errorf("unknown engine %q", j.Engine)
	}
	if _, err := j.Window(); err != nil {
		return err
	}
	if ex := targets.ParseList(j.Exclusions); len(ex) > 0 {
		for _, e := range ex {
			if _, err := targets.Classify(e); err != nil {
				return fmt.Errorf("exclusions: %w", err)
			}
		}
	}
	return nil
}

const jobCols = `id, name, description, enabled, engine, ports, exclusions, rate_pps, http_rps, concurrency, chunk_size, chunk_target_sec,
 timing, service_detection, http_fingerprint, path_probes, nmap_extra, window_always, window_days, window_start, window_end, timezone,
 interval_minutes, inactive_after, reprobe_attempts, reprobe_delay_sec, next_run_at, last_run_at, created_at, updated_at, quick, vuln_lookup,
 (SELECT COUNT(*) FROM targets t WHERE t.job_id=jobs.id), (SELECT COALESCE(SUM(addr_count),0) FROM targets t WHERE t.job_id=jobs.id)`

func (s *Store) scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var en, sd, hf, pp, wa, qk, vl int
	err := row.Scan(&j.ID, &j.Name, &j.Description, &en, &j.Engine, &j.Ports, &j.Exclusions, &j.RatePPS, &j.HTTPRPS, &j.Concurrency,
		&j.ChunkSize, &j.ChunkTargetSec, &j.Timing, &sd, &hf, &pp, &j.NmapExtra, &wa, &j.WindowDays, &j.WindowStart, &j.WindowEnd,
		&j.Timezone, &j.IntervalMinutes, &j.InactiveAfter, &j.ReprobeAttempts, &j.ReprobeDelaySec, &j.NextRunAt, &j.LastRunAt,
		&j.CreatedAt, &j.UpdatedAt, &qk, &vl, &j.TargetCount, &j.AddressCount)
	if err != nil {
		return nil, err
	}
	j.Enabled, j.ServiceDetection, j.HTTPFingerprint, j.PathProbes, j.WindowAlways = en == 1, sd == 1, hf == 1, pp == 1, wa == 1
	j.Quick, j.VulnLookup = qk == 1, vl == 1
	if w, err := j.Window(); err == nil {
		j.WindowText = w.String()
		j.WindowOpen = w.IsOpen(s.Now())
	}
	return &j, nil
}

func (s *Store) ListJobs(ctx context.Context) ([]*Job, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+jobCols+` FROM jobs`+addWhere("", jobScope(ctx, "jobs.id"))+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := s.scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) GetJob(ctx context.Context, id int64) (*Job, error) {
	j, err := s.scanJob(s.DB.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

func (s *Store) CreateJob(ctx context.Context, j *Job) (int64, error) {
	now := s.now()
	res, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(name, description, enabled, engine, ports, exclusions, rate_pps, http_rps, concurrency,
	 chunk_size, chunk_target_sec, timing, service_detection, http_fingerprint, path_probes, nmap_extra, window_always, window_days,
	 window_start, window_end, timezone, interval_minutes, inactive_after, reprobe_attempts, reprobe_delay_sec, next_run_at, created_at, updated_at, quick, vuln_lookup)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		j.Name, j.Description, b2i(j.Enabled), j.Engine, j.Ports, j.Exclusions, j.RatePPS, j.HTTPRPS, j.Concurrency, j.ChunkSize, j.ChunkTargetSec,
		j.Timing, b2i(j.ServiceDetection), b2i(j.HTTPFingerprint), b2i(j.PathProbes), j.NmapExtra, b2i(j.WindowAlways), j.WindowDays,
		j.WindowStart, j.WindowEnd, j.Timezone, j.IntervalMinutes, j.InactiveAfter, j.ReprobeAttempts, j.ReprobeDelaySec, j.NextRunAt, now, now, b2i(j.Quick), b2i(j.VulnLookup))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateJob(ctx context.Context, j *Job) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET name=?, description=?, enabled=?, engine=?, ports=?, exclusions=?, rate_pps=?, http_rps=?,
	 concurrency=?, chunk_size=?, chunk_target_sec=?, timing=?, service_detection=?, http_fingerprint=?, path_probes=?, nmap_extra=?,
	 window_always=?, window_days=?, window_start=?, window_end=?, timezone=?, interval_minutes=?, inactive_after=?, reprobe_attempts=?,
	 reprobe_delay_sec=?, next_run_at=?, vuln_lookup=?, updated_at=? WHERE id=?`,
		j.Name, j.Description, b2i(j.Enabled), j.Engine, j.Ports, j.Exclusions, j.RatePPS, j.HTTPRPS, j.Concurrency, j.ChunkSize, j.ChunkTargetSec,
		j.Timing, b2i(j.ServiceDetection), b2i(j.HTTPFingerprint), b2i(j.PathProbes), j.NmapExtra, b2i(j.WindowAlways), j.WindowDays,
		j.WindowStart, j.WindowEnd, j.Timezone, j.IntervalMinutes, j.InactiveAfter, j.ReprobeAttempts, j.ReprobeDelaySec, j.NextRunAt, b2i(j.VulnLookup), s.now(), j.ID)
	return err
}

func (s *Store) SetJobSchedule(ctx context.Context, id, lastRun, nextRun int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET last_run_at=?, next_run_at=? WHERE id=?`, lastRun, nextRun, id)
	return err
}

func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	return err
}

// --- targets -----------------------------------------------------------------

type TargetRow struct {
	ID        int64    `json:"id"`
	JobID     int64    `json:"job_id"`
	Value     string   `json:"value"`
	Kind      string   `json:"kind"`
	Count     int64    `json:"addr_count"`
	Tags      []string `json:"tags"`
	Note      string   `json:"note"`
	Source    string   `json:"source"`
	CreatedAt int64    `json:"created_at"`
}

type TargetInput struct {
	Value string   `json:"value"`
	Tags  []string `json:"tags,omitempty"`
	Note  string   `json:"note,omitempty"`
}

type AddResult struct {
	Added   int      `json:"added"`
	Updated int      `json:"updated"`
	Errors  []string `json:"errors,omitempty"`
	Total   int64    `json:"total_addresses"`
}

// AddTargets validates and upserts scope entries for a job.
func (s *Store) AddTargets(ctx context.Context, jobID int64, in []TargetInput, source string, maxTargets int64) (*AddResult, error) {
	res := &AddResult{}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, t := range in {
		tg, err := targets.Classify(t.Value)
		if err != nil {
			if len(res.Errors) < 50 {
				res.Errors = append(res.Errors, err.Error())
			}
			continue
		}
		r, err := tx.ExecContext(ctx, `INSERT INTO targets(job_id, value, kind, addr_count, tags, note_enc, source, created_at) VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(job_id, value) DO UPDATE SET tags=CASE WHEN excluded.tags!='[]' THEN excluded.tags ELSE targets.tags END,
			note_enc=CASE WHEN excluded.note_enc!='' THEN excluded.note_enc ELSE targets.note_enc END`,
			jobID, tg.Value, tg.Kind, tg.Count, jsonStr(NormalizeTags(t.Tags)), s.K.SealString("targets.note", t.Note), source, s.now())
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			res.Added++
		}
	}
	// safety: verify resulting scope size
	var vals []string
	rows, err := tx.QueryContext(ctx, `SELECT value FROM targets WHERE job_id=?`, jobID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		vals = append(vals, v)
	}
	rows.Close()
	var excl string
	tx.QueryRowContext(ctx, `SELECT exclusions FROM jobs WHERE id=?`, jobID).Scan(&excl)
	sp, err := targets.Build(vals, targets.ParseList(excl), maxTargets)
	if err != nil {
		return nil, err
	}
	res.Total = sp.Len()
	return res, tx.Commit()
}

func (s *Store) ListTargets(ctx context.Context, jobID int64) ([]TargetRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, job_id, value, kind, addr_count, tags, note_enc, source, created_at FROM targets WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TargetRow{}
	for rows.Next() {
		var t TargetRow
		var tags, note string
		rows.Scan(&t.ID, &t.JobID, &t.Value, &t.Kind, &t.Count, &tags, &note, &t.Source, &t.CreatedAt)
		t.Tags = parseTags(tags)
		t.Note = s.K.OpenString("targets.note", note)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TargetValues(ctx context.Context, jobID int64) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT value FROM targets WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		rows.Scan(&v)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) UpdateTarget(ctx context.Context, jobID, id int64, tags []string, note string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE targets SET tags=?, note_enc=? WHERE id=? AND job_id=?`, jsonStr(NormalizeTags(tags)), s.K.SealString("targets.note", note), id, jobID)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTarget(ctx context.Context, jobID, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM targets WHERE id=? AND job_id=?`, id, jobID)
	return err
}

func (s *Store) DeleteAllTargets(ctx context.Context, jobID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM targets WHERE job_id=?`, jobID)
	return err
}

// DefaultPolicy is the host state machine policy for job-less runs (imports).
func DefaultPolicy() analysis.Policy { return analysis.DefaultPolicy() }
