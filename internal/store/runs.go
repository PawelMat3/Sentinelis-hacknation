package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// Run statuses.
const (
	RunQueued    = "queued" // waiting for its time window
	RunRunning   = "running"
	RunPaused    = "paused" // window closed / manual pause / crash recovery; resumes from checkpoint
	RunCompleted = "completed"
	RunCancelled = "cancelled"
	RunFailed    = "failed"
)

// RunSpec freezes job configuration at run creation, so a run that spans
// several windows resumes with identical scope and settings.
type RunSpec struct {
	Targets          []string `json:"targets"`
	Exclusions       []string `json:"exclusions"`
	Ports            string   `json:"ports"`
	Engine           string   `json:"engine"`
	RatePPS          int      `json:"rate_pps"`
	HTTPRPS          int      `json:"http_rps"`
	Concurrency      int      `json:"concurrency"`
	ChunkSize        int      `json:"chunk_size"`
	ChunkTargetSec   int      `json:"chunk_target_sec"`
	Timing           string   `json:"timing"`
	ServiceDetection bool     `json:"service_detection"`
	HTTPFingerprint  bool     `json:"http_fingerprint"`
	PathProbes       bool     `json:"path_probes"`
	NmapExtra        string   `json:"nmap_extra"`
	InactiveAfter    int      `json:"inactive_after"`
	ReprobeAttempts  int      `json:"reprobe_attempts"`
	ReprobeDelaySec  int      `json:"reprobe_delay_sec"`
	VulnLookup       bool     `json:"vuln_lookup"`
}

func SpecFromJob(j *Job, tg []string) RunSpec {
	var ex []string
	for _, e := range strings.FieldsFunc(j.Exclusions, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\r' }) {
		if e = strings.TrimSpace(e); e != "" && !strings.HasPrefix(e, "#") {
			ex = append(ex, e)
		}
	}
	return RunSpec{Targets: tg, Exclusions: ex, Ports: j.Ports, Engine: j.Engine, RatePPS: j.RatePPS, HTTPRPS: j.HTTPRPS,
		Concurrency: j.Concurrency, ChunkSize: j.ChunkSize, ChunkTargetSec: j.ChunkTargetSec, Timing: j.Timing,
		ServiceDetection: j.ServiceDetection, HTTPFingerprint: j.HTTPFingerprint, PathProbes: j.PathProbes, NmapExtra: j.NmapExtra,
		InactiveAfter: j.InactiveAfter, ReprobeAttempts: j.ReprobeAttempts, ReprobeDelaySec: j.ReprobeDelaySec, VulnLookup: j.VulnLookup}
}

type Run struct {
	ID             int64   `json:"id"`
	JobID          int64   `json:"job_id"`
	JobName        string  `json:"job_name"`
	Seq            int     `json:"seq"`
	Trigger        string  `json:"trigger"`
	Status         string  `json:"status"`
	StatusReason   string  `json:"status_reason"`
	IgnoreWindow   bool    `json:"ignore_window"`
	Spec           RunSpec `json:"-"`
	Engine         string  `json:"engine"`
	TotalTargets   int64   `json:"total_targets"`
	Cursor         int64   `json:"cursor"`
	DoneTargets    int64   `json:"done_targets"`
	HostsUp        int     `json:"hosts_up"`
	OpenPorts      int     `json:"open_ports"`
	SecPerHost     float64 `json:"sec_per_host"`
	ActiveMS       int64   `json:"active_ms"`
	WindowsUsed    int     `json:"windows_used"`
	ReprobeRound   int     `json:"reprobe_round"`
	Phase          string  `json:"phase"`
	ChangesNew     int     `json:"changes_new"`
	ChangesGone    int     `json:"changes_gone"`
	ChangesChanged int     `json:"changes_changed"`
	ChangesHosts   int     `json:"changes_hosts"`
	CreatedBy      string  `json:"created_by"`
	CreatedAt      int64   `json:"created_at"`
	StartedAt      int64   `json:"started_at"`
	LastResumedAt  int64   `json:"last_resumed_at"`
	FinishedAt     int64   `json:"finished_at"`
	// derived
	Progress      float64 `json:"progress"`
	ThroughputHPS float64 `json:"throughput_hps"`
	ETASec        int64   `json:"eta_sec"`
}

const runCols = `r.id, COALESCE(r.job_id,0), COALESCE(j.name,''), r.seq, r.trigger, r.status, r.status_reason, r.ignore_window, r.spec, r.engine,
 r.total_targets, r.cursor, r.done_targets, r.hosts_up, r.open_ports, r.sec_per_host, r.active_ms, r.windows_used, r.reprobe_round, r.phase,
 r.changes_new, r.changes_gone, r.changes_changed, r.changes_hosts, r.created_by, r.created_at, r.started_at, r.last_resumed_at, r.finished_at`

func (s *Store) scanRun(row interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var iw int
	var spec string
	err := row.Scan(&r.ID, &r.JobID, &r.JobName, &r.Seq, &r.Trigger, &r.Status, &r.StatusReason, &iw, &spec, &r.Engine, &r.TotalTargets, &r.Cursor,
		&r.DoneTargets, &r.HostsUp, &r.OpenPorts, &r.SecPerHost, &r.ActiveMS, &r.WindowsUsed, &r.ReprobeRound, &r.Phase, &r.ChangesNew,
		&r.ChangesGone, &r.ChangesChanged, &r.ChangesHosts, &r.CreatedBy, &r.CreatedAt, &r.StartedAt, &r.LastResumedAt, &r.FinishedAt)
	if err != nil {
		return nil, err
	}
	r.IgnoreWindow = iw == 1
	json.Unmarshal([]byte(spec), &r.Spec)
	if r.TotalTargets > 0 {
		r.Progress = float64(r.DoneTargets) / float64(r.TotalTargets)
	}
	active := r.ActiveMS
	if r.Status == RunRunning && r.LastResumedAt > 0 {
		active += (s.now() - r.LastResumedAt) * 1000
	}
	if active > 0 && r.DoneTargets > 0 {
		r.ThroughputHPS = float64(r.DoneTargets) / (float64(active) / 1000)
		if r.Status != RunCompleted {
			r.ETASec = int64(float64(r.TotalTargets-r.DoneTargets) / r.ThroughputHPS)
		}
	}
	return &r, nil
}

func (s *Store) CreateRun(ctx context.Context, jobID int64, trigger string, ignoreWindow bool, spec RunSpec, total int64, user string) (*Run, error) {
	var seq int
	s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM runs WHERE COALESCE(job_id,0)=?`, jobID).Scan(&seq)
	var jid any = jobID
	if jobID == 0 {
		jid = nil
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO runs(job_id, seq, trigger, status, ignore_window, spec, engine, total_targets, created_by, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		jid, seq, trigger, RunQueued, b2i(ignoreWindow), jsonStr(spec), spec.Engine, total, user, s.now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetRun(ctx, id)
}

func (s *Store) GetRun(ctx context.Context, id int64) (*Run, error) {
	r, err := s.scanRun(s.DB.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs r LEFT JOIN jobs j ON j.id=r.job_id WHERE r.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *Store) ListRuns(ctx context.Context, jobID int64, limit int) ([]*Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT ` + runCols + ` FROM runs r LEFT JOIN jobs j ON j.id=r.job_id`
	args := []any{}
	where := ""
	if jobID > 0 {
		where = ` WHERE r.job_id=?`
		args = append(args, jobID)
	}
	q += addWhere(where, jobScope(ctx, "r.job_id")) + ` ORDER BY r.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Run{}
	for rows.Next() {
		r, err := s.scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRun returns the unfinished run of a job (queued/running/paused).
func (s *Store) ActiveRun(ctx context.Context, jobID int64) (*Run, error) {
	r, err := s.scanRun(s.DB.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs r LEFT JOIN jobs j ON j.id=r.job_id
		WHERE r.job_id=? AND r.status IN ('queued','running','paused') ORDER BY r.id DESC LIMIT 1`, jobID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// RecoverInterrupted turns runs left "running" by a crash into paused runs and
// puts their in-flight chunks back into the queue (checkpoint resume).
func (s *Store) RecoverInterrupted(ctx context.Context) (int, error) {
	if _, err := s.DB.ExecContext(ctx, `UPDATE chunks SET status='pending', attempts=MAX(attempts-1,0) WHERE status='running'`); err != nil {
		return 0, err
	}
	r, err := s.DB.ExecContext(ctx, `UPDATE runs SET status='paused', status_reason='recovered after restart', active_ms=active_ms+MAX(0,(?-last_resumed_at)*1000)
		WHERE status='running'`, s.now())
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return int(n), nil
}

func (s *Store) SetRunStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE runs SET status=?, status_reason=? WHERE id=?`, status, reason, id)
	return err
}

// MarkRunActive records the start of a new window segment.
func (s *Store) MarkRunActive(ctx context.Context, id int64) error {
	now := s.now()
	_, err := s.DB.ExecContext(ctx, `UPDATE runs SET status='running', status_reason='', started_at=CASE WHEN started_at=0 THEN ? ELSE started_at END,
		last_resumed_at=?, windows_used=windows_used+1 WHERE id=?`, now, now, id)
	return err
}

// EndSegment closes a window segment, accumulating active scan time.
func (s *Store) EndSegment(ctx context.Context, id int64, status, reason string, activeMS int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE runs SET status=?, status_reason=?, active_ms=active_ms+? WHERE id=?`, status, reason, activeMS, id)
	return err
}

func (s *Store) SetRunPhase(ctx context.Context, id int64, phase string, reprobeRound int) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE runs SET phase=?, reprobe_round=? WHERE id=?`, phase, reprobeRound, id)
	return err
}

// --- chunks ----------------------------------------------------------------

type Chunk struct {
	ID         int64    `json:"id"`
	RunID      int64    `json:"run_id"`
	Seq        int      `json:"seq"`
	Kind       string   `json:"kind"`
	Start      int64    `json:"start"`
	End        int64    `json:"end"`
	Targets    []string `json:"targets,omitempty"`
	Status     string   `json:"status"`
	Attempts   int      `json:"attempts"`
	HostsUp    int      `json:"hosts_up"`
	OpenPorts  int      `json:"open_ports"`
	DurationMS int64    `json:"duration_ms"`
	StartedAt  int64    `json:"started_at"`
	FinishedAt int64    `json:"finished_at"`
	Error      string   `json:"error,omitempty"`
}

func (c *Chunk) Size() int64 {
	if c.Kind == "reprobe" {
		return int64(len(c.Targets))
	}
	return c.End - c.Start
}

const chunkCols = `id, run_id, seq, kind, start_idx, end_idx, targets, status, attempts, hosts_up, open_ports, duration_ms, started_at, finished_at, error`

func scanChunk(row interface{ Scan(...any) error }) (*Chunk, error) {
	var c Chunk
	var tg string
	err := row.Scan(&c.ID, &c.RunID, &c.Seq, &c.Kind, &c.Start, &c.End, &tg, &c.Status, &c.Attempts, &c.HostsUp, &c.OpenPorts, &c.DurationMS, &c.StartedAt, &c.FinishedAt, &c.Error)
	if tg != "" {
		c.Targets = strings.Split(tg, "\n")
	}
	return &c, err
}

// NextChunk claims the next unit of work: a pending chunk (checkpointed from a
// previous window or retried), split down to maxSize if needed, or a freshly
// carved slice [cursor, cursor+want) of the target space.
func (s *Store) NextChunk(ctx context.Context, runID int64, want, maxSize int64) (*Chunk, error) {
	if want < 1 {
		want = 1
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now()
	c, err := scanChunk(tx.QueryRowContext(ctx, `SELECT `+chunkCols+` FROM chunks WHERE run_id=? AND status='pending' ORDER BY seq LIMIT 1`, runID))
	if err == nil {
		if c.Kind == "main" && maxSize > 0 && c.Size() > maxSize {
			// split: keep head, push tail back as a new pending chunk
			var seq int
			tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM chunks WHERE run_id=?`, runID).Scan(&seq)
			if _, err := tx.ExecContext(ctx, `INSERT INTO chunks(run_id, seq, kind, start_idx, end_idx, status) VALUES(?,?,?,?,?,'pending')`,
				runID, seq, "main", c.Start+maxSize, c.End); err != nil {
				return nil, err
			}
			c.End = c.Start + maxSize
		}
		c.Status, c.StartedAt = "running", now
		c.Attempts++
		if _, err := tx.ExecContext(ctx, `UPDATE chunks SET status='running', attempts=?, started_at=?, end_idx=? WHERE id=?`, c.Attempts, now, c.End, c.ID); err != nil {
			return nil, err
		}
		return c, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var cursor, total int64
	var phase string
	if err := tx.QueryRowContext(ctx, `SELECT cursor, total_targets, phase FROM runs WHERE id=?`, runID).Scan(&cursor, &total, &phase); err != nil {
		return nil, err
	}
	if phase != "main" || cursor >= total {
		return nil, nil
	}
	end := cursor + want
	if end > total {
		end = total
	}
	var seq int
	tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM chunks WHERE run_id=?`, runID).Scan(&seq)
	res, err := tx.ExecContext(ctx, `INSERT INTO chunks(run_id, seq, kind, start_idx, end_idx, status, attempts, started_at) VALUES(?,?,?,?,?,'running',1,?)`,
		runID, seq, "main", cursor, end, now)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET cursor=? WHERE id=?`, end, runID); err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Chunk{ID: id, RunID: runID, Seq: seq, Kind: "main", Start: cursor, End: end, Status: "running", Attempts: 1, StartedAt: now}, nil
}

// AddReprobeChunk queues a re-probe of hosts that did not answer.
func (s *Store) AddReprobeChunk(ctx context.Context, runID int64, tg []string) error {
	var seq int
	s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM chunks WHERE run_id=?`, runID).Scan(&seq)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO chunks(run_id, seq, kind, targets, status) VALUES(?,?,?,?,'pending')`, runID, seq, "reprobe", strings.Join(tg, "\n"))
	return err
}

// CompleteChunk stores chunk metrics and updates run progress + the EWMA of
// seconds per host used for adaptive chunk sizing.
func (s *Store) CompleteChunk(ctx context.Context, c *Chunk, hostsUp, openPorts int, durMS int64, concurrency int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE chunks SET status='done', hosts_up=?, open_ports=?, duration_ms=?, finished_at=?, error='' WHERE id=?`,
		hostsUp, openPorts, durMS, s.now(), c.ID); err != nil {
		return err
	}
	size := c.Size()
	if c.Kind == "main" && size > 0 {
		sph := float64(durMS) / 1000 / float64(size)
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET done_targets=done_targets+?, sec_per_host=CASE WHEN sec_per_host=0 THEN ? ELSE sec_per_host*0.7+?*0.3 END WHERE id=?`,
			size, sph, sph, c.RunID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReleaseChunk returns an interrupted chunk to the queue without penalty.
func (s *Store) ReleaseChunk(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE chunks SET status='pending', attempts=MAX(attempts-1,0) WHERE id=?`, id)
	return err
}

func (s *Store) FailChunk(ctx context.Context, c *Chunk, msg string, maxAttempts int) error {
	st := "pending"
	if c.Attempts >= maxAttempts {
		st = "failed"
	}
	_, err := s.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE chunks SET status=?, error=?, finished_at=? WHERE id=?`, st, msg, s.now(), c.ID)
	if st == "failed" && c.Kind == "main" {
		s.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE runs SET done_targets=done_targets+? WHERE id=?`, c.Size(), c.RunID)
	}
	return err
}

func (s *Store) ListChunks(ctx context.Context, runID int64, limit int) ([]*Chunk, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+chunkCols+` FROM chunks WHERE run_id=? ORDER BY seq LIMIT ?`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Chunk{}
	for rows.Next() {
		c, err := scanChunk(rows)
		if err != nil {
			return nil, err
		}
		if len(c.Targets) > 20 {
			c.Targets = c.Targets[:20]
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type ChunkStats struct {
	Pending int `json:"pending"`
	Running int `json:"running"`
	Done    int `json:"done"`
	Failed  int `json:"failed"`
}

func (s *Store) ChunkStats(ctx context.Context, runID int64) ChunkStats {
	var st ChunkStats
	rows, err := s.DB.QueryContext(ctx, `SELECT status, COUNT(*) FROM chunks WHERE run_id=? GROUP BY status`, runID)
	if err != nil {
		return st
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		rows.Scan(&k, &n)
		switch k {
		case "pending":
			st.Pending = n
		case "running":
			st.Running = n
		case "done":
			st.Done = n
		case "failed":
			st.Failed = n
		}
	}
	return st
}

// LastSecPerHost returns the measured cost of the previous run of a job
// (seeds adaptive chunking for the next run).
func (s *Store) LastSecPerHost(ctx context.Context, jobID int64) float64 {
	var v float64
	s.DB.QueryRowContext(ctx, `SELECT sec_per_host FROM runs WHERE job_id=? AND sec_per_host>0 ORDER BY id DESC LIMIT 1`, jobID).Scan(&v)
	return v
}
