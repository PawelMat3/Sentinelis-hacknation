// Package orchestrator schedules and executes scan runs:
//
//   - scheduler: starts runs when a job is due (interval) and its time window
//     is open; resumes paused runs when the next window opens;
//   - executor: carves adaptive chunks out of the target space, runs them on
//     a worker pool with per-run rate limits, fingerprints web services,
//     ingests results per chunk (checkpoint), and stops gracefully when the
//     window closes (in-flight chunks are returned to the queue);
//   - re-probe: hosts that stopped answering are re-scanned before a miss is
//     recorded, so transient loss is not reported as a disappearance.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"asi/internal/clock"
	"asi/internal/fingerprint"
	"asi/internal/lab"
	"asi/internal/ratelimit"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
	"asi/internal/vulns"
	"asi/internal/window"
)

// Pause/stop causes.
var (
	ErrWindowClosed = errors.New("window_closed")
	ErrPaused       = errors.New("manual_pause")
	ErrCancelled    = errors.New("cancelled")
	ErrShutdown     = errors.New("shutdown")
)

// Status reasons persisted on runs (UI translates them).
const (
	ReasonWindow    = "window_closed"
	ReasonManual    = "manual_pause"
	ReasonWaiting   = "waiting_window"
	ReasonShutdown  = "shutdown"
	ReasonRecovered = "recovered after restart"
)

type Config struct {
	MaxRate      int   // global cap on configured pps per run
	MaxTargets   int64 // safety cap on scope size
	Tick         time.Duration
	MaxAttempts  int
	HTTPWorkers  int
	MinChunkTime time.Duration // do not start a chunk when less time is left in the window
	Logf         func(string, ...any)
}

type Manager struct {
	st      *store.Store
	engines scanner.Registry
	clock   clock.Clock
	cfg     Config
	model   *lab.Model

	mu     sync.Mutex
	active map[int64]context.CancelCauseFunc
	wg     sync.WaitGroup

	vulns *vulns.Client

	sigMu sync.RWMutex
	sigs  *fingerprint.Set
}

func New(st *store.Store, engines scanner.Registry, c clock.Clock, model *lab.Model, cfg Config) *Manager {
	if cfg.Tick <= 0 {
		cfg.Tick = 10 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.HTTPWorkers <= 0 {
		cfg.HTTPWorkers = 8
	}
	if cfg.MinChunkTime <= 0 {
		cfg.MinChunkTime = 5 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Manager{st: st, engines: engines, clock: c, cfg: cfg, model: model, active: map[int64]context.CancelCauseFunc{}}
}

func (m *Manager) Engines() []string  { return m.engines.Names() }
func (m *Manager) Clock() clock.Clock { return m.clock }

// ReloadSignatures recompiles enabled signatures (after CRUD changes).
func (m *Manager) ReloadSignatures(ctx context.Context) error {
	set, err := m.st.LoadSignatureSet(ctx)
	if err != nil {
		return err
	}
	m.sigMu.Lock()
	m.sigs = set
	m.sigMu.Unlock()
	return nil
}

func (m *Manager) signatures() *fingerprint.Set {
	m.sigMu.RLock()
	defer m.sigMu.RUnlock()
	if m.sigs == nil {
		s, _ := fingerprint.NewSet(nil)
		return s
	}
	return m.sigs
}

// --- scheduler -------------------------------------------------------------------

// Start recovers interrupted runs and launches the scheduler loop.
func (m *Manager) Start(ctx context.Context) error {
	if err := m.ReloadSignatures(ctx); err != nil {
		return err
	}
	n, err := m.st.RecoverInterrupted(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		m.cfg.Logf("orchestrator: %d interrupted run(s) will resume from their last checkpoint", n)
	}
	go func() {
		t := time.NewTicker(m.cfg.Tick)
		defer t.Stop()
		m.Tick(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Tick(ctx)
			}
		}
	}()
	return nil
}

// Tick evaluates all jobs once.
func (m *Manager) Tick(ctx context.Context) {
	jobs, err := m.st.ListJobs(ctx)
	if err != nil {
		m.cfg.Logf("scheduler: %v", err)
		return
	}
	now := m.clock.Now()
	for _, j := range jobs {
		w, err := j.Window()
		if err != nil {
			continue
		}
		ar, err := m.st.ActiveRun(ctx, j.ID)
		if err == nil {
			if m.isActive(ar.ID) {
				continue
			}
			resumable := ar.Status == store.RunQueued || (ar.Status == store.RunPaused && ar.StatusReason != ReasonManual) || ar.Status == store.RunRunning
			if resumable && (ar.IgnoreWindow || w.IsOpen(now)) && j.Enabled {
				m.cfg.Logf("scheduler: resuming run #%d of job %q (window open)", ar.ID, j.Name)
				m.launch(ctx, ar.ID)
			}
			continue
		}
		if !j.Enabled || j.IntervalMinutes <= 0 || j.TargetCount == 0 {
			continue
		}
		if j.NextRunAt <= now.Unix() && w.IsOpen(now) {
			if _, err := m.StartRun(ctx, j.ID, "schedule", false, "scheduler"); err != nil {
				m.cfg.Logf("scheduler: job %q: %v", j.Name, err)
			}
		}
	}
}

func (m *Manager) isActive(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[id]
	return ok
}

func (m *Manager) launch(parent context.Context, runID int64) {
	m.mu.Lock()
	if _, ok := m.active[runID]; ok {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	m.active[runID] = cancel
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.execute(ctx, runID)
	}()
}

// StartRun creates a run for a job. force ignores the time window.
func (m *Manager) StartRun(ctx context.Context, jobID int64, trigger string, force bool, user string) (*store.Run, error) {
	j, err := m.st.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if ar, err := m.st.ActiveRun(ctx, jobID); err == nil {
		return ar, fmt.Errorf("job already has an unfinished run #%d (%s)", ar.ID, ar.Status)
	}
	tg, err := m.st.TargetValues(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if len(tg) == 0 {
		return nil, errors.New("job has no targets")
	}
	spec := store.SpecFromJob(j, tg)
	if m.cfg.MaxRate > 0 && spec.RatePPS > m.cfg.MaxRate {
		spec.RatePPS = m.cfg.MaxRate
	}
	sp, err := targets.Build(spec.Targets, spec.Exclusions, m.cfg.MaxTargets)
	if err != nil {
		return nil, err
	}
	if _, err := m.engines.Get(spec.Engine); err != nil {
		return nil, err
	}
	run, err := m.st.CreateRun(ctx, jobID, trigger, force, spec, sp.Len(), user)
	if err != nil {
		return nil, err
	}
	now := m.clock.Now()
	next := int64(0)
	if j.IntervalMinutes > 0 {
		next = now.Add(time.Duration(j.IntervalMinutes) * time.Minute).Unix()
	}
	m.st.SetJobSchedule(ctx, jobID, now.Unix(), next)
	w, _ := j.Window()
	if force || w.IsOpen(now) {
		m.launch(ctx, run.ID)
	} else {
		m.st.SetRunStatus(ctx, run.ID, store.RunQueued, ReasonWaiting)
	}
	return m.st.GetRun(ctx, run.ID)
}

func (m *Manager) cancelRun(id int64, cause error) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.active[id]; ok {
		c(cause)
		return true
	}
	return false
}

func (m *Manager) Pause(ctx context.Context, id int64) error {
	r, err := m.st.GetRun(ctx, id)
	if err != nil {
		return err
	}
	if m.cancelRun(id, ErrPaused) {
		return nil
	}
	if r.Status == store.RunQueued || r.Status == store.RunPaused {
		return m.st.SetRunStatus(ctx, id, store.RunPaused, ReasonManual)
	}
	return fmt.Errorf("run is %s", r.Status)
}

func (m *Manager) Resume(ctx context.Context, id int64, force bool) error {
	r, err := m.st.GetRun(ctx, id)
	if err != nil {
		return err
	}
	if r.Status != store.RunPaused && r.Status != store.RunQueued {
		return fmt.Errorf("run is %s", r.Status)
	}
	j, err := m.st.GetJob(ctx, r.JobID)
	if err != nil {
		return err
	}
	w, _ := j.Window()
	if force && !r.IgnoreWindow {
		m.st.DB.ExecContext(ctx, `UPDATE runs SET ignore_window=1 WHERE id=?`, id)
	}
	if force || r.IgnoreWindow || w.IsOpen(m.clock.Now()) {
		m.launch(ctx, id)
		return nil
	}
	return m.st.SetRunStatus(ctx, id, store.RunQueued, ReasonWaiting)
}

func (m *Manager) Cancel(ctx context.Context, id int64) error {
	if m.cancelRun(id, ErrCancelled) {
		return nil
	}
	r, err := m.st.GetRun(ctx, id)
	if err != nil {
		return err
	}
	if r.Status == store.RunCompleted || r.Status == store.RunCancelled {
		return fmt.Errorf("run is %s", r.Status)
	}
	return m.st.SetRunStatus(ctx, id, store.RunCancelled, "")
}

// StopAll is the emergency kill switch: pauses every running scan.
func (m *Manager) StopAll() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.active {
		c(ErrPaused)
	}
	return len(m.active)
}

// Shutdown pauses active runs (they resume after restart) and waits.
func (m *Manager) Shutdown(timeout time.Duration) {
	m.mu.Lock()
	for _, c := range m.active {
		c(ErrShutdown)
	}
	m.mu.Unlock()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// RunSync executes a run in the calling goroutine (demo seeding, tests).
func (m *Manager) RunSync(ctx context.Context, runID int64) {
	m.mu.Lock()
	cctx, cancel := context.WithCancelCause(ctx)
	m.active[runID] = cancel
	m.mu.Unlock()
	m.execute(cctx, runID)
}

// --- execution -----------------------------------------------------------------------

func (m *Manager) execute(ctx context.Context, runID int64) {
	defer func() {
		m.mu.Lock()
		if c, ok := m.active[runID]; ok {
			c(nil)
			delete(m.active, runID)
		}
		m.mu.Unlock()
	}()
	bg := context.WithoutCancel(ctx)
	run, err := m.st.GetRun(bg, runID)
	if err != nil {
		return
	}
	j, err := m.st.GetJob(bg, run.JobID)
	if err != nil {
		m.st.SetRunStatus(bg, runID, store.RunFailed, "job deleted")
		return
	}
	spec := run.Spec
	w, err := j.Window()
	if err != nil {
		m.st.SetRunStatus(bg, runID, store.RunFailed, err.Error())
		return
	}
	now := m.clock.Now()
	var deadline time.Time
	if !run.IgnoreWindow {
		if !w.IsOpen(now) {
			m.st.SetRunStatus(bg, runID, store.RunQueued, ReasonWaiting)
			return
		}
		deadline = w.End(now)
	}
	space, err := targets.Build(spec.Targets, spec.Exclusions, m.cfg.MaxTargets)
	if err != nil {
		m.st.SetRunStatus(bg, runID, store.RunFailed, err.Error())
		return
	}
	engine, err := m.engines.Get(spec.Engine)
	if err != nil {
		m.st.SetRunStatus(bg, runID, store.RunFailed, err.Error())
		return
	}
	m.st.MarkRunActive(bg, runID)
	segStart := m.clock.Now()
	if !deadline.IsZero() && !m.clock.Virtual() {
		cancel := m.cancelFunc(runID)
		t := time.AfterFunc(time.Until(deadline), func() { cancel(ErrWindowClosed) })
		defer t.Stop()
	}
	m.cfg.Logf("run #%d (%s, seq %d): segment start, %d/%d targets done, deadline %v", runID, j.Name, run.Seq, run.DoneTargets, run.TotalTargets, deadline)

	ex := &executor{m: m, run: run, job: j, spec: spec, space: space, engine: engine, deadline: deadline, loc: w.Loc,
		httpLim: ratelimit.New(float64(max(1, spec.HTTPRPS)), max(1, spec.HTTPRPS)), cancel: m.cancelFunc(runID)}
	if m.clock.Virtual() {
		ex.httpLim = nil // simulated time: in-memory transport, no real traffic to pace
	}
	ex.sph.Store(math.Float64bits(m.initialSecPerHost(bg, run, j)))

	conc := max(1, spec.Concurrency)
	if m.clock.Virtual() {
		conc = 1
	}
	ex.workers(ctx, conc)

	if m.finishSegment(ctx, bg, runID, segStart, w) {
		return
	}
	// Re-probe phase: give silent known hosts another chance before recording a miss.
	run, _ = m.st.GetRun(bg, runID)
	for round := run.ReprobeRound; round < spec.ReprobeAttempts; round++ {
		missing, err := m.st.MissingHosts(bg, runID)
		if err != nil || len(missing) == 0 {
			break
		}
		m.st.SetRunPhase(bg, runID, "reprobe", round+1)
		m.cfg.Logf("run #%d: re-probe round %d for %d silent host(s)", runID, round+1, len(missing))
		if err := m.clock.Sleep(ctx, time.Duration(spec.ReprobeDelaySec)*time.Second); err != nil {
			break
		}
		m.st.AddReprobeChunk(bg, runID, missing)
		ex.workers(ctx, 1)
		if context.Cause(ctx) != nil {
			break
		}
	}
	if m.finishSegment(ctx, bg, runID, segStart, w) {
		return
	}
	run, _ = m.st.GetRun(bg, runID)
	if err := m.st.FinalizeRun(bg, run, m.clock.Now(), j.Policy(), w.Loc); err != nil {
		m.st.EndSegment(bg, runID, store.RunFailed, "finalize: "+err.Error(), 0)
		return
	}
	if run.Spec.VulnLookup && m.vulns != nil {
		// escalation step: versions found -> known CVEs (passive, NVD)
		m.st.SetRunStatus(bg, runID, store.RunRunning, "")
		m.st.SetRunPhase(bg, runID, "vulns", run.ReprobeRound)
		m.lookupVulns(ctx, run)
		m.st.SetRunPhase(bg, runID, "done", run.ReprobeRound)
	}
	m.st.EndSegment(bg, runID, store.RunCompleted, "", m.clock.Now().Sub(segStart).Milliseconds())
	r, _ := m.st.GetRun(bg, runID)
	if r != nil {
		m.cfg.Logf("run #%d completed: %d hosts up, %d services, +%d new / -%d gone / ~%d changed, active %ds in %d window(s)",
			runID, r.HostsUp, r.OpenPorts, r.ChangesNew, r.ChangesGone, r.ChangesChanged, r.ActiveMS/1000, r.WindowsUsed)
	}
}

func (m *Manager) cancelFunc(runID int64) context.CancelCauseFunc {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.active[runID]; ok {
		return c
	}
	return func(error) {}
}

// finishSegment persists the outcome of an interrupted segment. Returns true
// when the run must stop here.
func (m *Manager) finishSegment(ctx, bg context.Context, runID int64, segStart time.Time, w window.Window) bool {
	cause := context.Cause(ctx)
	if cause == nil {
		return false
	}
	ms := m.clock.Now().Sub(segStart).Milliseconds()
	switch {
	case errors.Is(cause, ErrWindowClosed):
		next := w.NextOpen(m.clock.Now().Add(time.Minute))
		m.st.EndSegment(bg, runID, store.RunPaused, ReasonWindow, ms)
		m.cfg.Logf("run #%d: time window closed - checkpoint saved, resumes at %s", runID, next.Format(time.RFC3339))
	case errors.Is(cause, ErrCancelled):
		m.st.EndSegment(bg, runID, store.RunCancelled, "", ms)
	case errors.Is(cause, ErrShutdown):
		m.st.EndSegment(bg, runID, store.RunPaused, ReasonShutdown, ms)
	default:
		m.st.EndSegment(bg, runID, store.RunPaused, ReasonManual, ms)
	}
	return true
}

func (m *Manager) initialSecPerHost(ctx context.Context, run *store.Run, j *store.Job) float64 {
	if run.SecPerHost > 0 {
		return run.SecPerHost
	}
	if v := m.st.LastSecPerHost(ctx, j.ID); v > 0 {
		return v
	}
	ports, _ := scanner.ExpandPorts(run.Spec.Ports)
	n := float64(len(ports) + 10)
	if strings.HasPrefix(run.Spec.Ports, "top:") {
		fmt.Sscanf(run.Spec.Ports, "top:%f", &n)
		n += 10
	}
	perWorker := float64(max(1, run.Spec.RatePPS)) / float64(max(1, run.Spec.Concurrency))
	return math.Max(0.01, n/perWorker)
}

type executor struct {
	m        *Manager
	run      *store.Run
	job      *store.Job
	spec     store.RunSpec
	space    *targets.Space
	engine   scanner.Engine
	deadline time.Time
	loc      *time.Location
	httpLim  *ratelimit.Limiter
	cancel   context.CancelCauseFunc
	sph      atomic.Uint64 // float64 bits: EWMA seconds per host (per worker)
}

func (ex *executor) secPerHost() float64 { return math.Float64frombits(ex.sph.Load()) }

// want computes the adaptive chunk size: target duration / measured cost.
func (ex *executor) want() int64 {
	if ex.spec.ChunkSize > 0 {
		return int64(ex.spec.ChunkSize)
	}
	n := float64(max(10, ex.spec.ChunkTargetSec)) / math.Max(ex.secPerHost(), 0.0005)
	return int64(math.Max(8, math.Min(4096, n)))
}

func (ex *executor) workers(ctx context.Context, n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex.loop(ctx)
		}()
	}
	wg.Wait()
}

func (ex *executor) loop(ctx context.Context) {
	m := ex.m
	bg := context.WithoutCancel(ctx)
	for ctx.Err() == nil {
		want, maxSize := ex.want(), int64(0)
		if !ex.deadline.IsZero() {
			remaining := ex.deadline.Sub(m.clock.Now())
			if remaining < m.cfg.MinChunkTime {
				ex.cancel(ErrWindowClosed) // not enough time for another chunk: stop gracefully
				return
			}
			maxSize = int64(remaining.Seconds() * 0.8 / math.Max(ex.secPerHost(), 0.0005))
			if maxSize < 1 {
				ex.cancel(ErrWindowClosed)
				return
			}
			want = min(want, maxSize)
		}
		c, err := m.st.NextChunk(bg, ex.run.ID, want, maxSize)
		if err != nil {
			m.cfg.Logf("run #%d: next chunk: %v", ex.run.ID, err)
			return
		}
		if c == nil {
			return
		}
		tg := c.Targets
		if c.Kind == "main" {
			tg = ex.space.Slice(c.Start, c.End)
		}
		vStart, rStart := m.clock.Now(), time.Now()
		res, err := ex.engine.Scan(ctx, tg, ex.options(vStart))
		if ctx.Err() != nil {
			m.st.ReleaseChunk(bg, c.ID)
			return
		}
		if err != nil {
			m.cfg.Logf("run #%d chunk %d: %v", ex.run.ID, c.Seq, err)
			m.st.FailChunk(bg, c, err.Error(), m.cfg.MaxAttempts)
			continue
		}
		obs := ex.enrich(ctx, res, tg, vStart)
		if ctx.Err() != nil {
			m.st.ReleaseChunk(bg, c.ID)
			return
		}
		if m.clock.Virtual() && !ex.deadline.IsZero() && m.clock.Now().After(ex.deadline) {
			// simulated time ran past the window: behave like a killed scan
			m.st.ReleaseChunk(bg, c.ID)
			ex.cancel(ErrWindowClosed)
			return
		}
		stats, err := m.st.Ingest(bg, ex.run, obs, vStart, ex.job.Policy(), ex.loc)
		if err != nil {
			m.cfg.Logf("run #%d chunk %d ingest: %v", ex.run.ID, c.Seq, err)
			m.st.FailChunk(bg, c, "ingest: "+err.Error(), m.cfg.MaxAttempts)
			continue
		}
		dur := time.Since(rStart)
		if m.clock.Virtual() {
			dur = m.clock.Now().Sub(vStart)
		}
		m.st.CompleteChunk(bg, c, stats.HostsUp, stats.OpenPorts, dur.Milliseconds(), ex.spec.Concurrency)
		if c.Kind == "main" && c.Size() > 0 {
			obsSph := dur.Seconds() / float64(c.Size())
			old := ex.secPerHost()
			ex.sph.Store(math.Float64bits(old*0.6 + obsSph*0.4))
		}
	}
}

func (ex *executor) options(now time.Time) scanner.Options {
	extra, _ := scanner.ParseExtra(ex.spec.NmapExtra)
	rate := ex.spec.RatePPS / max(1, ex.spec.Concurrency)
	return scanner.Options{Ports: ex.spec.Ports, RatePPS: max(1, rate), Timing: ex.spec.Timing, ServiceDetection: ex.spec.ServiceDetection,
		Extra: extra, HostTimeout: 5 * time.Minute, Generation: ex.run.Seq, Now: now}
}

// enrich adds HTTP fingerprints, detections and insights; also synthesises
// "down" observations for chunk targets the engine did not report as up.
func (ex *executor) enrich(ctx context.Context, res []scanner.HostResult, chunk []string, at time.Time) []store.HostObs {
	upKeys := map[string]bool{}
	var out []store.HostObs
	sigs := ex.m.signatures()
	var paths []string
	if ex.spec.PathProbes {
		paths = sigs.Paths()
	}
	type job struct {
		hi, si int
	}
	var jobs []job
	for _, hr := range res {
		if !hr.Up {
			continue
		}
		upKeys[hr.Address] = true
		if hr.Target != "" {
			upKeys[hr.Target] = true
		}
		ho := store.HostObs{Address: hr.Address, Hostname: hr.Hostname, Target: hr.Target, OS: hr.OS, Up: true}
		for _, p := range hr.Ports {
			ho.Services = append(ho.Services, store.ServiceObs{PortResult: p})
		}
		out = append(out, ho)
	}
	for hi := range out {
		for si, sv := range out[hi].Services {
			if ex.spec.HTTPFingerprint && fingerprint.IsWebCandidate(sv.Port, sv.Name, sv.Tunnel) {
				jobs = append(jobs, job{hi, si})
			}
		}
	}
	// bounded-parallel HTTP probing; global rate enforced by ex.httpLim
	ch := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < min(ex.m.cfg.HTTPWorkers, max(1, len(jobs))); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				ho := &out[j.hi]
				sv := &ho.Services[j.si]
				p := fingerprint.NewProber(ex.httpLim)
				p.Now = func() time.Time { return at }
				if ex.spec.Engine == "sim" && ex.m.model != nil {
					p.TransportFor = ex.m.model.Transport(at, ex.run.Seq)
				}
				tls := sv.Tunnel == "ssl" || strings.Contains(sv.Name, "https") || strings.Contains(sv.Name, "ssl")
				info := p.Probe(ctx, fingerprint.Target{Address: ho.Address, Port: sv.Port, VHost: ho.Target, Paths: paths, TLSHint: tls})
				if info.Error == "" {
					sv.HTTP = info
				}
			}
		}()
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		ch <- j
	}
	close(ch)
	wg.Wait()
	for hi := range out {
		ho := &out[hi]
		name := ho.Target
		if name == "" {
			name = ho.Hostname
		}
		for si := range ho.Services {
			sv := &ho.Services[si]
			ev := &fingerprint.Evidence{Address: ho.Address, Hostname: name, Port: sv.Port, Service: sv.Name, Product: sv.Product,
				Version: sv.Version, Banner: sv.Banner, HTTP: sv.HTTP}
			sv.Detections = append(sigs.Evaluate(ev), fingerprint.Components(sv.HTTP)...)
			sv.Insights = fingerprint.Insights(sv.HTTP)
		}
	}
	for _, t := range chunk {
		if !upKeys[t] {
			ho := store.HostObs{Address: t, Up: false}
			if !targets.IsIP(t) {
				ho.Target = t
			}
			out = append(out, ho)
		}
	}
	return out
}

// Enricher returns a function applying signatures to manual/imported data.
func (m *Manager) Enricher() store.Enricher {
	return func(o store.ServiceObs, hostname string) store.ServiceObs {
		ev := &fingerprint.Evidence{Hostname: hostname, Port: o.Port, Service: o.Name, Product: o.Product, Version: o.Version, Banner: o.Banner, HTTP: o.HTTP}
		o.Detections = m.signatures().Evaluate(ev)
		o.Insights = fingerprint.Insights(o.HTTP)
		return o
	}
}

// Import ingests externally produced results through the same pipeline as
// scans (signatures, scoring, diffing, state machine).
func (m *Manager) Import(ctx context.Context, hosts []store.HostObs, user string) (*store.Run, error) {
	if len(hosts) == 0 {
		return nil, errors.New("no hosts in import")
	}
	enrich := m.Enricher()
	for hi := range hosts {
		name := hosts[hi].Target
		if name == "" {
			name = hosts[hi].Hostname
		}
		for si := range hosts[hi].Services {
			hosts[hi].Services[si] = enrich(hosts[hi].Services[si], name)
		}
	}
	spec := store.RunSpec{Engine: "import", Ports: "1-65535"}
	run, err := m.st.CreateRun(ctx, 0, "import", true, spec, int64(len(hosts)), user)
	if err != nil {
		return nil, err
	}
	m.st.MarkRunActive(ctx, run.ID)
	start := m.clock.Now()
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if _, err := m.st.Ingest(ctx, run, hosts, start, store.DefaultPolicy(), loc); err != nil {
		m.st.EndSegment(ctx, run.ID, store.RunFailed, err.Error(), 0)
		return nil, err
	}
	run, _ = m.st.GetRun(ctx, run.ID)
	if err := m.st.FinalizeRun(ctx, run, m.clock.Now(), store.DefaultPolicy(), loc); err != nil {
		return nil, err
	}
	m.st.EndSegment(ctx, run.ID, store.RunCompleted, "", m.clock.Now().Sub(start).Milliseconds())
	return m.st.GetRun(ctx, run.ID)
}
