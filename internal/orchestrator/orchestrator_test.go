package orchestrator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asi/internal/clock"
	"asi/internal/crypto"
	"asi/internal/lab"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
)

type env struct {
	st    *store.Store
	m     *Manager
	fc    *clock.Fake
	job   *store.Job
	dbp   string
	loc   *time.Location
	model *lab.Model
}

func setup(t *testing.T, costPerHost time.Duration) *env {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("tzdata")
	}
	dir := t.TempDir()
	dbp := filepath.Join(dir, "asi.db")
	st, err := store.Open(dbp, crypto.RandomKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.SyncBuiltinSignatures(ctx); err != nil {
		t.Fatal(err)
	}
	// Monday 23 Nov 2026, 05:50 local - 10 minutes before the night window closes.
	fc := clock.NewFake(time.Date(2026, 11, 23, 5, 50, 0, 0, loc))
	st.Now = fc.Now
	model := lab.NewModel(fc.Now())
	eng := scanner.Registry{"sim": &scanner.Sim{Model: model, Clock: fc, CostPerHost: costPerHost}}
	m := New(st, eng, fc, model, Config{MaxTargets: 1 << 20, Logf: t.Logf})
	if err := m.ReloadSignatures(ctx); err != nil {
		t.Fatal(err)
	}
	j := &store.Job{Name: "test", Enabled: true, Engine: "sim", Ports: "top:200", RatePPS: 300, HTTPRPS: 200, Concurrency: 4,
		ChunkTargetSec: 60, Timing: "T3", ServiceDetection: true, HTTPFingerprint: true, PathProbes: true,
		WindowDays: "1111111", WindowStart: "22:00", WindowEnd: "06:00", Timezone: "Europe/Warsaw", IntervalMinutes: 1440,
		InactiveAfter: 3, ReprobeAttempts: 1, ReprobeDelaySec: 30}
	j.Defaults()
	if err := j.Validate(0); err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateJob(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddTargets(ctx, id, []store.TargetInput{{Value: "10.20.0.0/20"}, {Value: "staging.rekrutacja.lab.agh.local"}}, "test", 0); err != nil {
		t.Fatal(err)
	}
	job, _ := st.GetJob(ctx, id)
	return &env{st: st, m: m, fc: fc, job: job, dbp: dbp, loc: loc, model: model}
}

func (e *env) newRun(t *testing.T) *store.Run {
	t.Helper()
	ctx := context.Background()
	tg, _ := e.st.TargetValues(ctx, e.job.ID)
	spec := store.SpecFromJob(e.job, tg)
	sp, err := targets.Build(spec.Targets, spec.Exclusions, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.st.CreateRun(ctx, e.job.ID, "test", false, spec, sp.Len(), "tester")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) runAt(t *testing.T, at time.Time) *store.Run {
	t.Helper()
	e.fc.Set(at)
	r := e.newRun(t)
	e.m.RunSync(context.Background(), r.ID)
	r, _ = e.st.GetRun(context.Background(), r.ID)
	return r
}

func TestWindowCheckpointResumeAndChangeDetection(t *testing.T) {
	e := setup(t, 250*time.Millisecond) // 4097 targets * 0.25s = ~17 min of (virtual) scanning
	ctx := context.Background()

	// --- Run 1 starts 10 minutes before the window closes -> must pause.
	r1 := e.newRun(t)
	e.m.RunSync(ctx, r1.ID)
	r1, _ = e.st.GetRun(ctx, r1.ID)
	if r1.Status != store.RunPaused || r1.StatusReason != ReasonWindow {
		t.Fatalf("expected pause at window end, got %s/%s", r1.Status, r1.StatusReason)
	}
	if r1.DoneTargets == 0 || r1.DoneTargets >= r1.TotalTargets {
		t.Fatalf("expected partial progress, got %d/%d", r1.DoneTargets, r1.TotalTargets)
	}
	if e.fc.Now().After(time.Date(2026, 11, 23, 6, 0, 0, 0, e.loc)) {
		t.Fatalf("scan overran the window: %v", e.fc.Now())
	}
	partial := r1.DoneTargets
	t.Logf("window 1: %d/%d targets, active %dms", r1.DoneTargets, r1.TotalTargets, r1.ActiveMS)

	// Scheduler must not resume while the window is closed.
	e.fc.Set(time.Date(2026, 11, 23, 12, 0, 0, 0, e.loc))
	if w, _ := e.job.Window(); w.IsOpen(e.fc.Now()) {
		t.Fatal("window should be closed at noon")
	}
	e.m.RunSync(ctx, r1.ID) // executor itself refuses to scan outside the window
	r1, _ = e.st.GetRun(ctx, r1.ID)
	if r1.DoneTargets != partial || r1.Status == store.RunCompleted {
		t.Fatalf("scanned outside the window: %+v", r1)
	}

	// --- Next window (22:00) resumes from the checkpoint and completes.
	e.fc.Set(time.Date(2026, 11, 23, 22, 0, 0, 0, e.loc))
	e.m.RunSync(ctx, r1.ID)
	r1, _ = e.st.GetRun(ctx, r1.ID)
	if r1.Status != store.RunCompleted || r1.DoneTargets != r1.TotalTargets {
		t.Fatalf("expected completion after resume, got %s %d/%d (%s)", r1.Status, r1.DoneTargets, r1.TotalTargets, r1.StatusReason)
	}
	if r1.WindowsUsed < 2 {
		t.Fatalf("expected >=2 windows, got %d", r1.WindowsUsed)
	}
	chunks, _ := e.st.ListChunks(ctx, r1.ID, 0)
	first, maxSz := chunks[0].Size(), int64(0)
	seen := map[int64]bool{}
	for _, c := range chunks {
		if c.Kind != "main" {
			continue
		}
		if c.Size() > maxSz {
			maxSz = c.Size()
		}
		for i := c.Start; i < c.End; i++ {
			if seen[i] {
				t.Fatalf("target index %d scanned twice (checkpoint overlap)", i)
			}
			seen[i] = true
		}
	}
	if int64(len(seen)) != r1.TotalTargets {
		t.Fatalf("coverage %d != %d", len(seen), r1.TotalTargets)
	}
	if maxSz < 3*first {
		t.Fatalf("adaptive chunking expected (first=%d max=%d)", first, maxSz)
	}
	t.Logf("run1: %d hosts up, %d services, %d chunks (first %d, max %d)", r1.HostsUp, r1.OpenPorts, len(chunks), first, maxSz)
	if r1.HostsUp < 100 || r1.OpenPorts < 200 {
		t.Fatalf("too few results: %+v", r1)
	}
	if r1.ChangesNew != 0 {
		t.Fatalf("baseline run must not flood change feed, got %d new", r1.ChangesNew)
	}

	// --- Analyst edits a finding; it must survive later scans.
	svcs, _, _ := e.st.ListServices(ctx, store.ServiceFilter{Q: "staging.rekrutacja", Limit: 10})
	if len(svcs) == 0 {
		t.Fatal("staging host not found")
	}
	var stg *store.Service
	for _, s := range svcs {
		if s.Port == 80 {
			stg = s
		}
	}
	if stg == nil {
		t.Fatalf("staging web service missing: %+v", svcs)
	}
	hasCat := func(s *store.Service, c string) bool {
		for _, x := range s.Categories {
			if x == c {
				return true
			}
		}
		return false
	}
	if !hasCat(stg, "staging") || stg.Priority != "critical" {
		t.Fatalf("staging should be detected and critical: %+v", stg)
	}
	prod := "Rekrutacja (aplikacja wewnętrzna)"
	note := "secret note XYZ – właściciel: dział IT"
	tags := []string{"rekrutacja", "do-weryfikacji"}
	tri := "confirmed"
	if _, err := e.st.UpdateAnnotation(ctx, "service", stg.ID, store.AnnotationPatch{Tags: &tags, Note: &note, Triage: &tri,
		Overrides: map[string]*string{"product": &prod}}, "analyst"); err != nil {
		t.Fatal(err)
	}

	// --- Run 2 (generation 2): upgrades, new hosts appear.
	r2 := e.runAt(t, time.Date(2026, 11, 24, 23, 0, 0, 0, e.loc))
	if r2.Status != store.RunCompleted {
		t.Fatalf("run2 %s %s", r2.Status, r2.StatusReason)
	}
	if r2.ChangesChanged == 0 || r2.ChangesNew == 0 {
		t.Fatalf("run2 should detect changed and new services: %+v", r2)
	}
	after, err := e.st.GetService(ctx, stg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Product != prod || after.Observed["product"] == prod || after.Triage != "confirmed" || len(after.Tags) != 2 || after.Annotation.Note != note {
		t.Fatalf("manual edits lost after rescan: product=%q observed=%v triage=%q tags=%v note=%q", after.Product, after.Observed, after.Triage, after.Tags, after.Annotation.Note)
	}
	if after.LastSeen != r2.FinishedAt && after.LastSeen < r1.FinishedAt {
		t.Fatalf("scan layer should still update last_seen")
	}

	cmp, err := e.st.CompareRuns(ctx, r1.ID, r2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp.Changed) == 0 || len(cmp.New) == 0 {
		t.Fatalf("compare: changed=%d new=%d", len(cmp.Changed), len(cmp.New))
	}
	vchg := false
	for _, c := range cmp.Changed {
		for _, f := range c.Fields {
			if f.Field == "version" || f.Field == "tech" || f.Field == "cert_sha256" {
				vchg = true
			}
		}
	}
	if !vchg {
		t.Fatalf("expected version/tech/cert changes in compare: %+v", cmp.Changed[:1])
	}

	// --- Runs 3..5: services disappear, decommissioned hosts go suspect -> inactive.
	e.runAt(t, time.Date(2026, 11, 25, 23, 0, 0, 0, e.loc))
	e.runAt(t, time.Date(2026, 11, 26, 23, 0, 0, 0, e.loc))
	r5 := e.runAt(t, time.Date(2026, 11, 27, 23, 0, 0, 0, e.loc))
	gone, _ := e.st.ListChanges(ctx, store.ChangeFilter{Kinds: []string{store.ChServiceGone}, Limit: 1000})
	inactive, _ := e.st.ListChanges(ctx, store.ChangeFilter{Kinds: []string{"host_inactive"}, Limit: 1000})
	suspect, _ := e.st.ListChanges(ctx, store.ChangeFilter{Kinds: []string{"host_suspect"}, Limit: 1000})
	if len(gone) == 0 || len(inactive) == 0 || len(suspect) == 0 {
		t.Fatalf("expected gone services (%d), suspect (%d) and inactive hosts (%d)", len(gone), len(suspect), len(inactive))
	}
	// a host must be suspect before it becomes inactive
	for _, in := range inactive {
		ok := false
		for _, s := range suspect {
			if s.HostID == in.HostID && s.RunID < in.RunID {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("host %s became inactive without a suspect phase", in.Address)
		}
	}
	t.Logf("run5: +%d -%d ~%d; total gone=%d suspect=%d inactive=%d", r5.ChangesNew, r5.ChangesGone, r5.ChangesChanged, len(gone), len(suspect), len(inactive))

	// --- Encryption at rest: sensitive values never appear in the raw DB files.
	e.st.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	var raw []byte
	for _, p := range []string{e.dbp, e.dbp + "-wal"} {
		b, _ := os.ReadFile(p)
		raw = append(raw, b...)
	}
	for _, secret := range []string{"secret note XYZ", "app-stg-02.internal", "eyJpdi", "Rekrutacja (aplikacja", "refs/heads/develop"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("plaintext %q found in database file", secret)
		}
	}
	var httpEnc, noteEnc string
	e.st.DB.QueryRow(`SELECT http_enc FROM services WHERE id=?`, stg.ID).Scan(&httpEnc)
	e.st.DB.QueryRow(`SELECT note_enc FROM annotations WHERE entity_type='service' AND entity_id=?`, stg.ID).Scan(&noteEnc)
	if !strings.HasPrefix(httpEnc, crypto.Prefix) || !strings.HasPrefix(noteEnc, crypto.Prefix) {
		t.Fatalf("columns not encrypted: %q %q", httpEnc[:20], noteEnc[:20])
	}
	// ...but decrypt transparently through the store.
	d, _ := e.st.GetService(ctx, stg.ID)
	if d.HTTP == nil || d.HTTP.Header("X-Backend-Server") != "app-stg-02.internal" {
		t.Fatal("decryption through store failed")
	}
}

func TestReprobeRecoversFlakyHosts(t *testing.T) {
	e := setup(t, time.Millisecond)
	e.fc.Set(time.Date(2026, 11, 23, 23, 0, 0, 0, e.loc))
	r1 := e.newRun(t)
	e.m.RunSync(context.Background(), r1.ID)
	e.runAt(t, time.Date(2026, 11, 24, 23, 0, 0, 0, e.loc))
	r3 := e.runAt(t, time.Date(2026, 11, 25, 23, 0, 0, 0, e.loc)) // decommissioned hosts go silent in generation 3
	chunks, _ := e.st.ListChunks(context.Background(), r3.ID, 0)
	re := 0
	for _, c := range chunks {
		if c.Kind == "reprobe" {
			re++
			if c.HostsUp == 0 && len(c.Targets) > 5 {
				t.Logf("reprobe chunk with %d targets recovered none", len(c.Targets))
			}
		}
	}
	if re == 0 {
		t.Fatal("expected a re-probe round for hosts that went silent")
	}
}

func TestManualEntryProcessedLikeScan(t *testing.T) {
	e := setup(t, time.Millisecond)
	ctx := context.Background()
	hid, sids, err := e.st.CreateManual(ctx, store.ManualHost{Address: "192.0.2.10", Hostname: "legacy-db.agh.local", Tags: []string{"Legacy"},
		Services: []store.ManualService{{Port: 6379, Name: "redis", Product: "Redis key-value store", Note: "zgłoszone przez admina"}}}, e.m.Enricher(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	sv, err := e.st.GetService(ctx, sids[0])
	if err != nil {
		t.Fatal(err)
	}
	if sv.Origin != "manual" || sv.HostID != hid || len(sv.Tech) == 0 || sv.Tech[0].Name != "Redis" || sv.Curiosity == 0 {
		t.Fatalf("manual service not enriched/scored like scan data: %+v", sv)
	}
	h, _ := e.st.GetHost(ctx, hid)
	if len(h.Tags) != 1 || h.Tags[0] != "legacy" {
		t.Fatalf("tags: %+v", h.Tags)
	}
}

func TestDataScopeSeparatesDemoFromReal(t *testing.T) {
	e := setup(t, time.Millisecond)
	ctx := context.Background()
	e.runAt(t, time.Date(2026, 11, 23, 23, 0, 0, 0, e.loc)) // simulator job = demo data
	hid, _, err := e.st.CreateManual(ctx, store.ManualHost{Address: "192.0.2.10",
		Services: []store.ManualService{{Port: 22, Name: "ssh", Product: "OpenSSH"}}}, e.m.Enricher(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	count := func(sc store.Scope) (hosts, services, jobs int) {
		c := store.WithScope(ctx, sc)
		_, hosts, _ = e.st.ListHosts(c, store.HostFilter{})
		_, services, _ = e.st.ListServices(c, store.ServiceFilter{})
		j, _ := e.st.ListJobs(c)
		return hosts, services, len(j)
	}
	ah, as, aj := count(store.ScopeAll)
	rh, rs, rj := count(store.ScopeReal)
	dh, ds, dj := count(store.ScopeDemo)
	if rh != 1 || rs != 1 || rj != 0 {
		t.Fatalf("real scope must hold only the manual entry: hosts=%d services=%d jobs=%d", rh, rs, rj)
	}
	if dh != ah-1 || ds != as-1 || dj != aj || dh == 0 {
		t.Fatalf("demo scope must hold the simulator data: demo %d/%d/%d all %d/%d/%d", dh, ds, dj, ah, as, aj)
	}
	d, err := e.st.Dashboard(store.WithScope(ctx, store.ScopeReal))
	if err != nil {
		t.Fatal(err)
	}
	if d.Totals.Hosts != 1 || d.Totals.Services != 1 || d.Totals.Jobs != 0 || len(d.Trend) != 0 {
		t.Fatalf("real dashboard leaks demo data: %+v trend=%d", d.Totals, len(d.Trend))
	}
	// detail views are not filtered
	if h, err := e.st.GetHost(store.WithScope(ctx, store.ScopeDemo), hid); err != nil || len(h.Services) != 1 {
		t.Fatalf("host detail must ignore scope: %v", err)
	}
	if !e.st.HasDemoData(ctx) {
		t.Fatal("HasDemoData")
	}
}

func TestSubdomainBase(t *testing.T) {
	for in, want := range map[string]string{"www.agh.edu.pl": "agh.edu.pl", "WWW.Example.org.": "example.org", "agh.edu.pl": "agh.edu.pl",
		"www.com": "www.com", "panel.agh.edu.pl": "panel.agh.edu.pl"} {
		if got := SubdomainBase(in); got != want {
			t.Errorf("SubdomainBase(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPublicDomain(t *testing.T) {
	for d, want := range map[string]bool{"agh.edu.pl": true, "www.agh.edu.pl": true, "localhost": false, "gitea": false,
		"app.lab.local": false, "x.localhost": false, "db.internal": false} {
		if got := PublicDomain(d); got != want {
			t.Errorf("PublicDomain(%q)=%v want %v", d, got, want)
		}
	}
}
