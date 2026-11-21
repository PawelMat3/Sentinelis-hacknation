// Package demo seeds a realistic dataset for presentations: three days of
// simulated scans of a 16k-address campus network (time-of-day dependent
// hosts, upgrades, new and vanishing services), a night-window DMZ scan that
// pauses at 06:00 and resumes the next night, demo users for every role,
// custom signatures, analyst annotations and a manually entered host.
package demo

import (
	"context"
	"fmt"
	"time"

	"asi/internal/clock"
	"asi/internal/fingerprint"
	"asi/internal/lab"
	"asi/internal/orchestrator"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
)

const DefaultPassword = "Demo-ASI-2026!"

type Result struct {
	Runs  int
	Users []string
}

// Seed populates an empty database. It uses a virtual clock so three days of
// scanning are generated in under a minute.
func Seed(ctx context.Context, st *store.Store, password string, logf func(string, ...any)) (*Result, error) {
	if password == "" {
		password = DefaultPassword
	}
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		loc = time.UTC
	}
	realNow := time.Now().In(loc)
	day0 := time.Date(realNow.Year(), realNow.Month(), realNow.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -3)
	fc := clock.NewFake(day0)
	origNow := st.Now
	st.Now = fc.Now
	defer func() { st.Now = origNow }()

	res := &Result{}
	// --- users & custom role
	roles := map[string]int64{}
	rl, _ := st.ListRoles(ctx)
	for _, r := range rl {
		roles[r.Name] = r.ID
	}
	socID, err := st.CreateRole(ctx, store.Role{Name: "Zespół SOC (rola własna)", Description: "Przykład roli niestandardowej: triage znalezisk i eksport do DefectDojo",
		Permissions: []string{store.PermAssetsRead, store.PermAssetsUpdate, store.PermJobsRead, store.PermSigsRead, store.PermDataExport, store.PermDojoExport}})
	if err != nil {
		return nil, err
	}
	users := []struct {
		u, d string
		role int64
	}{
		{"operator", "Operator skanów", roles["Dodawanie, usuwanie, modyfikacja"]},
		{"analityk", "Analityk bezpieczeństwa", roles["Modyfikacja i odczyt"]},
		{"audytor", "Audytor (tylko odczyt)", roles["Odczyt"]},
		{"soc", "Dyżurny SOC", socID},
	}
	for _, x := range users {
		if _, err := st.CreateUser(ctx, x.u, x.d, password, x.role); err == nil {
			res.Users = append(res.Users, x.u)
		}
	}

	// --- custom signatures (before scanning so they apply)
	model := lab.NewModel(day0)
	customs := []*fingerprint.Signature{
		{Name: "Panel administracyjny AGH (favicon)", Category: "admin-panel", Description: "Własna sygnatura: hash favicony wewnętrznego panelu (mmh3, zgodny z Shodan)",
			Enabled: true, Def: fingerprint.Definition{Curiosity: 20, Tags: []string{"wewnętrzne"}, Matchers: []fingerprint.Matcher{
				{Type: fingerprint.MFavicon, Value: fingerprint.FaviconHash(lab.FakeIcon("custom-admin")), Weight: 0.95}}}},
		{Name: "Aplikacja rekrutacyjna", Category: "app", Description: "Własna sygnatura: endpoint /version zwraca nazwę aplikacji, nagłówek środowiska",
			Enabled: true, Def: fingerprint.Definition{Curiosity: 10, Matchers: []fingerprint.Matcher{
				{Type: fingerprint.MPath, Path: "/version", Status: []int{200}, Pattern: `"app":\s*"rekrutacja"`, Weight: 0.9},
				{Type: fingerprint.MHeader, Name: "X-Backend-Server", Pattern: `app-stg`, Weight: 0.5}}}},
		{Name: "Ciasteczko F5/BIG-IP lub sesja bez flag", Category: "cookie", Description: "Przykład: wykrywanie ciasteczek sesyjnych PHP bez flagi HttpOnly",
			Enabled: true, Def: fingerprint.Definition{Condition: "all", Curiosity: 5, Matchers: []fingerprint.Matcher{
				{Type: fingerprint.MCookie, Pattern: `^PHPSESSID$`, Weight: 0.6}, {Type: fingerprint.MTitle, Pattern: `panel|logowanie`, Weight: 0.4}}}},
	}
	for _, sg := range customs {
		if _, err := st.CreateSignature(ctx, sg, "demo"); err != nil {
			return nil, fmt.Errorf("signature %s: %w", sg.Name, err)
		}
	}

	sim := &scanner.Sim{Model: model, Clock: fc, CostPerHost: 20 * time.Millisecond}
	eng := scanner.Registry{"sim": sim}
	m := orchestrator.New(st, eng, fc, model, orchestrator.Config{MaxTargets: 1 << 20, Logf: logf})
	if err := m.ReloadSignatures(ctx); err != nil {
		return nil, err
	}

	// --- job A: campus network, 16k addresses + DNS names, scanned 4x a day
	jobA := &store.Job{Name: "Kampus – sieć główna (symulacja 16k IP)", Description: "Demonstracja: 10.20.0.0/18 + nazwy domenowe; hosty zależne od pory dnia, zmiany wersji, nowe i znikające usługi.",
		Enabled: true, Engine: "sim", Ports: "top:200", RatePPS: 1500, HTTPRPS: 50, Concurrency: 4, ChunkTargetSec: 60, Timing: "T3",
		ServiceDetection: true, HTTPFingerprint: true, PathProbes: true, WindowAlways: true, Timezone: "Europe/Warsaw", IntervalMinutes: 360,
		InactiveAfter: 3, ReprobeAttempts: 2, ReprobeDelaySec: 30}
	jobA.Defaults()
	aID, err := st.CreateJob(ctx, jobA)
	if err != nil {
		return nil, err
	}
	tin := []store.TargetInput{{Value: "10.20.0.0/18", Tags: []string{"kampus"}, Note: "Sieć główna kampusu (symulacja)"}}
	for _, n := range model.Names() {
		tin = append(tin, store.TargetInput{Value: n, Tags: []string{"dns"}})
	}
	if _, err := st.AddTargets(ctx, aID, tin, "demo", 0); err != nil {
		return nil, err
	}

	// --- job B: DMZ scanned only at night 22:00-06:00 (window demo)
	jobB := &store.Job{Name: "DMZ – okno nocne 22:00–06:00 (symulacja)", Description: "Demonstracja okna czasowego: skan przerwany o 06:00 i wznowiony z punktu kontrolnego następnej nocy.",
		Enabled: true, Engine: "sim", Ports: "top:100", RatePPS: 300, HTTPRPS: 20, Concurrency: 4, ChunkTargetSec: 60, Timing: "T3",
		ServiceDetection: true, HTTPFingerprint: true, PathProbes: true, WindowDays: "1111111", WindowStart: "22:00", WindowEnd: "06:00",
		Timezone: "Europe/Warsaw", IntervalMinutes: 1440, InactiveAfter: 3, ReprobeAttempts: 1, ReprobeDelaySec: 30}
	jobB.Defaults()
	bID, err := st.CreateJob(ctx, jobB)
	if err != nil {
		return nil, err
	}
	if _, err := st.AddTargets(ctx, bID, []store.TargetInput{{Value: "10.30.0.0/20", Tags: []string{"dmz"}}}, "demo", 0); err != nil {
		return nil, err
	}

	// --- job C: real lab scan with nmap (run live during the demo)
	jobC := &store.Job{Name: "Laboratorium – prawdziwy skan (asi lab)", Description: "Uruchom `asi lab` i ten skan, aby pokazać nmap + fingerprinting na żywo (127.0.1.1–10). Host .9 odpowiada tylko w parzystych minutach.",
		Enabled: true, Engine: "nmap", Ports: "3000,5000,8021-8025,8080,8081,8443,9100,9200", RatePPS: 200, HTTPRPS: 10, Concurrency: 2, ChunkTargetSec: 30,
		Timing: "T3", ServiceDetection: true, HTTPFingerprint: true, PathProbes: true, WindowAlways: true, Timezone: "Europe/Warsaw",
		IntervalMinutes: 0, InactiveAfter: 3, ReprobeAttempts: 2, ReprobeDelaySec: 20}
	jobC.Defaults()
	cID, err := st.CreateJob(ctx, jobC)
	if err != nil {
		return nil, err
	}
	st.AddTargets(ctx, cID, []store.TargetInput{{Value: "127.0.1.1-127.0.1.10", Tags: []string{"lab"}}}, "demo", 0)

	runJob := func(jobID int64, at time.Time) (*store.Run, error) {
		fc.Set(at)
		j, _ := st.GetJob(ctx, jobID)
		tg, _ := st.TargetValues(ctx, jobID)
		spec := store.SpecFromJob(j, tg)
		sp, err := targets.Build(spec.Targets, spec.Exclusions, 0)
		if err != nil {
			return nil, err
		}
		r, err := st.CreateRun(ctx, jobID, "schedule", false, spec, sp.Len(), "scheduler")
		if err != nil {
			return nil, err
		}
		m.RunSync(ctx, r.ID)
		res.Runs++
		return st.GetRun(ctx, r.ID)
	}

	hours := []struct{ d, h int }{{0, 2}, {0, 8}, {0, 14}, {0, 20}, {1, 2}, {1, 10}, {1, 15}, {1, 21}, {2, 3}, {2, 13}}
	for i, x := range hours {
		at := day0.AddDate(0, 0, x.d).Add(time.Duration(x.h) * time.Hour)
		r, err := runJob(aID, at)
		if err != nil {
			return nil, err
		}
		logf("demo: run %d/%d %s – %d hosts, %d services, +%d/-%d/~%d", i+1, len(hours), at.Format("Mon 15:04"), r.HostsUp, r.OpenPorts, r.ChangesNew, r.ChangesGone, r.ChangesChanged)
		if i == 0 {
			annotate(ctx, st, logf)
		}
	}
	// night window demo: starts 05:52, pauses at 06:00, resumes next night
	sim.CostPerHost = 200 * time.Millisecond // slower segment so the scan cannot finish before 06:00
	rb, err := runJob(bID, day0.AddDate(0, 0, 1).Add(5*time.Hour+52*time.Minute))
	if err != nil {
		return nil, err
	}
	logf("demo: DMZ run paused: %s (%s) after %d/%d targets", rb.Status, rb.StatusReason, rb.DoneTargets, rb.TotalTargets)
	fc.Set(day0.AddDate(0, 0, 1).Add(22 * time.Hour))
	m.RunSync(ctx, rb.ID)
	rb, _ = st.GetRun(ctx, rb.ID)
	logf("demo: DMZ run resumed in next window: %s, windows used %d", rb.Status, rb.WindowsUsed)

	// manual host entered by an operator (processed like scan data)
	fc.Set(day0.AddDate(0, 0, 2).Add(9 * time.Hour))
	st.CreateManual(ctx, store.ManualHost{Address: "10.20.63.250", Hostname: "stary-nas.wydzial.lab.agh.local", Tags: []string{"legacy", "zgłoszenie"},
		Note: "Zgłoszony przez administratora wydziału – serwer plików poza inwentaryzacją.",
		Services: []store.ManualService{{Port: 445, Name: "microsoft-ds", Product: "Samba smbd", Version: "3.6.25", Note: "Bardzo stara wersja Samby"},
			{Port: 21, Name: "ftp", Product: "vsftpd", Version: "2.3.4"}}}, m.Enricher(), "operator")

	// the manual entry above belongs to the demo dataset as well (UI "demo" scope)
	st.DB.ExecContext(ctx, `UPDATE hosts SET job_id=? WHERE job_id IS NULL`, aID)

	// schedule: next runs in the (real) future
	now := origNow()
	st.SetJobSchedule(ctx, aID, now.Add(-2*time.Hour).Unix(), now.Add(6*time.Hour).Unix())
	if w, err := jobB.Window(); err == nil {
		st.SetJobSchedule(ctx, bID, now.Add(-20*time.Hour).Unix(), w.NextOpen(now.Add(time.Hour)).Unix())
	}
	return res, nil
}

// annotate simulates analyst work right after the baseline scan.
func annotate(ctx context.Context, st *store.Store, logf func(string, ...any)) {
	set := func(f store.ServiceFilter, p store.AnnotationPatch, who string) int {
		items, _, _ := st.ListServices(ctx, f)
		n := 0
		for _, it := range items {
			if _, err := st.UpdateAnnotation(ctx, "service", it.ID, p, who); err == nil {
				n++
			}
		}
		return n
	}
	str := func(s string) *string { return &s }
	tags := func(t ...string) *[]string { return &t }
	set(store.ServiceFilter{Q: "staging.rekrutacja", Limit: 5}, store.AnnotationPatch{Tags: tags("rekrutacja", "do-wyłączenia"),
		Triage: str("confirmed"), Owner: str("Dział Rekrutacji"), Note: str("Środowisko testowe dostępne z sieci kampusu. Właściciel potwierdził – wyłączenie do końca miesiąca."),
		Overrides: map[string]*string{"product": str("System rekrutacji (STAGING)")}}, "analityk")
	set(store.ServiceFilter{Category: "iot", Limit: 3}, store.AnnotationPatch{Tags: tags("cctv"), Triage: str("accepted_risk"),
		Note: str("Kamery w VLAN monitoringu – ryzyko zaakceptowane przez ochronę obiektu.")}, "analityk")
	set(store.ServiceFilter{Tech: "Jenkins", Limit: 2}, store.AnnotationPatch{Tags: tags("ci", "devops"), Triage: str("in_progress"),
		PriorityOverride: str("critical"), Note: str("Jenkins bez SSO – zgłoszono do zespołu DevOps.")}, "operator")
	set(store.ServiceFilter{Tech: "Drukarka sieciowa", Limit: 2}, store.AnnotationPatch{Triage: str("false_positive"),
		Note: str("To serwer wydruku, nie drukarka – korekta ręczna."), Overrides: map[string]*string{"name": str("print-server")}}, "analityk")
	logf("demo: analyst annotations applied (they must survive all later scans)")
}

var _ = context.Background
