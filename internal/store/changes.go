package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"asi/internal/analysis"
)

type ChangeRow struct {
	ID        int64           `json:"id"`
	RunID     int64           `json:"run_id"`
	JobID     int64           `json:"job_id"`
	HostID    int64           `json:"host_id"`
	ServiceID int64           `json:"service_id"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	Summary   string          `json:"summary"`
	CreatedAt int64           `json:"created_at"`
	Address   string          `json:"address"`
	Port      int             `json:"port"`
	Detail    json.RawMessage `json:"detail,omitempty"`
}

type ChangeFilter struct {
	RunID     int64
	JobID     int64
	HostID    int64
	ServiceID int64
	Kinds     []string
	Severity  []string
	Since     int64
	Q         string
	Detail    bool
	Limit     int
	Offset    int
}

func (s *Store) ListChanges(ctx context.Context, f ChangeFilter) ([]ChangeRow, error) {
	var w []string
	var args []any
	if f.RunID > 0 {
		w, args = append(w, "c.run_id=?"), append(args, f.RunID)
	}
	if f.JobID > 0 {
		w, args = append(w, "c.job_id=?"), append(args, f.JobID)
	}
	if f.HostID > 0 {
		w, args = append(w, "c.host_id=?"), append(args, f.HostID)
	}
	if f.ServiceID > 0 {
		w, args = append(w, "c.service_id=?"), append(args, f.ServiceID)
	}
	if len(f.Kinds) > 0 {
		w = append(w, "c.kind IN ("+placeholders(len(f.Kinds))+")")
		for _, k := range f.Kinds {
			args = append(args, k)
		}
	}
	if len(f.Severity) > 0 {
		w = append(w, "c.severity IN ("+placeholders(len(f.Severity))+")")
		for _, k := range f.Severity {
			args = append(args, k)
		}
	}
	if f.Since > 0 {
		w, args = append(w, "c.created_at>=?"), append(args, f.Since)
	}
	if f.Q != "" {
		w, args = append(w, "LOWER(c.summary) LIKE ?"), append(args, "%"+strings.ToLower(f.Q)+"%")
	}
	if c := jobScope(ctx, "c.job_id"); c != "" {
		w = append(w, c)
	}
	where := ""
	if len(w) > 0 {
		where = " WHERE " + strings.Join(w, " AND ")
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT c.id, c.run_id, c.job_id, c.host_id, c.service_id, c.kind, c.severity, c.summary, c.created_at,
		COALESCE(h.address,''), COALESCE(sv.port,0), c.detail_enc FROM changes c LEFT JOIN hosts h ON h.id=c.host_id LEFT JOIN services sv ON sv.id=c.service_id`+
		where+` ORDER BY c.id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChangeRow{}
	for rows.Next() {
		var c ChangeRow
		var det string
		if err := rows.Scan(&c.ID, &c.RunID, &c.JobID, &c.HostID, &c.ServiceID, &c.Kind, &c.Severity, &c.Summary, &c.CreatedAt, &c.Address, &c.Port, &det); err != nil {
			return nil, err
		}
		if f.Detail && det != "" {
			if b, err := s.K.Open("changes.detail", det); err == nil {
				c.Detail = b
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- run comparison ---------------------------------------------------------------

type CompareItem struct {
	ServiceID int64                  `json:"service_id"`
	HostID    int64                  `json:"host_id"`
	Address   string                 `json:"address"`
	Hostname  string                 `json:"hostname"`
	Port      int                    `json:"port"`
	Proto     string                 `json:"proto"`
	Name      string                 `json:"name"`
	Title     string                 `json:"title,omitempty"`
	Tech      []string               `json:"tech,omitempty"`
	Fields    []analysis.FieldChange `json:"fields,omitempty"`
}

type CompareResult struct {
	A           *Run          `json:"a"`
	B           *Run          `json:"b"`
	New         []CompareItem `json:"new"`
	Gone        []CompareItem `json:"gone"`
	Unreachable []CompareItem `json:"unreachable"` // in A; host did not answer in B (not confirmed gone)
	Changed     []CompareItem `json:"changed"`
	Same        int           `json:"same"`
	HostsA      int           `json:"hosts_a"`
	HostsB      int           `json:"hosts_b"`
	HostsNew    []string      `json:"hosts_new"`
	HostsGone   []string      `json:"hosts_gone"`
}

type runSvc struct {
	CompareItem
	digest string
	snap   analysis.Snapshot
}

func (s *Store) runServices(ctx context.Context, runID int64) (map[int64]*runSvc, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT rs.service_id, rs.host_id, h.address, h.hostname, sv.port, sv.proto, rs.digest, rs.snap_enc
		FROM run_services rs JOIN services sv ON sv.id=rs.service_id JOIN hosts h ON h.id=rs.host_id WHERE rs.run_id=?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*runSvc{}
	for rows.Next() {
		var r runSvc
		var enc string
		rows.Scan(&r.ServiceID, &r.HostID, &r.Address, &r.Hostname, &r.Port, &r.Proto, &r.digest, &enc)
		s.K.OpenJSON("services.snap", enc, &r.snap)
		r.Name, r.Title, r.Tech = r.snap.Name, r.snap.Title, r.snap.Tech
		out[r.ServiceID] = &r
	}
	return out, rows.Err()
}

func (s *Store) runHostsUp(ctx context.Context, runID int64) (map[int64]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT rh.host_id, h.address FROM run_hosts rh JOIN hosts h ON h.id=rh.host_id WHERE rh.run_id=? AND rh.up=1`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var a string
		rows.Scan(&id, &a)
		out[id] = a
	}
	return out, rows.Err()
}

// CompareRuns diffs two arbitrary runs (A = older baseline, B = newer).
func (s *Store) CompareRuns(ctx context.Context, a, b int64) (*CompareResult, error) {
	ra, err := s.GetRun(ctx, a)
	if err != nil {
		return nil, err
	}
	rb, err := s.GetRun(ctx, b)
	if err != nil {
		return nil, err
	}
	sa, err := s.runServices(ctx, a)
	if err != nil {
		return nil, err
	}
	sb, err := s.runServices(ctx, b)
	if err != nil {
		return nil, err
	}
	ha, _ := s.runHostsUp(ctx, a)
	hb, _ := s.runHostsUp(ctx, b)
	res := &CompareResult{A: ra, B: rb, New: []CompareItem{}, Gone: []CompareItem{}, Unreachable: []CompareItem{}, Changed: []CompareItem{},
		HostsA: len(ha), HostsB: len(hb), HostsNew: []string{}, HostsGone: []string{}}
	for id, x := range sb {
		y, ok := sa[id]
		switch {
		case !ok:
			res.New = append(res.New, x.CompareItem)
		case y.digest != x.digest:
			it := x.CompareItem
			it.Fields = analysis.DiffSnapshots(y.snap, x.snap)
			res.Changed = append(res.Changed, it)
		default:
			res.Same++
		}
	}
	for id, y := range sa {
		if _, ok := sb[id]; ok {
			continue
		}
		if _, up := hb[y.HostID]; up {
			res.Gone = append(res.Gone, y.CompareItem)
		} else {
			res.Unreachable = append(res.Unreachable, y.CompareItem)
		}
	}
	for id, addr := range hb {
		if _, ok := ha[id]; !ok {
			res.HostsNew = append(res.HostsNew, addr)
		}
	}
	for id, addr := range ha {
		if _, ok := hb[id]; !ok {
			res.HostsGone = append(res.HostsGone, addr)
		}
	}
	srt := func(l []CompareItem) {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Address != l[j].Address {
				return l[i].Address < l[j].Address
			}
			return l[i].Port < l[j].Port
		})
	}
	srt(res.New)
	srt(res.Gone)
	srt(res.Changed)
	srt(res.Unreachable)
	sort.Strings(res.HostsNew)
	sort.Strings(res.HostsGone)
	return res, nil
}

// --- dashboard ------------------------------------------------------------------------

type KV struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

type TrendPoint struct {
	RunID     int64  `json:"run_id"`
	JobName   string `json:"job_name"`
	At        int64  `json:"at"`
	HostsUp   int    `json:"hosts_up"`
	OpenPorts int    `json:"open_ports"`
	New       int    `json:"new"`
	Gone      int    `json:"gone"`
	Changed   int    `json:"changed"`
}

type Dashboard struct {
	Totals struct {
		Hosts         int `json:"hosts"`
		Active        int `json:"active"`
		Unstable      int `json:"unstable"`
		Suspect       int `json:"suspect"`
		Inactive      int `json:"inactive"`
		Services      int `json:"services"`
		Web           int `json:"web"`
		Critical      int `json:"critical"`
		High          int `json:"high"`
		Medium        int `json:"medium"`
		Changes24h    int `json:"changes_24h"`
		NewServices7d int `json:"new_services_7d"`
		Staging       int `json:"staging"`
		AdminPanels   int `json:"admin_panels"`
		CertProblems  int `json:"cert_problems"`
		Manual        int `json:"manual"`
		VulnServices  int `json:"vuln_services"`
		CriticalCVE   int `json:"critical_cve"`
		Jobs          int `json:"jobs"`
		ActiveRuns    int `json:"active_runs"`
	} `json:"totals"`
	TopFindings   []*Service   `json:"top_findings"`
	RecentChanges []ChangeRow  `json:"recent_changes"`
	Trend         []TrendPoint `json:"trend"`
	Categories    []KV         `json:"categories"`
	TopTech       []KV         `json:"top_tech"`
	HourlyUp      [24]float64  `json:"hourly_up"`
	Unstable      []*Host      `json:"unstable"`
	FaviconGroups []Group      `json:"favicon_groups"`
	IssuerGroups  []Group      `json:"issuer_groups"`
	ActiveRuns    []*Run       `json:"active_runs"`
}

func (s *Store) count(ctx context.Context, q string, args ...any) int {
	var n int
	s.DB.QueryRowContext(ctx, q, args...).Scan(&n)
	return n
}

func (s *Store) kv(ctx context.Context, q string, args ...any) []KV {
	out := []KV{}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k KV
		rows.Scan(&k.Key, &k.Value)
		out = append(out, k)
	}
	return out
}

func (s *Store) Dashboard(ctx context.Context) (*Dashboard, error) {
	d := &Dashboard{Trend: []TrendPoint{}} // [] not null when the (scoped) dataset has no runs yet
	t := &d.Totals
	hc := andCond(hostScope(ctx, "h"))                       // hosts h
	svc := ` FROM services s JOIN hosts h ON h.id=s.host_id` // services s scoped through their host
	cc := andCond(jobScope(ctx, "c.job_id"))                 // changes c
	rc := andCond(jobScope(ctx, "r.job_id"))                 // runs r
	for _, kv := range s.kv(ctx, `SELECT state, COUNT(*) FROM hosts h WHERE 1=1`+hc+` GROUP BY state`) {
		t.Hosts += kv.Value
		switch kv.Key {
		case analysis.StateActive:
			t.Active = kv.Value
		case analysis.StateUnstable:
			t.Unstable = kv.Value
		case analysis.StateSuspect:
			t.Suspect = kv.Value
		case analysis.StateInactive:
			t.Inactive = kv.Value
		}
	}
	t.Services = s.count(ctx, `SELECT COUNT(*)`+svc+` WHERE s.status='open'`+hc)
	t.Web = s.count(ctx, `SELECT COUNT(*)`+svc+` WHERE s.status='open' AND s.is_web=1`+hc)
	for _, kv := range s.kv(ctx, `SELECT `+effPrio+`, COUNT(*)`+serviceFrom+` WHERE s.status='open'`+hc+` GROUP BY 1`) {
		switch kv.Key {
		case "critical":
			t.Critical = kv.Value
		case "high":
			t.High = kv.Value
		case "medium":
			t.Medium = kv.Value
		}
	}
	now := s.now()
	t.Changes24h = s.count(ctx, `SELECT COUNT(*) FROM changes c WHERE c.created_at>=? AND c.severity!='info'`+cc, now-86400)
	t.NewServices7d = s.count(ctx, `SELECT COUNT(*) FROM changes c WHERE c.created_at>=? AND c.kind='service_new'`+cc, now-7*86400)
	t.Staging = s.count(ctx, `SELECT COUNT(DISTINCT s.id)`+svc+`, json_each(s.categories) c WHERE s.status='open' AND c.value='staging'`+hc)
	t.AdminPanels = s.count(ctx, `SELECT COUNT(DISTINCT s.id)`+svc+`, json_each(s.categories) c WHERE s.status='open' AND c.value='admin-panel'`+hc)
	t.CertProblems = s.count(ctx, `SELECT COUNT(*)`+svc+` WHERE s.status='open' AND s.cert_not_after>0 AND (s.cert_not_after<? OR s.cert_not_after<? OR s.cert_self_signed=1)`+hc, now, now+14*86400)
	t.Manual = s.count(ctx, `SELECT COUNT(*)`+svc+` WHERE s.origin='manual'`+hc)
	t.VulnServices = s.count(ctx, `SELECT COUNT(DISTINCT v.service_id) FROM service_vulns v JOIN services s ON s.id=v.service_id JOIN hosts h ON h.id=s.host_id WHERE s.status='open'`+hc)
	t.CriticalCVE = s.count(ctx, `SELECT COUNT(DISTINCT v.service_id) FROM service_vulns v JOIN services s ON s.id=v.service_id JOIN hosts h ON h.id=s.host_id WHERE s.status='open' AND v.cvss>=9`+hc)
	t.Jobs = s.count(ctx, `SELECT COUNT(*) FROM jobs`+addWhere("", jobScope(ctx, "jobs.id")))
	t.ActiveRuns = s.count(ctx, `SELECT COUNT(*) FROM runs r WHERE r.status IN ('running','paused','queued')`+rc)

	top, _, err := s.ListServices(ctx, ServiceFilter{Limit: 400})
	if err != nil {
		return nil, err
	}
	// Show distinct kinds of problems (max 2 per kind) so one widespread
	// issue does not hide everything else; the full list is one click away.
	d.TopFindings = []*Service{}
	perKind := map[string]int{}
	for _, sv := range top {
		if sv.Triage == "false_positive" || sv.Triage == "resolved" || sv.Curiosity == 0 {
			continue
		}
		key := sv.Title + "|" + sv.Product
		if len(sv.Tech) > 0 {
			key = sv.Tech[0].Name + "|" + sv.Title
		}
		if perKind[key] >= 2 {
			continue
		}
		perKind[key]++
		d.TopFindings = append(d.TopFindings, sv)
		if len(d.TopFindings) >= 14 {
			break
		}
	}
	d.RecentChanges, _ = s.ListChanges(ctx, ChangeFilter{Limit: 25, Severity: []string{"critical", "high", "medium", "low"}})
	rows, err := s.DB.QueryContext(ctx, `SELECT r.id, COALESCE(j.name,'import'), CASE WHEN r.finished_at>0 THEN r.finished_at ELSE r.created_at END, r.hosts_up, r.open_ports,
		r.changes_new, r.changes_gone, r.changes_changed FROM runs r LEFT JOIN jobs j ON j.id=r.job_id WHERE r.status='completed'`+rc+` ORDER BY r.id DESC LIMIT 24`)
	if err == nil {
		for rows.Next() {
			var p TrendPoint
			rows.Scan(&p.RunID, &p.JobName, &p.At, &p.HostsUp, &p.OpenPorts, &p.New, &p.Gone, &p.Changed)
			d.Trend = append([]TrendPoint{p}, d.Trend...)
		}
		rows.Close()
	}
	d.Categories = s.kv(ctx, `SELECT c.value, COUNT(DISTINCT s.id)`+svc+`, json_each(s.categories) c WHERE s.status='open'`+hc+` GROUP BY c.value ORDER BY 2 DESC`)
	d.TopTech = s.kv(ctx, `SELECT t.name, COUNT(*) FROM service_tech t JOIN services s ON s.id=t.service_id JOIN hosts h ON h.id=s.host_id WHERE s.status='open' AND t.category NOT IN ('info','auth')`+hc+`
		GROUP BY t.name ORDER BY 2 DESC LIMIT 15`)
	// hour-of-day availability across all known hosts
	var up, pr [24]float64
	hr, err := s.DB.QueryContext(ctx, `SELECT h.hour_up, h.hour_probe FROM hosts h WHERE 1=1`+hc)
	if err == nil {
		for hr.Next() {
			var a, b string
			var au, ap [24]int
			hr.Scan(&a, &b)
			json.Unmarshal([]byte(a), &au)
			json.Unmarshal([]byte(b), &ap)
			for i := 0; i < 24; i++ {
				up[i] += float64(au[i])
				pr[i] += float64(ap[i])
			}
		}
		hr.Close()
	}
	for i := 0; i < 24; i++ {
		if pr[i] > 0 {
			d.HourlyUp[i] = up[i] / pr[i]
		} else {
			d.HourlyUp[i] = -1
		}
	}
	d.Unstable, _, _ = s.ListHosts(ctx, HostFilter{State: analysis.StateUnstable, Limit: 8})
	d.FaviconGroups, _ = s.Groups(ctx, "favicon", 6)
	d.IssuerGroups, _ = s.Groups(ctx, "cert_issuer", 6)
	runs, _ := s.ListRuns(ctx, 0, 20)
	d.ActiveRuns = []*Run{}
	for _, r := range runs {
		if r.Status == RunRunning || r.Status == RunPaused || r.Status == RunQueued {
			d.ActiveRuns = append(d.ActiveRuns, r)
		}
	}
	_ = time.Now
	return d, nil
}
