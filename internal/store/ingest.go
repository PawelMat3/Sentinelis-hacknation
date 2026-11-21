package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"asi/internal/analysis"
	"asi/internal/fingerprint"
	"asi/internal/scanner"
)

// ServiceObs is one observed open port with enrichment.
type ServiceObs struct {
	scanner.PortResult
	HTTP       *fingerprint.HTTPInfo   `json:"http,omitempty"`
	Detections []fingerprint.Detection `json:"detections,omitempty"`
	Insights   []fingerprint.Insight   `json:"insights,omitempty"`
	// analyst-layer data carried by imports
	ImportTags []string `json:"-"`
	ImportNote string   `json:"-"`
}

// HostObs is one host as observed by a chunk (or imported).
type HostObs struct {
	Address  string
	Hostname string
	Target   string // scope entry that produced it (domain), if any
	OS       string
	Up       bool
	Services []ServiceObs
	// Analyst-layer data carried by imports (never produced by scanners).
	ImportTags []string
	ImportNote string
}

type IngestStats struct {
	HostsUp   int
	OpenPorts int
}

// Change kinds.
const (
	ChServiceNew     = "service_new"
	ChServiceGone    = "service_gone"
	ChServiceChanged = "service_changed"
	ChManual         = "manual"
)

type ingestCtx struct {
	tx       *sql.Tx
	run      *Run
	at       int64
	local    time.Time
	baseline bool
	user     string
}

func (s *Store) addChange(ctx context.Context, ic *ingestCtx, hostID, serviceID int64, kind, severity, summary string, detail any) error {
	det := ""
	if detail != nil {
		det = s.K.MustSealJSON("changes.detail", detail)
	}
	var runID, jobID int64
	if ic.run != nil {
		runID, jobID = ic.run.ID, ic.run.JobID
	}
	_, err := ic.tx.ExecContext(ctx, `INSERT INTO changes(run_id, job_id, host_id, service_id, kind, severity, summary, detail_enc, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		runID, jobID, hostID, serviceID, kind, severity, summary, det, ic.at)
	return err
}

type hostRow struct {
	ID       int64
	Address  string
	Hostname string
	Track    analysis.Track
}

func (s *Store) loadHostTx(ctx context.Context, tx *sql.Tx, where string, arg any) (*hostRow, error) {
	var h hostRow
	var hu, hp string
	err := tx.QueryRowContext(ctx, `SELECT id, address, hostname, state, misses, history, hour_up, hour_probe, probes, ups FROM hosts WHERE `+where+` LIMIT 1`, arg).
		Scan(&h.ID, &h.Address, &h.Hostname, &h.Track.State, &h.Track.Misses, &h.Track.History, &hu, &hp, &h.Track.Probes, &h.Track.Ups)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(hu), &h.Track.HourUp)
	json.Unmarshal([]byte(hp), &h.Track.HourProbe)
	return &h, nil
}

func (s *Store) saveTrack(ctx context.Context, tx *sql.Tx, h *hostRow, at int64, seen bool, runID int64) error {
	q := `UPDATE hosts SET state=?, misses=?, history=?, hour_up=?, hour_probe=?, probes=?, ups=?, pattern=?, last_probed=?, updated_at=?`
	args := []any{h.Track.State, h.Track.Misses, h.Track.History, jsonStr(h.Track.HourUp), jsonStr(h.Track.HourProbe), h.Track.Probes, h.Track.Ups,
		h.Track.Pattern(), at, at}
	if seen {
		q += `, last_seen=?, last_run_id=?`
		args = append(args, at, runID)
	}
	q += ` WHERE id=?`
	args = append(args, h.ID)
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

func hostEventText(ev, addr string, t *analysis.Track, p analysis.Policy) (string, string) {
	switch ev {
	case analysis.EvHostNew:
		return "Nowy host " + addr, "medium"
	case analysis.EvHostReturned:
		return "Host ponownie aktywny: " + addr, "medium"
	case analysis.EvHostSuspect:
		return fmt.Sprintf("Brak odpowiedzi %s (%d/%d) – oczekuje na potwierdzenie (re-probe wykonany)", addr, t.Misses, p.InactiveAfter), "info"
	case analysis.EvHostInactive:
		return fmt.Sprintf("Host nieaktywny: %s – brak odpowiedzi w %d kolejnych skanach", addr, t.Misses), "medium"
	case analysis.EvHostUnstable:
		return "Host niestabilny/okresowy: " + addr + " – " + t.Pattern(), "low"
	case analysis.EvHostStable:
		return "Host ustabilizował się: " + addr, "info"
	}
	return ev + " " + addr, "info"
}

// Snapshot builds the comparable service state.
func Snapshot(o ServiceObs) analysis.Snapshot {
	sn := analysis.Snapshot{Name: o.Name, Product: o.Product, Version: o.Version}
	if h := o.HTTP; h != nil && h.Error == "" {
		sn.Status = h.StatusCode
		sn.Title = h.Title
		sn.Server = h.Header("Server")
		sn.PoweredBy = h.Header("X-Powered-By")
		if u, err := url.Parse(h.FinalURL); err == nil {
			sn.FinalURL = u.Scheme + "://" + u.Path
			if u.RawQuery != "" {
				sn.FinalURL += "?" + u.RawQuery
			}
		}
		for _, c := range h.Cookies {
			sn.Cookies = append(sn.Cookies, c.Name)
		}
		sn.Favicon = h.FaviconHash
		sn.RespMS = h.ResponseMS
		if h.TLS != nil {
			sn.CertSHA256 = h.TLS.SHA256
			sn.CertIssuer = h.TLS.IssuerCN
			sn.CertExpiry = analysis.CertExpiry(h.TLS.NotAfter)
		}
	}
	for _, d := range o.Detections {
		t := d.Name
		if d.Version != "" {
			t += " " + d.Version
		}
		sn.Tech = append(sn.Tech, t)
	}
	return sn.Normalize()
}

func techLabel(ds []fingerprint.Detection) string {
	var n []string
	for i, d := range ds {
		if i >= 3 {
			break
		}
		t := d.Name
		if d.Version != "" {
			t += " " + d.Version
		}
		n = append(n, t)
	}
	if len(n) == 0 {
		return ""
	}
	return " (" + strings.Join(n, ", ") + ")"
}

// applyService upserts one observed service (scan or import) and records
// novelty/changes. Returns the service id and whether it was new.
func (s *Store) applyService(ctx context.Context, ic *ingestCtx, hostID int64, addr, hostState string, hostNew bool, o ServiceObs, origin string) (int64, bool, error) {
	if o.Proto == "" {
		o.Proto = "tcp"
	}
	sort.Slice(o.Detections, func(i, j int) bool { return o.Detections[i].Confidence > o.Detections[j].Confidence })
	snap := Snapshot(o)
	digest := snap.Digest()

	var (
		id                       int64
		status, oldDigest, snapE string
		oldOrigin                string
		lastRun                  int64
		exists                   = true
	)
	err := ic.tx.QueryRowContext(ctx, `SELECT id, status, digest, snap_enc, last_run_id, origin FROM services WHERE host_id=? AND port=? AND proto=?`,
		hostID, o.Port, o.Proto).Scan(&id, &status, &oldDigest, &snapE, &lastRun, &oldOrigin)
	if errors.Is(err, sql.ErrNoRows) {
		exists = false
	} else if err != nil {
		return 0, false, err
	}
	var runID int64
	if ic.run != nil {
		runID = ic.run.ID
	}
	sameRun := exists && runID != 0 && lastRun == runID
	isNew := !exists || status == "gone"
	var changed []analysis.FieldChange
	if exists && !isNew && !sameRun && oldDigest != "" {
		var old analysis.Snapshot
		s.K.OpenJSON("services.snap", snapE, &old)
		if oldDigest != digest {
			changed = analysis.DiffSnapshots(old, snap)
		}
		// response time is outside the digest: report only large shifts
		// (e.g. a proxy adding latency, an overloaded backend)
		if fc, ok := analysis.LatencyShift(old.RespMS, snap.RespMS); ok {
			changed = append(changed, fc)
		}
	}
	novel := isNew && !sameRun && (!ic.baseline || !hostNew)
	score, prio, reasons := analysis.Score(analysis.ScoreInput{Port: o.Port, Name: o.Name, Detections: o.Detections, Insights: o.Insights,
		HTTP: o.HTTP, IsNew: novel, Changed: changed, HostState: hostState})

	// observed-layer columns
	var isWeb int
	var urlS, title, server, httpE, tlsE, issuer, subject, fav string
	var httpStatus int
	var notAfter int64
	var selfSigned int
	if h := o.HTTP; h != nil && h.Error == "" {
		isWeb = 1
		urlS, title, server, httpStatus, fav = h.FinalURL, h.Title, h.Header("Server"), h.StatusCode, h.FaviconHash
		cp := *h
		cp.TLS = nil
		httpE = s.K.MustSealJSON("services.http", &cp)
		if h.TLS != nil {
			tlsE = s.K.MustSealJSON("services.tls", h.TLS)
			issuer, subject, notAfter, selfSigned = h.TLS.IssuerCN, h.TLS.SubjectCN, h.TLS.NotAfter.Unix(), b2i(h.TLS.SelfSigned)
		}
	}
	cats := map[string]bool{}
	var catList []string
	for _, d := range o.Detections {
		if !cats[d.Category] {
			cats[d.Category] = true
			catList = append(catList, d.Category)
		}
	}
	sort.Strings(catList)
	if catList == nil {
		catList = []string{}
	}
	reasonsE := s.K.MustSealJSON("services.reasons", reasons)
	bannerE := s.K.SealString("services.banner", o.Banner)
	snapEnc := s.K.MustSealJSON("services.snap", snap)
	if origin == "" {
		origin = "scan"
	}
	if exists {
		if oldOrigin == "manual" {
			origin = "manual" // keep provenance; scanner confirms it
		}
		q := `UPDATE services SET status='open', origin=?, name=?, product=?, version=?, tunnel=?, banner_enc=?, is_web=?, url=?, http_status=?, title=?, server=?,
			http_enc=?, tls_enc=?, snap_enc=?, cert_issuer=?, cert_subject=?, cert_not_after=?, cert_self_signed=?, favicon_hash=?, categories=?,
			curiosity=?, priority=?, reasons=?, digest=?, last_seen=?, gone_at=0, last_run_id=?, updated_at=?`
		args := []any{origin, o.Name, o.Product, o.Version, o.Tunnel, bannerE, isWeb, urlS, httpStatus, title, server, httpE, tlsE, snapEnc,
			issuer, subject, notAfter, selfSigned, fav, jsonStr(catList), score, prio, reasonsE, digest, ic.at, runID, ic.at}
		if isNew || len(changed) > 0 {
			q += `, last_changed=?`
			args = append(args, ic.at)
		}
		if isNew {
			q += `, first_seen=CASE WHEN first_seen=0 THEN ? ELSE first_seen END`
			args = append(args, ic.at)
		}
		q += ` WHERE id=?`
		args = append(args, id)
		if _, err := ic.tx.ExecContext(ctx, q, args...); err != nil {
			return 0, false, err
		}
	} else {
		res, err := ic.tx.ExecContext(ctx, `INSERT INTO services(host_id, port, proto, status, origin, name, product, version, tunnel, banner_enc, is_web, url,
			http_status, title, server, http_enc, tls_enc, snap_enc, cert_issuer, cert_subject, cert_not_after, cert_self_signed, favicon_hash, categories,
			curiosity, priority, reasons, digest, first_seen, last_seen, last_changed, last_run_id, updated_at)
			VALUES(?,?,?,'open',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			hostID, o.Port, o.Proto, origin, o.Name, o.Product, o.Version, o.Tunnel, bannerE, isWeb, urlS, httpStatus, title, server, httpE, tlsE, snapEnc,
			issuer, subject, notAfter, selfSigned, fav, jsonStr(catList), score, prio, reasonsE, digest, ic.at, ic.at, ic.at, runID, ic.at)
		if err != nil {
			return 0, false, err
		}
		id, _ = res.LastInsertId()
	}
	if _, err := ic.tx.ExecContext(ctx, `DELETE FROM service_tech WHERE service_id=?`, id); err != nil {
		return 0, false, err
	}
	for _, d := range o.Detections {
		if _, err := ic.tx.ExecContext(ctx, `INSERT OR REPLACE INTO service_tech(service_id, name, category, version, confidence, signature_id, evidence) VALUES(?,?,?,?,?,?,?)`,
			id, d.Name, d.Category, d.Version, d.Confidence, d.SignatureID, s.K.MustSealJSON("service_tech.evidence", d.Evidence)); err != nil {
			return 0, false, err
		}
	}
	if runID != 0 {
		if _, err := ic.tx.ExecContext(ctx, `INSERT OR REPLACE INTO run_services(run_id, service_id, host_id, digest, snap_enc) VALUES(?,?,?,?,?)`,
			runID, id, hostID, digest, snapEnc); err != nil {
			return 0, false, err
		}
	}
	label := fmt.Sprintf("%s:%d/%s %s", addr, o.Port, o.Proto, o.Name)
	switch {
	case origin == "manual" && runID == 0:
		// manual entry recorded by caller
	case novel:
		txt := "Nowa usługa " + label + techLabel(o.Detections)
		if exists {
			txt = "Usługa ponownie wykryta " + label + techLabel(o.Detections)
		}
		sev := prio
		if sev == "info" {
			sev = "low"
		}
		if err := s.addChange(ctx, ic, hostID, id, ChServiceNew, sev, txt, map[string]any{"snapshot": snap, "priority": prio, "score": score}); err != nil {
			return 0, false, err
		}
	case len(changed) > 0:
		var parts []string
		for _, c := range changed {
			parts = append(parts, fmt.Sprintf("%s: %s → %s", analysis.Label(c.Field), dash(c.Old), dash(c.New)))
		}
		txt := "Zmiana " + label + " – " + strings.Join(parts, "; ")
		if len(txt) > 400 {
			txt = txt[:400] + "…"
		}
		if err := s.addChange(ctx, ic, hostID, id, ChServiceChanged, analysis.ChangeSeverity(changed), txt, map[string]any{"fields": changed}); err != nil {
			return 0, false, err
		}
	}
	return id, novel, nil
}

func dash(s string) string {
	if s == "" {
		return "∅"
	}
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// Ingest stores the results of one chunk (or an import batch) atomically.
func (s *Store) Ingest(ctx context.Context, run *Run, obs []HostObs, at time.Time, policy analysis.Policy, loc *time.Location) (IngestStats, error) {
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	var st IngestStats
	if loc == nil {
		loc = time.Local
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	ic := &ingestCtx{tx: tx, run: run, at: at.Unix(), local: at.In(loc), baseline: run.Seq <= 1}
	for _, h := range obs {
		if !h.Up {
			// Only hosts we already know matter; unknown silent IPs are not stored.
			hr, err := s.loadHostTx(ctx, tx, `address=?`, h.Address)
			if errors.Is(err, sql.ErrNoRows) && h.Target != "" {
				hr, err = s.loadHostTx(ctx, tx, `hostname=?`, h.Target)
			}
			if err == nil {
				if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_hosts(run_id, host_id, up, pending, at) VALUES(?,?,0,1,?)`, run.ID, hr.ID, ic.at); err != nil {
					return st, err
				}
			}
			continue
		}
		st.HostsUp++
		hr, err := s.loadHostTx(ctx, tx, `address=?`, h.Address)
		hostNew := false
		if errors.Is(err, sql.ErrNoRows) {
			hostNew = true
			name := h.Target
			if name == "" {
				name = h.Hostname
			}
			var jid any
			if run.JobID > 0 {
				jid = run.JobID
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO hosts(address, hostname, state, origin, job_id, os_guess, first_seen, last_seen, last_run_id, updated_at)
				VALUES(?,?,'',?,?,?,?,?,?,?)`, h.Address, name, map[bool]string{true: "import", false: "scan"}[run.Trigger == "import"], jid, h.OS, ic.at, ic.at, run.ID, ic.at)
			if err != nil {
				return st, err
			}
			id, _ := res.LastInsertId()
			hr = &hostRow{ID: id, Address: h.Address, Hostname: name}
		} else if err != nil {
			return st, err
		}
		// Observe availability once per run (a host may be scanned by IP and by name).
		var already int
		tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM run_hosts WHERE run_id=? AND host_id=? AND up=1`, run.ID, hr.ID).Scan(&already)
		if already == 0 {
			ev := hr.Track.Observe(true, ic.local, policy)
			if ev == analysis.EvHostNew && ic.baseline {
				ev = "" // baseline run: everything is new, do not flood the change feed
			}
			if ev != "" {
				txt, sev := hostEventText(ev, h.Address, &hr.Track, policy)
				if ev == analysis.EvHostNew && len(h.Services) > 0 {
					var ps []string
					for _, sv := range h.Services {
						ps = append(ps, fmt.Sprint(sv.Port))
					}
					txt += fmt.Sprintf(" (%d usług: %s)", len(h.Services), strings.Join(ps, ", "))
				}
				if err := s.addChange(ctx, ic, hr.ID, 0, ev, sev, txt, map[string]any{"history": hr.Track.History, "pattern": hr.Track.Pattern()}); err != nil {
					return st, err
				}
			}
		}
		if err := s.saveTrack(ctx, tx, hr, ic.at, true, run.ID); err != nil {
			return st, err
		}
		if h.Target != "" && hr.Hostname != h.Target {
			tx.ExecContext(ctx, `UPDATE hosts SET hostname=? WHERE id=?`, h.Target, hr.ID)
		} else if hr.Hostname == "" && h.Hostname != "" {
			tx.ExecContext(ctx, `UPDATE hosts SET hostname=? WHERE id=?`, h.Hostname, hr.ID)
		}
		if h.OS != "" {
			tx.ExecContext(ctx, `UPDATE hosts SET os_guess=? WHERE id=?`, h.OS, hr.ID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_hosts(run_id, host_id, up, pending, at) VALUES(?,?,1,0,?)
			ON CONFLICT(run_id, host_id) DO UPDATE SET up=1, pending=0, at=excluded.at`, run.ID, hr.ID, ic.at); err != nil {
			return st, err
		}
		for _, sv := range h.Services {
			sid, _, err := s.applyService(ctx, ic, hr.ID, h.Address, hr.Track.State, hostNew, sv, "")
			if err != nil {
				return st, err
			}
			if len(sv.ImportTags) > 0 || sv.ImportNote != "" {
				if err := s.mergeAnnotation(ctx, tx, "service", sid, sv.ImportTags, sv.ImportNote, "import"); err != nil {
					return st, err
				}
			}
			st.OpenPorts++
		}
		if len(h.ImportTags) > 0 || h.ImportNote != "" {
			if err := s.mergeAnnotation(ctx, tx, "host", hr.ID, h.ImportTags, h.ImportNote, "import"); err != nil {
				return st, err
			}
		}
	}
	return st, tx.Commit()
}

// mergeAnnotation adds tags / appends a note in the analyst layer.
func (s *Store) mergeAnnotation(ctx context.Context, tx *sql.Tx, typ string, id int64, tags []string, note, user string) error {
	var oldTags, oldNote string
	err := tx.QueryRowContext(ctx, `SELECT tags, note_enc FROM annotations WHERE entity_type=? AND entity_id=?`, typ, id).Scan(&oldTags, &oldNote)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	all := NormalizeTags(append(parseTags(oldTags), tags...))
	n := s.K.OpenString("annotations.note", oldNote)
	if note != "" && !strings.Contains(n, note) {
		if n != "" {
			n += "\n"
		}
		n += note
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO annotations(entity_type, entity_id, tags, note_enc, updated_by, updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(entity_type, entity_id) DO UPDATE SET tags=excluded.tags, note_enc=excluded.note_enc, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
		typ, id, jsonStr(all), s.K.SealString("annotations.note", n), user, s.now())
	return err
}

// MissingHosts lists known hosts that did not answer yet in this run.
func (s *Store) MissingHosts(ctx context.Context, runID int64) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT h.address FROM run_hosts rh JOIN hosts h ON h.id=rh.host_id WHERE rh.run_id=? AND rh.pending=1 AND rh.up=0`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PortCoverage tells whether a port was part of the run's scan scope.
func PortCoverage(spec string) func(int) bool {
	if strings.HasPrefix(spec, "top:") {
		var n int
		fmt.Sscanf(spec, "top:%d", &n)
		if n >= 1000 {
			return func(p int) bool { return p < 49152 }
		}
	}
	ports, err := scanner.ExpandPorts(spec)
	if err != nil {
		return func(int) bool { return false }
	}
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	return func(p int) bool { return m[p] }
}

// FinalizeRun applies "no answer" outcomes (after re-probes) to the host state
// machine, marks vanished services and closes the run.
func (s *Store) FinalizeRun(ctx context.Context, run *Run, at time.Time, policy analysis.Policy, loc *time.Location) error {
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	if loc == nil {
		loc = time.Local
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ic := &ingestCtx{tx: tx, run: run, at: at.Unix(), local: at.In(loc), baseline: run.Seq <= 1}

	// 1. hosts that stayed silent (after re-probes)
	rows, err := tx.QueryContext(ctx, `SELECT host_id FROM run_hosts WHERE run_id=? AND pending=1 AND up=0`, run.ID)
	if err != nil {
		return err
	}
	var silent []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		silent = append(silent, id)
	}
	rows.Close()
	for _, id := range silent {
		hr, err := s.loadHostTx(ctx, tx, `id=?`, id)
		if err != nil {
			continue
		}
		ev := hr.Track.Observe(false, ic.local, policy)
		if err := s.saveTrack(ctx, tx, hr, ic.at, false, run.ID); err != nil {
			return err
		}
		if ev != "" {
			txt, sev := hostEventText(ev, hr.Address, &hr.Track, policy)
			if err := s.addChange(ctx, ic, hr.ID, 0, ev, sev, txt, map[string]any{"history": hr.Track.History, "pattern": hr.Track.Pattern()}); err != nil {
				return err
			}
		}
		if ev == analysis.EvHostInactive {
			if err := s.goneServices(ctx, ic, `host_id=? AND status='open'`, []any{hr.ID}, " (host nieaktywny)"); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE run_hosts SET pending=0 WHERE run_id=?`, run.ID); err != nil {
		return err
	}

	// 2. services of responsive hosts that were not seen although their port was scanned
	cover := PortCoverage(run.Spec.Ports)
	rows, err = tx.QueryContext(ctx, `SELECT s.id, s.port FROM services s JOIN run_hosts rh ON rh.host_id=s.host_id AND rh.run_id=? AND rh.up=1
		WHERE s.status='open' AND s.last_run_id!=? AND s.proto='tcp'`, run.ID, run.ID)
	if err != nil {
		return err
	}
	var goneIDs []any
	for rows.Next() {
		var id int64
		var port int
		rows.Scan(&id, &port)
		if run.Trigger == "import" || cover(port) {
			goneIDs = append(goneIDs, id)
		}
	}
	rows.Close()
	if run.Trigger == "import" {
		goneIDs = nil // partial imports must not delete knowledge
	}
	for _, id := range goneIDs {
		if err := s.goneServices(ctx, ic, `id=?`, []any{id}, ""); err != nil {
			return err
		}
	}

	// 3. host curiosity + exact run counters
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET curiosity=COALESCE((SELECT MAX(curiosity) FROM services s WHERE s.host_id=hosts.id AND s.status='open'),0)
		WHERE id IN (SELECT host_id FROM run_hosts WHERE run_id=?)`, run.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET
		hosts_up=(SELECT COUNT(*) FROM run_hosts WHERE run_id=runs.id AND up=1),
		open_ports=(SELECT COUNT(*) FROM run_services WHERE run_id=runs.id),
		changes_new=(SELECT COUNT(*) FROM changes WHERE run_id=runs.id AND kind IN ('service_new','host_new','host_returned')),
		changes_gone=(SELECT COUNT(*) FROM changes WHERE run_id=runs.id AND kind IN ('service_gone','host_inactive')),
		changes_changed=(SELECT COUNT(*) FROM changes WHERE run_id=runs.id AND kind='service_changed'),
		changes_hosts=(SELECT COUNT(*) FROM changes WHERE run_id=runs.id AND kind LIKE 'host_%'),
		status='completed', status_reason='', phase='done', done_targets=total_targets, finished_at=?
		WHERE id=?`, ic.at, run.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) goneServices(ctx context.Context, ic *ingestCtx, where string, args []any, suffix string) error {
	rows, err := ic.tx.QueryContext(ctx, `SELECT s.id, s.host_id, s.port, s.proto, s.name, s.priority, h.address FROM services s JOIN hosts h ON h.id=s.host_id WHERE s.`+where, args...)
	if err != nil {
		return err
	}
	type g struct {
		id, host        int64
		port            int
		proto, name, pr string
		addr            string
	}
	var list []g
	for rows.Next() {
		var x g
		rows.Scan(&x.id, &x.host, &x.port, &x.proto, &x.name, &x.pr, &x.addr)
		list = append(list, x)
	}
	rows.Close()
	for _, x := range list {
		if _, err := ic.tx.ExecContext(ctx, `UPDATE services SET status='gone', gone_at=?, last_changed=?, updated_at=? WHERE id=?`, ic.at, ic.at, ic.at, x.id); err != nil {
			return err
		}
		sev := "low"
		if x.pr == "critical" || x.pr == "high" {
			sev = "medium"
		}
		txt := fmt.Sprintf("Usługa zniknęła %s:%d/%s %s%s", x.addr, x.port, x.proto, x.name, suffix)
		if err := s.addChange(ctx, ic, x.host, x.id, ChServiceGone, sev, txt, nil); err != nil {
			return err
		}
	}
	return nil
}
