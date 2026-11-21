package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"asi/internal/analysis"
	"asi/internal/vulns"
)

// GetCVE / PutCVE implement vulns.Cache.
func (s *Store) GetCVE(ctx context.Context, cpe string, maxAge time.Duration) ([]vulns.Vuln, bool) {
	var at int64
	var data string
	if err := s.DB.QueryRowContext(ctx, `SELECT fetched_at, data FROM cve_cache WHERE cpe=?`, cpe).Scan(&at, &data); err != nil {
		return nil, false
	}
	if time.Since(time.Unix(at, 0)) > maxAge {
		return nil, false
	}
	var v []vulns.Vuln
	if json.Unmarshal([]byte(data), &v) != nil {
		return nil, false
	}
	return v, true
}

func (s *Store) PutCVE(ctx context.Context, cpe string, v []vulns.Vuln) {
	s.DB.ExecContext(ctx, `INSERT OR REPLACE INTO cve_cache(cpe, fetched_at, data) VALUES(?,?,?)`, cpe, time.Now().Unix(), jsonStr(v))
}

// VulnCandidate is a service component with a version worth checking.
type VulnCandidate struct {
	ServiceID int64
	HostID    int64
	Address   string
	Port      int
	Product   string
	Version   string
}

// VulnCandidates lists (product, version) pairs seen in a run: nmap product
// versions and versioned technology detections.
func (s *Store) VulnCandidates(ctx context.Context, runID int64) ([]VulnCandidate, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT sv.id, sv.host_id, h.address, sv.port, sv.product, sv.version FROM run_services rs
		  JOIN services sv ON sv.id=rs.service_id JOIN hosts h ON h.id=sv.host_id
		  WHERE rs.run_id=? AND sv.product!='' AND sv.version!=''
		UNION
		SELECT sv.id, sv.host_id, h.address, sv.port, t.name, t.version FROM run_services rs
		  JOIN services sv ON sv.id=rs.service_id JOIN hosts h ON h.id=sv.host_id
		  JOIN service_tech t ON t.service_id=sv.id
		  WHERE rs.run_id=? AND t.version!='' AND t.confidence>=60`, runID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnCandidate
	for rows.Next() {
		var c VulnCandidate
		rows.Scan(&c.ServiceID, &c.HostID, &c.Address, &c.Port, &c.Product, &c.Version)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveVulns stores CVEs for a service, raises its priority with an explained
// reason and records a change event.
func (s *Store) SaveVulns(ctx context.Context, runID, jobID int64, c VulnCandidate, list []vulns.Vuln) error {
	if len(list) == 0 {
		return nil
	}
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	maxCVSS, crit, high := 0.0, 0, 0
	for i, v := range list {
		if i >= 200 {
			break
		}
		if v.CVSS > maxCVSS {
			maxCVSS = v.CVSS
		}
		if v.CVSS >= 9 {
			crit++
		} else if v.CVSS >= 7 {
			high++
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO service_vulns(service_id, cve, cvss, severity, product, version, cpe, published, summary, found_at)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, c.ServiceID, v.CVE, v.CVSS, v.Severity, c.Product, c.Version, v.CPE, v.Published, v.Summary, now); err != nil {
			return err
		}
	}
	// add an explained reason to the curiosity score
	var curiosity int
	var reasonsE string
	tx.QueryRowContext(ctx, `SELECT curiosity, reasons FROM services WHERE id=?`, c.ServiceID).Scan(&curiosity, &reasonsE)
	var reasons []analysis.Reason
	s.K.OpenJSON("services.reasons", reasonsE, &reasons)
	code := "cve:" + strings.ToLower(c.Product)
	exists := false
	for _, r := range reasons {
		if r.Code == code {
			exists = true
		}
	}
	if !exists {
		pts := vulns.Points(maxCVSS)
		reasons = append(reasons, analysis.Reason{Code: code, Points: pts,
			Text: fmt.Sprintf("Znane podatności dla %s %s: %d (max CVSS %.1f) – do weryfikacji", c.Product, c.Version, len(list), maxCVSS)})
		curiosity += pts
		if curiosity > 100 {
			curiosity = 100
		}
		if _, err := tx.ExecContext(ctx, `UPDATE services SET curiosity=?, priority=?, reasons=? WHERE id=?`,
			curiosity, analysis.Priority(curiosity), s.K.MustSealJSON("services.reasons", reasons), c.ServiceID); err != nil {
			return err
		}
		sev := "low"
		switch {
		case maxCVSS >= 9:
			sev = "critical"
		case maxCVSS >= 7:
			sev = "high"
		case maxCVSS >= 4:
			sev = "medium"
		}
		ic := &ingestCtx{tx: tx, run: &Run{ID: runID, JobID: jobID}, at: now}
		top := list[0].CVE
		if err := s.addChange(ctx, ic, c.HostID, c.ServiceID, "vuln_found", sev,
			fmt.Sprintf("%s %s na %s:%d – %d znanych CVE (krytyczne: %d, wysokie: %d; najgroźniejsza %s, CVSS %.1f)",
				c.Product, c.Version, c.Address, c.Port, len(list), crit, high, top, maxCVSS), nil); err != nil {
			return err
		}
	}
	tx.ExecContext(ctx, `UPDATE hosts SET curiosity=MAX(curiosity, ?) WHERE id=?`, curiosity, c.HostID)
	return tx.Commit()
}

type VulnRow struct {
	ServiceID int64   `json:"service_id"`
	Address   string  `json:"address"`
	Hostname  string  `json:"hostname"`
	Port      int     `json:"port"`
	CVE       string  `json:"cve"`
	CVSS      float64 `json:"cvss"`
	Severity  string  `json:"severity"`
	Product   string  `json:"product"`
	Version   string  `json:"version"`
	Published string  `json:"published"`
	Summary   string  `json:"summary"`
}

// ListVulns lists CVEs (optionally only for services seen in a run / one service).
func (s *Store) ListVulns(ctx context.Context, runID, serviceID int64, limit int) ([]VulnRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT v.service_id, h.address, h.hostname, sv.port, v.cve, v.cvss, v.severity, v.product, v.version, v.published, v.summary
		FROM service_vulns v JOIN services sv ON sv.id=v.service_id JOIN hosts h ON h.id=sv.host_id WHERE sv.status='open'`
	var args []any
	if runID > 0 {
		q += ` AND v.service_id IN (SELECT service_id FROM run_services WHERE run_id=?)`
		args = append(args, runID)
	}
	if serviceID > 0 {
		q += ` AND v.service_id=?`
		args = append(args, serviceID)
	}
	q += ` ORDER BY v.cvss DESC, v.cve DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnRow{}
	for rows.Next() {
		var r VulnRow
		rows.Scan(&r.ServiceID, &r.Address, &r.Hostname, &r.Port, &r.CVE, &r.CVSS, &r.Severity, &r.Product, &r.Version, &r.Published, &r.Summary)
		out = append(out, r)
	}
	return out, rows.Err()
}
