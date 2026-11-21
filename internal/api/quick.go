package api

import (
	"context"
	"net/http"
	"time"

	"asi/internal/orchestrator"
	"asi/internal/store"
)

// POST /api/quickscan - one target in, full pipeline out.
func (s *Server) quickScan(w http.ResponseWriter, r *http.Request, u *store.User) error {
	if !u.Can(store.PermJobsCreate) {
		return errf(403, "szybki skan wymaga uprawnień %s i %s", store.PermScansRun, store.PermJobsCreate)
	}
	var in orchestrator.QuickScanRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second) // crt.sh can be slow
	defer cancel()
	res, err := s.m.QuickScan(ctx, in, u.Username)
	if err != nil {
		return err
	}
	s.audit(r, u, "quick_scan", "job", res.Job.ID, in.Target+" (zgoda właściciela potwierdzona)")
	writeJSON(w, 201, res)
	return nil
}

// GET /api/quickscan - history of quick scans with their latest run.
func (s *Server) listQuick(w http.ResponseWriter, r *http.Request, u *store.User) error {
	jobs, err := s.st.ListJobs(r.Context())
	if err != nil {
		return err
	}
	type item struct {
		Job *store.Job `json:"job"`
		Run *store.Run `json:"run,omitempty"`
	}
	out := []item{}
	for i := len(jobs) - 1; i >= 0; i-- {
		j := jobs[i]
		if !j.Quick {
			continue
		}
		it := item{Job: j}
		if runs, _ := s.st.ListRuns(r.Context(), j.ID, 1); len(runs) > 0 {
			it.Run = runs[0]
		}
		out = append(out, it)
	}
	writeJSON(w, 200, map[string]any{"items": out, "vuln_lookup": s.m.VulnLookupEnabled()})
	return nil
}

// GET /api/vulns?run=&service=
func (s *Server) listVulns(w http.ResponseWriter, r *http.Request, u *store.User) error {
	v, err := s.st.ListVulns(r.Context(), qint64(r, "run"), qint64(r, "service"), qint(r, "limit", 500))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}
