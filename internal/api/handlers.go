package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"asi/internal/fingerprint"
	"asi/internal/iox"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
)

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, u *store.User) error {
	d, err := s.st.Dashboard(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, d)
	return nil
}

// --- hosts / services ------------------------------------------------------------------

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request, u *store.User) error {
	q := r.URL.Query()
	items, total, err := s.st.ListHosts(r.Context(), store.HostFilter{Q: q.Get("q"), State: q.Get("state"), Tag: q.Get("tag"), JobID: qint64(r, "job"),
		Sort: q.Get("sort"), Limit: qint(r, "limit", 100), Offset: qint(r, "offset", 0)})
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
	return nil
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, h)
	return nil
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		store.ManualHost
		AddToJob int64 `json:"add_to_job"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.AddToJob > 0 && !u.Can(store.PermJobsCreate) {
		return errf(403, "adding to a scan job requires %s", store.PermJobsCreate)
	}
	hid, sids, err := s.st.CreateManual(r.Context(), in.ManualHost, s.m.Enricher(), u.Username)
	if err != nil {
		return err
	}
	if in.AddToJob > 0 {
		if _, err := s.st.AddTargets(r.Context(), in.AddToJob, []store.TargetInput{{Value: in.Address, Tags: in.Tags, Note: "dodano ręcznie z formularza hosta"}}, "manual", s.cfg.MaxTargets); err != nil {
			return err
		}
	}
	s.audit(r, u, "create", "host", hid, fmt.Sprintf("%s, %d services", in.Address, len(sids)))
	writeJSON(w, 201, map[string]any{"host_id": hid, "service_ids": sids})
	return nil
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		HostID  int64  `json:"host_id"`
		Address string `json:"address"`
		store.ManualService
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	addr := in.Address
	hostname := ""
	if in.HostID > 0 {
		h, err := s.st.GetHost(r.Context(), in.HostID)
		if err != nil {
			return err
		}
		addr, hostname = h.Address, h.Hostname
	}
	hid, sids, err := s.st.CreateManual(r.Context(), store.ManualHost{Address: addr, Hostname: hostname, Services: []store.ManualService{in.ManualService}}, s.m.Enricher(), u.Username)
	if err != nil {
		return err
	}
	s.audit(r, u, "create", "service", sids[0], fmt.Sprintf("%s:%d", addr, in.Port))
	writeJSON(w, 201, map[string]any{"host_id": hid, "service_id": sids[0]})
	return nil
}

func (s *Server) patchHost(w http.ResponseWriter, r *http.Request, u *store.User) error {
	return s.patchEntity(w, r, u, "host")
}

func (s *Server) patchService(w http.ResponseWriter, r *http.Request, u *store.User) error {
	return s.patchEntity(w, r, u, "service")
}

func (s *Server) patchEntity(w http.ResponseWriter, r *http.Request, u *store.User, typ string) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var p store.AnnotationPatch
	if err := decode(r, &p); err != nil {
		return err
	}
	a, err := s.st.UpdateAnnotation(r.Context(), typ, id, p, u.Username)
	if err != nil {
		return err
	}
	var fields []string
	if p.Tags != nil {
		fields = append(fields, "tags")
	}
	if p.Note != nil {
		fields = append(fields, "note")
	}
	if p.Triage != nil {
		fields = append(fields, "triage="+*p.Triage)
	}
	if p.PriorityOverride != nil {
		fields = append(fields, "priority="+*p.PriorityOverride)
	}
	for k := range p.Overrides {
		fields = append(fields, "override:"+k)
	}
	s.audit(r, u, "update", typ, id, strings.Join(fields, ", "))
	writeJSON(w, 200, a)
	return nil
}

func (s *Server) bulkServices(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		IDs     []int64  `json:"ids"`
		AddTags []string `json:"add_tags"`
		Triage  *string  `json:"triage"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if len(in.IDs) > 5000 {
		return errf(400, "too many ids")
	}
	n := 0
	for _, id := range in.IDs {
		p := store.AnnotationPatch{Triage: in.Triage}
		if len(in.AddTags) > 0 {
			a, err := s.st.GetAnnotation(r.Context(), "service", id)
			if err != nil {
				continue
			}
			t := append(a.Tags, in.AddTags...)
			p.Tags = &t
		}
		if _, err := s.st.UpdateAnnotation(r.Context(), "service", id, p, u.Username); err == nil {
			n++
		}
	}
	s.audit(r, u, "bulk_update", "service", 0, fmt.Sprintf("%d services", n))
	writeJSON(w, 200, map[string]int{"updated": n})
	return nil
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := s.st.DeleteHost(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete", "host", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := s.st.DeleteService(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete", "service", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func serviceFilter(r *http.Request) store.ServiceFilter {
	q := r.URL.Query()
	return store.ServiceFilter{Q: q.Get("q"), Status: q.Get("status"), Priority: q.Get("priority"), Category: q.Get("category"), Tech: q.Get("tech"),
		Tag: q.Get("tag"), Triage: q.Get("triage"), Origin: q.Get("origin"), HostID: qint64(r, "host"), Favicon: q.Get("favicon"),
		CertIssuer: q.Get("cert_issuer"), Title: q.Get("title"), Product: q.Get("product"), Server: q.Get("server"), Web: q.Get("web") == "1",
		Since: qint64(r, "since"), RunID: qint64(r, "run"), Sort: q.Get("sort"), Limit: qint(r, "limit", 100), Offset: qint(r, "offset", 0)}
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request, u *store.User) error {
	items, total, err := s.st.ListServices(r.Context(), serviceFilter(r))
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
	return nil
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	sv, err := s.st.GetService(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, sv)
	return nil
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request, u *store.User) error {
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "tech"
	}
	g, err := s.st.Groups(r.Context(), by, qint(r, "limit", 50))
	if err != nil {
		return err
	}
	writeJSON(w, 200, g)
	return nil
}

func changeFilter(r *http.Request) store.ChangeFilter {
	q := r.URL.Query()
	f := store.ChangeFilter{RunID: qint64(r, "run"), JobID: qint64(r, "job"), HostID: qint64(r, "host"), Since: qint64(r, "since"), Q: q.Get("q"),
		Detail: q.Get("detail") == "1", Limit: qint(r, "limit", 200), Offset: qint(r, "offset", 0)}
	if k := q.Get("kind"); k != "" {
		f.Kinds = strings.Split(k, ",")
	}
	if sv := q.Get("severity"); sv != "" {
		f.Severity = strings.Split(sv, ",")
	}
	return f
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request, u *store.User) error {
	c, err := s.st.ListChanges(r.Context(), changeFilter(r))
	if err != nil {
		return err
	}
	writeJSON(w, 200, c)
	return nil
}

func (s *Server) compare(w http.ResponseWriter, r *http.Request, u *store.User) error {
	a, b := qint64(r, "a"), qint64(r, "b")
	if a == 0 || b == 0 {
		return errf(400, "parameters a and b (run ids) required")
	}
	res, err := s.st.CompareRuns(r.Context(), a, b)
	if err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

// --- jobs / targets / runs ---------------------------------------------------------------

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request, u *store.User) error {
	jobs, err := s.st.ListJobs(r.Context())
	if err != nil {
		return err
	}
	type jobOut struct {
		*store.Job
		Active *store.Run `json:"active_run,omitempty"`
	}
	out := []jobOut{}
	for _, j := range jobs {
		jo := jobOut{Job: j}
		if ar, err := s.st.ActiveRun(r.Context(), j.ID); err == nil {
			jo.Active = ar
		}
		out = append(out, jo)
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	j, err := s.st.GetJob(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, j)
	return nil
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var j store.Job
	if err := decode(r, &j); err != nil {
		return err
	}
	j.Defaults()
	if err := j.Validate(s.cfg.MaxRate); err != nil {
		return err
	}
	if wnd, err := j.Window(); err == nil {
		j.NextRunAt = wnd.NextOpen(s.m.Clock().Now()).Unix()
	}
	id, err := s.st.CreateJob(r.Context(), &j)
	if err != nil {
		return err
	}
	s.audit(r, u, "create", "job", id, j.Name)
	out, _ := s.st.GetJob(r.Context(), id)
	writeJSON(w, 201, out)
	return nil
}

func (s *Server) updateJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	cur, err := s.st.GetJob(r.Context(), id)
	if err != nil {
		return err
	}
	j := *cur
	if err := decode(r, &j); err != nil {
		return err
	}
	j.ID = id
	j.Defaults()
	if err := j.Validate(s.cfg.MaxRate); err != nil {
		return err
	}
	if err := s.st.UpdateJob(r.Context(), &j); err != nil {
		return err
	}
	s.audit(r, u, "update", "job", id, j.Name)
	out, _ := s.st.GetJob(r.Context(), id)
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) deleteJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if ar, err := s.st.ActiveRun(r.Context(), id); err == nil {
		s.m.Cancel(r.Context(), ar.ID)
	}
	if err := s.st.DeleteJob(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete", "job", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	t, err := s.st.ListTargets(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, t)
	return nil
}

// readUpload returns (filename, data) from multipart "file" or the raw body.
func readUpload(r *http.Request, limit int64) (string, []byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(limit); err != nil {
			return "", nil, errf(400, "upload: %v", err)
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			if t := r.FormValue("text"); t != "" {
				return "input.txt", []byte(t), nil
			}
			return "", nil, errf(400, "missing file")
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		return h.Filename, b, err
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return "", nil, errf(413, "body too large")
	}
	name := "body"
	switch {
	case strings.Contains(r.Header.Get("Content-Type"), "json"):
		name = "body.json"
	case strings.Contains(r.Header.Get("Content-Type"), "csv"):
		name = "body.csv"
	case strings.Contains(r.Header.Get("Content-Type"), "xml"):
		name = "body.xml"
	}
	return name, b, nil
}

func (s *Server) addTargets(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if _, err := s.st.GetJob(r.Context(), id); err != nil {
		return err
	}
	name, data, err := readUpload(r, 32<<20)
	if err != nil {
		return err
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = iox.Detect(name, data)
	}
	if format != "csv" && format != "json" && format != "text" {
		return errf(400, "targets format must be csv, json or text")
	}
	in, err := iox.ParseTargets(format, data)
	if err != nil {
		return err
	}
	if len(in) > 0 && !u.Can(store.PermDataImport) && len(in) > 50 {
		return errf(403, "bulk import (>50 entries) requires %s", store.PermDataImport)
	}
	res, err := s.st.AddTargets(r.Context(), id, in, map[bool]string{true: "import", false: "manual"}[format != "text" || len(in) > 1], s.cfg.MaxTargets)
	if err != nil {
		return err
	}
	s.audit(r, u, "add_targets", "job", id, fmt.Sprintf("%d entries (%s), %d errors", res.Added, format, len(res.Errors)))
	writeJSON(w, 200, res)
	return nil
}

func (s *Server) patchTarget(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	tid, err := pathID(r, "tid")
	if err != nil {
		return err
	}
	var in struct {
		Tags []string `json:"tags"`
		Note string   `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := s.st.UpdateTarget(r.Context(), id, tid, in.Tags, in.Note); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	tid, err := pathID(r, "tid")
	if err != nil {
		return err
	}
	if err := s.st.DeleteTarget(r.Context(), id, tid); err != nil {
		return err
	}
	s.audit(r, u, "delete_target", "job", id, fmt.Sprint(tid))
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) deleteAllTargets(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := s.st.DeleteAllTargets(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete_all_targets", "job", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func attachment(w http.ResponseWriter, name, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
}

func (s *Server) exportTargets(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	rows, err := s.st.ListTargets(r.Context(), id)
	if err != nil {
		return err
	}
	s.audit(r, u, "export", "targets", id, r.URL.Query().Get("format"))
	if r.URL.Query().Get("format") == "csv" {
		attachment(w, fmt.Sprintf("asi-targets-job%d.csv", id), "text/csv; charset=utf-8")
		return iox.TargetsCSV(w, rows)
	}
	attachment(w, fmt.Sprintf("asi-targets-job%d.json", id), "application/json")
	return json.NewEncoder(w).Encode(map[string]any{"targets": rows})
}

func (s *Server) previewJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	j, err := s.st.GetJob(r.Context(), id)
	if err != nil {
		return err
	}
	tg, _ := s.st.TargetValues(r.Context(), id)
	spec := store.SpecFromJob(j, tg)
	out := map[string]any{"targets": len(tg)}
	sp, err := targets.Build(spec.Targets, spec.Exclusions, s.cfg.MaxTargets)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return nil
	}
	out["addresses"] = sp.Len()
	out["summary"] = sp.Summary()
	extra, _ := scanner.ParseExtra(j.NmapExtra)
	nm := &scanner.Nmap{Path: "nmap"}
	rate := max(1, j.RatePPS/max(1, j.Concurrency))
	out["nmap_command"] = "nmap " + strings.Join(nm.Args(scanner.Options{Ports: j.Ports, RatePPS: rate, Timing: j.Timing, ServiceDetection: j.ServiceDetection,
		Extra: extra, HostTimeout: 5 * time.Minute}), " ") + "  < chunk-targets"
	sph := s.st.LastSecPerHost(r.Context(), id)
	measured := sph > 0
	if !measured {
		ports, _ := scanner.ExpandPorts(j.Ports)
		n := float64(len(ports) + 10)
		if strings.HasPrefix(j.Ports, "top:") {
			fmt.Sscanf(j.Ports, "top:%f", &n)
			n += 10
		}
		sph = n / float64(rate)
	}
	est := sph * float64(sp.Len()) / float64(max(1, j.Concurrency))
	out["estimate_sec"] = int64(est)
	out["estimate_measured"] = measured
	out["chunk_size"] = int(math.Max(8, math.Min(4096, float64(max(10, j.ChunkTargetSec))/math.Max(sph, 0.0005))))
	if wnd, err := j.Window(); err == nil {
		out["window"] = wnd.String()
		out["window_open"] = wnd.IsOpen(s.m.Clock().Now())
		out["next_open"] = wnd.NextOpen(s.m.Clock().Now()).Unix()
		out["windows_needed"] = int(math.Ceil(est / wnd.Length().Seconds()))
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var in struct {
		Force bool `json:"force"`
	}
	if r.ContentLength > 0 {
		decode(r, &in)
	}
	run, err := s.m.StartRun(r.Context(), id, "manual", in.Force, u.Username)
	if err != nil {
		return err
	}
	s.audit(r, u, "run", "job", id, fmt.Sprintf("run #%d force=%v", run.ID, in.Force))
	writeJSON(w, 201, run)
	return nil
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, u *store.User) error {
	runs, err := s.st.ListRuns(r.Context(), qint64(r, "job"), qint(r, "limit", 50))
	if err != nil {
		return err
	}
	writeJSON(w, 200, runs)
	return nil
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		return err
	}
	chunks, _ := s.st.ListChunks(r.Context(), id, 2000)
	writeJSON(w, 200, map[string]any{"run": run, "chunks": chunks, "chunk_stats": s.st.ChunkStats(r.Context(), id), "spec": run.Spec})
	return nil
}

func (s *Server) runAction(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	act := r.PathValue("action")
	switch act {
	case "pause":
		err = s.m.Pause(r.Context(), id)
	case "resume":
		err = s.m.Resume(r.Context(), id, false)
	case "force-resume":
		err = s.m.Resume(r.Context(), id, true)
	case "cancel":
		err = s.m.Cancel(r.Context(), id)
	default:
		return errf(404, "unknown action")
	}
	if err != nil {
		return err
	}
	s.audit(r, u, "run_"+act, "run", id, "")
	time.Sleep(150 * time.Millisecond)
	run, _ := s.st.GetRun(r.Context(), id)
	writeJSON(w, 200, run)
	return nil
}

func (s *Server) stopAll(w http.ResponseWriter, r *http.Request, u *store.User) error {
	n := s.m.StopAll()
	s.audit(r, u, "stop_all", "scans", 0, fmt.Sprintf("%d runs paused", n))
	writeJSON(w, 200, map[string]int{"paused": n})
	return nil
}

// --- import / export ------------------------------------------------------------------------

func (s *Server) exportResults(w http.ResponseWriter, r *http.Request, u *store.User) error {
	f := serviceFilter(r)
	f.Limit, f.Offset = 1000, 0
	if f.Status == "" {
		f.Status = "all"
	}
	f.Sort = "address"
	format := r.URL.Query().Get("format")
	withHTTP := r.URL.Query().Get("detail") == "1"
	stamp := time.Now().Format("20060102-1504")
	s.audit(r, u, "export", "results", 0, format)
	if format == "csv" {
		attachment(w, "asi-results-"+stamp+".csv", "text/csv; charset=utf-8")
		w.Write([]byte("\xEF\xBB\xBF")) // UTF-8 BOM for spreadsheet apps
		cw := csv.NewWriter(w)
		cw.Write(iox.CSVHeader)
		for {
			items, _, err := s.st.ListServices(r.Context(), f)
			if err != nil {
				return err
			}
			for _, sv := range items {
				cw.Write(iox.ServiceCSVRow(sv))
			}
			if len(items) < f.Limit {
				break
			}
			f.Offset += f.Limit
		}
		cw.Flush()
		return nil
	}
	hosts, _, err := s.st.ListHosts(r.Context(), store.HostFilter{Limit: 5000, Q: f.Q, Tag: r.URL.Query().Get("host_tag")})
	if err != nil {
		return err
	}
	doc := iox.ExportDoc{Format: iox.ResultsFormat, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Hosts: []iox.ExportHost{}}
	for _, h := range hosts {
		hd, err := s.st.GetHost(r.Context(), h.ID)
		if err != nil {
			continue
		}
		eh := iox.ExportHost{Address: hd.Address, Hostname: hd.Hostname, State: hd.State, OS: hd.OS, Pattern: hd.Pattern,
			FirstSeen: time.Unix(hd.FirstSeen, 0).UTC().Format(time.RFC3339), LastSeen: time.Unix(hd.LastSeen, 0).UTC().Format(time.RFC3339),
			Tags: hd.Tags, Triage: hd.Triage, Services: []iox.ExportService{}}
		if hd.Annotation != nil {
			eh.Note = hd.Annotation.Note
		}
		for _, sv := range hd.Services {
			if f.Status == "open" && sv.Status != "open" {
				continue
			}
			note := ""
			full := sv
			if withHTTP || sv.HasNote {
				if d, err := s.st.GetService(r.Context(), sv.ID); err == nil {
					full = d
					if d.Annotation != nil {
						note = d.Annotation.Note
					}
				}
			}
			eh.Services = append(eh.Services, iox.ToExportService(full, note, withHTTP))
		}
		doc.Hosts = append(doc.Hosts, eh)
	}
	attachment(w, "asi-results-"+stamp+".json", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func (s *Server) exportChanges(w http.ResponseWriter, r *http.Request, u *store.User) error {
	f := changeFilter(r)
	f.Limit = 5000
	rows, err := s.st.ListChanges(r.Context(), f)
	if err != nil {
		return err
	}
	s.audit(r, u, "export", "changes", 0, r.URL.Query().Get("format"))
	if r.URL.Query().Get("format") == "csv" {
		attachment(w, "asi-changes.csv", "text/csv; charset=utf-8")
		return iox.ChangesCSV(w, rows)
	}
	attachment(w, "asi-changes.json", "application/json")
	return json.NewEncoder(w).Encode(rows)
}

func (s *Server) importResults(w http.ResponseWriter, r *http.Request, u *store.User) error {
	name, data, err := readUpload(r, 64<<20)
	if err != nil {
		return err
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = iox.Detect(name, data)
	}
	hosts, err := iox.ParseResults(format, data)
	if err != nil {
		return err
	}
	run, err := s.m.Import(r.Context(), hosts, u.Username)
	if err != nil {
		return err
	}
	s.audit(r, u, "import", "results", run.ID, fmt.Sprintf("%s: %d hosts", format, len(hosts)))
	writeJSON(w, 200, map[string]any{"run": run, "hosts": len(hosts), "format": format})
	return nil
}

// --- signatures ---------------------------------------------------------------------------------

func (s *Server) listSignatures(w http.ResponseWriter, r *http.Request, u *store.User) error {
	sigs, err := s.st.ListSignatures(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"items": sigs, "matcher_types": fingerprint.MatcherTypes})
	return nil
}

func (s *Server) createSignature(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var sg fingerprint.Signature
	if err := decode(r, &sg); err != nil {
		return err
	}
	id, err := s.st.CreateSignature(r.Context(), &sg, u.Username)
	if err != nil {
		return err
	}
	s.m.ReloadSignatures(r.Context())
	s.audit(r, u, "create", "signature", id, sg.Name)
	out, _ := s.st.GetSignature(r.Context(), id)
	writeJSON(w, 201, out)
	return nil
}

func (s *Server) updateSignature(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var sg fingerprint.Signature
	if err := decode(r, &sg); err != nil {
		return err
	}
	sg.ID = id
	if err := s.st.UpdateSignature(r.Context(), &sg); err != nil {
		return err
	}
	s.m.ReloadSignatures(r.Context())
	s.audit(r, u, "update", "signature", id, sg.Name)
	out, _ := s.st.GetSignature(r.Context(), id)
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) deleteSignature(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := s.st.DeleteSignature(r.Context(), id); err != nil {
		return err
	}
	s.m.ReloadSignatures(r.Context())
	s.audit(r, u, "delete", "signature", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

// testSignature dry-runs a definition against stored evidence of services.
func (s *Server) testSignature(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		Signature  fingerprint.Signature `json:"signature"`
		ServiceIDs []int64               `json:"service_ids"`
		Sample     int                   `json:"sample"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	in.Signature.Enabled = true
	if err := in.Signature.Compile(); err != nil {
		return err
	}
	ids := in.ServiceIDs
	if len(ids) == 0 {
		n := in.Sample
		if n <= 0 || n > 2000 {
			n = 500
		}
		items, _, err := s.st.ListServices(r.Context(), store.ServiceFilter{Limit: n})
		if err != nil {
			return err
		}
		for _, it := range items {
			ids = append(ids, it.ID)
		}
	}
	type hit struct {
		ServiceID  int64    `json:"service_id"`
		Address    string   `json:"address"`
		Port       int      `json:"port"`
		Title      string   `json:"title"`
		Confidence int      `json:"confidence"`
		Version    string   `json:"version,omitempty"`
		Evidence   []string `json:"evidence"`
	}
	hits := []hit{}
	for _, id := range ids {
		sv, err := s.st.GetService(r.Context(), id)
		if err != nil {
			continue
		}
		if sv.HTTP != nil {
			sv.HTTP.TLS = sv.TLS
		}
		ev := &fingerprint.Evidence{Address: sv.Address, Hostname: sv.Hostname, Port: sv.Port, Service: sv.Name, Product: sv.Product, Version: sv.Version, Banner: sv.Banner, HTTP: sv.HTTP}
		if d := in.Signature.Match(ev); d != nil {
			hits = append(hits, hit{sv.ID, sv.Address, sv.Port, sv.Title, d.Confidence, d.Version, d.Evidence})
		}
	}
	writeJSON(w, 200, map[string]any{"tested": len(ids), "matches": hits,
		"note": "Test na zapisanych dowodach (treść stron w formie skróconej); pełna treść jest analizowana podczas skanu."})
	return nil
}

func (s *Server) exportSignatures(w http.ResponseWriter, r *http.Request, u *store.User) error {
	sigs, err := s.st.ListSignatures(r.Context())
	if err != nil {
		return err
	}
	custom := []*fingerprint.Signature{}
	for _, sg := range sigs {
		if !sg.Builtin || r.URL.Query().Get("all") == "1" {
			custom = append(custom, sg)
		}
	}
	attachment(w, "asi-signatures.json", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"signatures": custom})
}

func (s *Server) importSignatures(w http.ResponseWriter, r *http.Request, u *store.User) error {
	_, data, err := readUpload(r, 4<<20)
	if err != nil {
		return err
	}
	var doc struct {
		Signatures []*fingerprint.Signature `json:"signatures"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Signatures == nil {
		var list []*fingerprint.Signature
		if err2 := json.NewDecoder(bytes.NewReader(data)).Decode(&list); err2 != nil {
			return errf(400, "expected {\"signatures\":[...]} or an array")
		}
		doc.Signatures = list
	}
	added, errs := 0, []string{}
	for _, sg := range doc.Signatures {
		sg.Builtin = false
		if _, err := s.st.CreateSignature(r.Context(), sg, u.Username); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sg.Name, err))
			continue
		}
		added++
	}
	s.m.ReloadSignatures(r.Context())
	s.audit(r, u, "import", "signatures", 0, fmt.Sprintf("%d added", added))
	writeJSON(w, 200, map[string]any{"added": added, "errors": errs})
	return nil
}
