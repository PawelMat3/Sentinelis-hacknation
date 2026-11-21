package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"asi/internal/dojo"
	"asi/internal/store"
)

// --- roles & users --------------------------------------------------------------------------

func (s *Server) permissions(w http.ResponseWriter, r *http.Request, u *store.User) error {
	writeJSON(w, 200, store.AllPermissions)
	return nil
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request, u *store.User) error {
	if !u.Can(store.PermAdminRoles) && !u.Can(store.PermAdminUsers) {
		writeJSON(w, 200, []*store.Role{u.Role})
		return nil
	}
	roles, err := s.st.ListRoles(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, roles)
	return nil
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in store.Role
	if err := decode(r, &in); err != nil {
		return err
	}
	id, err := s.st.CreateRole(r.Context(), in)
	if err != nil {
		return err
	}
	s.audit(r, u, "create", "role", id, in.Name+": "+strings.Join(in.Permissions, ","))
	role, _ := s.st.GetRole(r.Context(), id)
	writeJSON(w, 201, role)
	return nil
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var in store.Role
	if err := decode(r, &in); err != nil {
		return err
	}
	in.ID = id
	if err := s.st.UpdateRole(r.Context(), in); err != nil {
		return err
	}
	s.audit(r, u, "update", "role", id, in.Name+": "+strings.Join(in.Permissions, ","))
	role, _ := s.st.GetRole(r.Context(), id)
	writeJSON(w, 200, role)
	return nil
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := s.st.DeleteRole(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete", "role", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, u *store.User) error {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, users)
	return nil
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		RoleID      int64  `json:"role_id"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	id, err := s.st.CreateUser(r.Context(), in.Username, in.DisplayName, in.Password, in.RoleID)
	if err != nil {
		return err
	}
	s.audit(r, u, "create", "user", id, in.Username)
	nu, _ := s.st.GetUser(r.Context(), id)
	writeJSON(w, 201, nu)
	return nil
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var p store.UserPatch
	if err := decode(r, &p); err != nil {
		return err
	}
	if id == u.ID && ((p.Disabled != nil && *p.Disabled) || (p.RoleID != nil && *p.RoleID != u.RoleID)) {
		return errf(400, "you cannot disable yourself or change your own role")
	}
	if err := s.st.UpdateUser(r.Context(), id, p); err != nil {
		return err
	}
	s.audit(r, u, "update", "user", id, "")
	nu, _ := s.st.GetUser(r.Context(), id)
	writeJSON(w, 200, nu)
	return nil
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, u *store.User) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if id == u.ID {
		return errf(400, "you cannot delete yourself")
	}
	if err := s.st.DeleteUser(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, u, "delete", "user", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, u *store.User) error {
	a, err := s.st.ListAudit(r.Context(), qint(r, "limit", 200), qint(r, "offset", 0))
	if err != nil {
		return err
	}
	writeJSON(w, 200, a)
	return nil
}

// --- DefectDojo ----------------------------------------------------------------------------

// dojoTitle builds a short finding title: the single most important kind of
// exposure (if any) and the main technology, e.g. "Tryb debug: Werkzeug 2.0.1".
func dojoTitle(sv *store.Service) string {
	label := map[string]string{"debug": "Tryb debug", "exposure": "Ekspozycja zasobu", "staging": "Środowisko testowe",
		"admin-panel": "Panel administracyjny", "database": "Baza danych dostępna sieciowo", "iot": "Urządzenie IoT"}
	kind := ""
	for _, c := range []string{"debug", "exposure", "staging", "admin-panel", "database", "iot"} { // most severe first
		if slices.Contains(sv.Categories, c) {
			kind = label[c]
			break
		}
	}
	main := ""
	for _, t := range sv.Tech { // skip detections that only restate the category (e.g. "Środowisko testowe / staging")
		if t.Category == "staging" || t.Category == "admin-panel" || t.Category == "auth" || t.Category == "info" {
			continue
		}
		main = strings.TrimSpace(t.Name + " " + t.Version)
		break
	}
	if main == "" {
		main = strings.TrimSpace(sv.Product + " " + sv.Version)
	}
	if main == "" {
		main = sv.Name
	}
	if sv.Title != "" && len(sv.Tech) == 0 {
		main += " (" + sv.Title + ")"
	}
	if kind == "" {
		return main
	}
	return kind + ": " + main
}

// DojoSettingKey is the settings key holding the (encrypted) DefectDojo config.
const DojoSettingKey = "defectdojo"

const dojoKey = DojoSettingKey

func (s *Server) dojoConfig(ctx context.Context) (dojo.Config, error) {
	var c dojo.Config
	err := s.st.GetSetting(ctx, dojoKey, &c)
	if err == store.ErrNotFound {
		return dojo.Config{TestTitle: "Sentinelis discovery", MinimumSeverity: "Info"}, nil
	}
	return c, err
}

func (s *Server) getDojo(w http.ResponseWriter, r *http.Request, u *store.User) error {
	c, err := s.dojoConfig(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, c.Masked())
	return nil
}

func (s *Server) putDojo(w http.ResponseWriter, r *http.Request, u *store.User) error {
	cur, _ := s.dojoConfig(r.Context())
	var in dojo.Config
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.APIKey == "" || strings.Contains(in.APIKey, "•") {
		in.APIKey = cur.APIKey // keep stored secret when the masked value is sent back
	}
	if err := in.Valid(); err != nil {
		return err
	}
	if err := s.st.SetSetting(r.Context(), dojoKey, in); err != nil {
		return err
	}
	s.audit(r, u, "update", "settings", 0, "defectdojo "+in.URL)
	writeJSON(w, 200, in.Masked())
	return nil
}

func (s *Server) testDojo(w http.ResponseWriter, r *http.Request, u *store.User) error {
	c, err := s.dojoConfig(r.Context())
	if err != nil {
		return err
	}
	if err := c.Valid(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := dojo.New(c).Ping(ctx)
	if err != nil {
		return errf(502, "%v", err)
	}
	writeJSON(w, 200, map[string]string{"status": "ok", "user": user})
	return nil
}

func (s *Server) buildFinding(ctx context.Context, sv *store.Service, informational bool) dojo.Finding {
	tech := []string{}
	for _, t := range sv.Tech {
		x := t.Name
		if t.Version != "" {
			x += " " + t.Version
		}
		tech = append(tech, fmt.Sprintf("%s (%d%%)", x, t.Confidence))
	}
	what := dojoTitle(sv)
	var d strings.Builder
	fmt.Fprintf(&d, "**Usługa:** %s:%d/%s (%s %s %s)\n\n", sv.Address, sv.Port, sv.Proto, sv.Name, sv.Product, sv.Version)
	if sv.Hostname != "" {
		fmt.Fprintf(&d, "**Host:** %s (stan: %s)\n\n", sv.Hostname, sv.HostState)
	}
	if sv.URL != "" {
		fmt.Fprintf(&d, "**URL:** %s — HTTP %d — tytuł: %q\n\n", sv.URL, sv.HTTPStatus, sv.Title)
	}
	if len(tech) > 0 {
		fmt.Fprintf(&d, "**Technologie (pewność):** %s\n\n", strings.Join(tech, ", "))
	}
	fmt.Fprintf(&d, "**Priorytet Sentinelis:** %s (ciekawość %d/100)\n\n", sv.Priority, sv.Curiosity)
	if len(sv.Reasons) > 0 {
		d.WriteString("**Uzasadnienie:**\n")
		for _, rs := range sv.Reasons {
			fmt.Fprintf(&d, "- %s (+%d)\n", rs.Text, rs.Points)
		}
		d.WriteString("\n")
	}
	fmt.Fprintf(&d, "Pierwsze wykrycie: %s, ostatnio: %s. Źródło: %s. Obserwacja pasywna – bez prób logowania ani eksploitacji.\n",
		time.Unix(sv.FirstSeen, 0).UTC().Format(time.RFC3339), time.Unix(sv.LastSeen, 0).UTC().Format(time.RFC3339), sv.Origin)

	f := dojo.Finding{Title: fmt.Sprintf("[Sentinelis] %s – %s:%d", what, sv.Address, sv.Port), Description: d.String(),
		Severity: dojo.Severity(sv.Priority, informational), Date: time.Now().Format("2006-01-02"), Active: true, DynamicFinding: true,
		UniqueIDFromTool: fmt.Sprintf("asi-service-%d", sv.ID), Component: sv.Product, ComponentVersion: sv.Version,
		Mitigation: "Zweryfikować, czy usługa powinna być dostępna z tej sieci; ograniczyć dostęp lub wyłączyć zbędne komponenty.",
		Tags:       append([]string{"asi", "priority-" + sv.Priority}, sv.Categories...)}
	if len(sv.Categories) > 0 {
		f.VulnIDFromTool = "ASI-" + strings.ToUpper(sv.Categories[0])
	}
	proto := sv.Proto
	if sv.IsWeb && sv.URL != "" {
		proto = strings.SplitN(sv.URL, ":", 2)[0]
	}
	host := sv.Address
	f.Endpoints = []dojo.Endpoint{{Host: host, Port: sv.Port, Protocol: proto}}
	if sv.Hostname != "" && sv.Hostname != host {
		f.Endpoints = append(f.Endpoints, dojo.Endpoint{Host: sv.Hostname, Port: sv.Port, Protocol: proto})
	}
	if sv.HTTP != nil {
		var e strings.Builder
		fmt.Fprintf(&e, "GET %s\nHTTP %d\n", sv.HTTP.FinalURL, sv.HTTP.StatusCode)
		keys := make([]string, 0, len(sv.HTTP.Headers))
		for k := range sv.HTTP.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&e, "%s: %s\n", k, strings.Join(sv.HTTP.Headers[k], ", "))
		}
		for _, c := range sv.HTTP.Cookies {
			fmt.Fprintf(&e, "Set-Cookie: %s (secure=%v httponly=%v samesite=%s)\n", c.Name, c.Secure, c.HttpOnly, c.SameSite)
		}
		for _, rd := range sv.HTTP.Redirects {
			fmt.Fprintf(&e, "redirect %d: %s -> %s\n", rd.Status, rd.From, rd.To)
		}
		f.Files = append(f.Files, dojo.Evidence("http-response.txt", e.String()))
	}
	if sv.TLS != nil {
		b, _ := json.MarshalIndent(sv.TLS, "", "  ")
		f.Files = append(f.Files, dojo.Evidence("tls-certificate.json", string(b)))
	}
	if len(sv.Tech) > 0 {
		var e strings.Builder
		for _, t := range sv.Tech {
			fmt.Fprintf(&e, "%s %s [%s] %d%%\n", t.Name, t.Version, t.Category, t.Confidence)
			for _, x := range t.Evidence {
				fmt.Fprintf(&e, "  - %s\n", x)
			}
		}
		f.Files = append(f.Files, dojo.Evidence("detection-evidence.txt", e.String()))
	}
	return f
}

func (s *Server) dojoExport(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		ServiceIDs    []int64 `json:"service_ids"`
		ChangeIDs     []int64 `json:"change_ids"`
		Informational *bool   `json:"informational"`
		DryRun        bool    `json:"dry_run"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	info := in.Informational == nil || *in.Informational
	if len(in.ServiceIDs)+len(in.ChangeIDs) == 0 || len(in.ServiceIDs)+len(in.ChangeIDs) > 2000 {
		return errf(400, "select 1..2000 observations")
	}
	rep := dojo.Report{}
	for _, id := range in.ServiceIDs {
		sv, err := s.st.GetService(r.Context(), id)
		if err != nil {
			continue
		}
		rep.Findings = append(rep.Findings, s.buildFinding(r.Context(), sv, info))
	}
	if len(in.ChangeIDs) > 0 {
		all, _ := s.st.ListChanges(r.Context(), store.ChangeFilter{Limit: 5000, Detail: true})
		want := map[int64]bool{}
		for _, id := range in.ChangeIDs {
			want[id] = true
		}
		for _, c := range all {
			if !want[c.ID] {
				continue
			}
			f := dojo.Finding{Title: "[Sentinelis] Zmiana: " + c.Summary, Severity: "Info", Date: time.Unix(c.CreatedAt, 0).Format("2006-01-02"), Active: true,
				DynamicFinding: true, UniqueIDFromTool: fmt.Sprintf("asi-change-%d", c.ID), Tags: []string{"asi", "change", c.Kind},
				Description: fmt.Sprintf("**Typ zmiany:** %s\n\n**Opis:** %s\n\n**Przebieg skanu:** #%d", c.Kind, c.Summary, c.RunID)}
			if !info {
				f.Severity = map[string]string{"critical": "High", "high": "Medium", "medium": "Low"}[c.Severity]
				if f.Severity == "" {
					f.Severity = "Info"
				}
			}
			if c.Address != "" {
				f.Endpoints = []dojo.Endpoint{{Host: c.Address, Port: c.Port}}
			}
			if len(c.Detail) > 0 {
				f.Files = []dojo.File{dojo.Evidence("change-detail.json", string(c.Detail))}
			}
			rep.Findings = append(rep.Findings, f)
		}
	}
	if len(rep.Findings) == 0 {
		return errf(404, "no observations found")
	}
	if in.DryRun {
		attachment(w, "asi-defectdojo-generic.json", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		s.audit(r, u, "dojo_download", "findings", 0, fmt.Sprintf("%d findings", len(rep.Findings)))
		return enc.Encode(rep)
	}
	cfg, err := s.dojoConfig(r.Context())
	if err != nil {
		return err
	}
	if err := cfg.Valid(); err != nil {
		return errf(400, "DefectDojo not configured: %v", err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	res, err := dojo.New(cfg).ImportFindings(ctx, rep, []string{"asi"})
	status, detail := "ok", ""
	testID := 0
	if err != nil {
		status, detail = "error", err.Error()
	} else {
		testID, detail = res.TestID, res.Raw
	}
	s.st.DB.ExecContext(r.Context(), `INSERT INTO dojo_exports(ts, username, items, test_id, status, detail_enc) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), u.Username, len(rep.Findings), testID, status, s.st.K.SealString("dojo_exports.detail", detail))
	s.audit(r, u, "dojo_export", "findings", int64(testID), fmt.Sprintf("%d findings: %s", len(rep.Findings), status))
	if err != nil {
		return errf(502, "%v", err)
	}
	writeJSON(w, 200, map[string]any{"exported": len(rep.Findings), "test_id": res.TestID, "engagement_id": res.EngagementID, "product_id": res.ProductID})
	return nil
}

func (s *Server) dojoHistory(w http.ResponseWriter, r *http.Request, u *store.User) error {
	rows, err := s.st.DB.QueryContext(r.Context(), `SELECT id, ts, username, items, test_id, status FROM dojo_exports ORDER BY id DESC LIMIT 50`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		ID       int64  `json:"id"`
		TS       int64  `json:"ts"`
		Username string `json:"username"`
		Items    int    `json:"items"`
		TestID   int    `json:"test_id"`
		Status   string `json:"status"`
	}
	out := []row{}
	for rows.Next() {
		var x row
		rows.Scan(&x.ID, &x.TS, &x.Username, &x.Items, &x.TestID, &x.Status)
		out = append(out, x)
	}
	writeJSON(w, 200, out)
	return nil
}
