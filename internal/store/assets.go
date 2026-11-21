package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"asi/internal/analysis"
	"asi/internal/fingerprint"
	"asi/internal/scanner"
)

// --- DTOs (effective view = observed layer + analyst layer) ----------------

type Tech struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type Annotation struct {
	Tags             []string          `json:"tags"`
	Triage           string            `json:"triage"`
	Owner            string            `json:"owner"`
	Criticality      string            `json:"criticality"`
	PriorityOverride string            `json:"priority_override"`
	Note             string            `json:"note"`
	Overrides        map[string]string `json:"overrides"`
	UpdatedBy        string            `json:"updated_by"`
	UpdatedAt        int64             `json:"updated_at"`
}

type Service struct {
	ID           int64             `json:"id"`
	HostID       int64             `json:"host_id"`
	Address      string            `json:"address"`
	Hostname     string            `json:"hostname"`
	HostState    string            `json:"host_state"`
	Port         int               `json:"port"`
	Proto        string            `json:"proto"`
	Status       string            `json:"status"`
	Origin       string            `json:"origin"`
	Name         string            `json:"name"`
	Product      string            `json:"product"`
	Version      string            `json:"version"`
	Tunnel       string            `json:"tunnel,omitempty"`
	IsWeb        bool              `json:"is_web"`
	URL          string            `json:"url"`
	HTTPStatus   int               `json:"http_status"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	CertIssuer   string            `json:"cert_issuer"`
	CertSubject  string            `json:"cert_subject"`
	CertNotAfter int64             `json:"cert_not_after"`
	CertSelfSign bool              `json:"cert_self_signed"`
	Favicon      string            `json:"favicon_hash"`
	Categories   []string          `json:"categories"`
	Tech         []Tech            `json:"tech"`
	Curiosity    int               `json:"curiosity"`
	Priority     string            `json:"priority"`      // effective
	ScanPriority string            `json:"scan_priority"` // as computed
	FirstSeen    int64             `json:"first_seen"`
	LastSeen     int64             `json:"last_seen"`
	LastChanged  int64             `json:"last_changed"`
	GoneAt       int64             `json:"gone_at"`
	Tags         []string          `json:"tags"`
	Triage       string            `json:"triage"`
	HasNote      bool              `json:"has_note"`
	Overrides    map[string]string `json:"overrides,omitempty"`
	Observed     map[string]string `json:"observed,omitempty"`
	// detail only
	Reasons    []analysis.Reason     `json:"reasons,omitempty"`
	HTTP       *fingerprint.HTTPInfo `json:"http,omitempty"`
	TLS        *fingerprint.TLSInfo  `json:"tls,omitempty"`
	Banner     string                `json:"banner,omitempty"`
	Annotation *Annotation           `json:"annotation,omitempty"`
	Changes    []ChangeRow           `json:"changes,omitempty"`
	History    []HistoryPoint        `json:"history,omitempty"`
	Vulns      []VulnRow             `json:"vulns,omitempty"`
}

type HistoryPoint struct {
	RunID  int64  `json:"run_id"`
	At     int64  `json:"at"`
	Digest string `json:"digest"`
	Up     bool   `json:"up"`
}

type Host struct {
	ID           int64             `json:"id"`
	Address      string            `json:"address"`
	Hostname     string            `json:"hostname"`
	State        string            `json:"state"`
	Origin       string            `json:"origin"`
	OS           string            `json:"os"`
	FirstSeen    int64             `json:"first_seen"`
	LastSeen     int64             `json:"last_seen"`
	LastProbed   int64             `json:"last_probed"`
	Misses       int               `json:"misses"`
	Probes       int               `json:"probes"`
	Ups          int               `json:"ups"`
	History      string            `json:"history"`
	HourUp       [24]int           `json:"hour_up"`
	HourProbe    [24]int           `json:"hour_probe"`
	Pattern      string            `json:"pattern"`
	Curiosity    int               `json:"curiosity"`
	OpenServices int               `json:"open_services"`
	TopPriority  string            `json:"top_priority"`
	Tags         []string          `json:"tags"`
	Triage       string            `json:"triage"`
	Criticality  string            `json:"criticality"`
	Overrides    map[string]string `json:"overrides,omitempty"`
	Observed     map[string]string `json:"observed,omitempty"`
	// detail only
	Annotation *Annotation    `json:"annotation,omitempty"`
	Services   []*Service     `json:"services,omitempty"`
	Changes    []ChangeRow    `json:"changes,omitempty"`
	Timeline   []HistoryPoint `json:"timeline,omitempty"`
}

var serviceOverrideFields = map[string]bool{"name": true, "product": true, "version": true, "title": true, "url": true}
var hostOverrideFields = map[string]bool{"hostname": true, "os": true}
var validTriage = map[string]bool{"": true, "new": true, "in_progress": true, "confirmed": true, "false_positive": true, "accepted_risk": true, "resolved": true}
var validPriority = map[string]bool{"": true, "critical": true, "high": true, "medium": true, "low": true, "info": true}

func (s *Store) applyServiceOverrides(sv *Service, ov map[string]string) {
	if len(ov) == 0 {
		return
	}
	sv.Overrides = ov
	sv.Observed = map[string]string{}
	set := func(k string, dst *string) {
		if v, ok := ov[k]; ok {
			sv.Observed[k] = *dst
			*dst = v
		}
	}
	set("name", &sv.Name)
	set("product", &sv.Product)
	set("version", &sv.Version)
	set("title", &sv.Title)
	set("url", &sv.URL)
}

func (s *Store) applyHostOverrides(h *Host, ov map[string]string) {
	if len(ov) == 0 {
		return
	}
	h.Overrides = ov
	h.Observed = map[string]string{}
	if v, ok := ov["hostname"]; ok {
		h.Observed["hostname"] = h.Hostname
		h.Hostname = v
	}
	if v, ok := ov["os"]; ok {
		h.Observed["os"] = h.OS
		h.OS = v
	}
}

// --- services ---------------------------------------------------------------

type ServiceFilter struct {
	Q          string
	Status     string // open (default) | gone | all
	Priority   string // comma list (effective priority)
	Category   string
	Tech       string
	Tag        string
	Triage     string
	Origin     string
	HostID     int64
	Favicon    string
	CertIssuer string
	Title      string
	Product    string
	Server     string
	Web        bool
	Since      int64 // last_changed >=
	RunID      int64 // only services observed in this run
	Sort       string
	Limit      int
	Offset     int
}

const effPrio = `COALESCE(NULLIF(a.priority_override,''), s.priority)`
const prioRank = `CASE ` + effPrio + ` WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END`

const serviceCols = `s.id, s.host_id, h.address, h.hostname, h.state, s.port, s.proto, s.status, s.origin, s.name, s.product, s.version, s.tunnel,
 s.is_web, s.url, s.http_status, s.title, s.server, s.cert_issuer, s.cert_subject, s.cert_not_after, s.cert_self_signed, s.favicon_hash,
 s.categories, s.curiosity, s.priority, ` + effPrio + `, s.first_seen, s.last_seen, s.last_changed, s.gone_at,
 COALESCE(a.tags,'[]'), COALESCE(a.triage,''), COALESCE(a.note_enc,'')!='', COALESCE(a.overrides_enc,'')`

const serviceFrom = ` FROM services s JOIN hosts h ON h.id=s.host_id LEFT JOIN annotations a ON a.entity_type='service' AND a.entity_id=s.id`

func (s *Store) scanService(row interface{ Scan(...any) error }) (*Service, error) {
	var sv Service
	var isWeb, ss int
	var cats, tags, ov string
	var hasNote bool
	err := row.Scan(&sv.ID, &sv.HostID, &sv.Address, &sv.Hostname, &sv.HostState, &sv.Port, &sv.Proto, &sv.Status, &sv.Origin, &sv.Name, &sv.Product,
		&sv.Version, &sv.Tunnel, &isWeb, &sv.URL, &sv.HTTPStatus, &sv.Title, &sv.Server, &sv.CertIssuer, &sv.CertSubject, &sv.CertNotAfter, &ss,
		&sv.Favicon, &cats, &sv.Curiosity, &sv.ScanPriority, &sv.Priority, &sv.FirstSeen, &sv.LastSeen, &sv.LastChanged, &sv.GoneAt, &tags, &sv.Triage, &hasNote, &ov)
	if err != nil {
		return nil, err
	}
	sv.IsWeb, sv.CertSelfSign, sv.HasNote = isWeb == 1, ss == 1, hasNote
	json.Unmarshal([]byte(cats), &sv.Categories)
	sv.Tags = parseTags(tags)
	if ov != "" {
		var m map[string]string
		s.K.OpenJSON("annotations.overrides", ov, &m)
		s.applyServiceOverrides(&sv, m)
	}
	return &sv, nil
}

func (f *ServiceFilter) where() (string, []any) {
	var w []string
	var args []any
	switch f.Status {
	case "all":
	case "gone":
		w = append(w, "s.status='gone'")
	default:
		w = append(w, "s.status='open'")
	}
	if f.Q != "" {
		q := "%" + strings.ToLower(f.Q) + "%"
		w = append(w, `(LOWER(h.address) LIKE ? OR LOWER(h.hostname) LIKE ? OR LOWER(s.title) LIKE ? OR LOWER(s.product) LIKE ? OR LOWER(s.name) LIKE ? OR LOWER(s.server) LIKE ?
			OR CAST(s.port AS TEXT)=? OR EXISTS(SELECT 1 FROM service_tech t WHERE t.service_id=s.id AND LOWER(t.name) LIKE ?))`)
		args = append(args, q, q, q, q, q, q, f.Q, q)
	}
	if f.Priority != "" {
		ps := strings.Split(f.Priority, ",")
		w = append(w, effPrio+` IN (`+placeholders(len(ps))+`)`)
		for _, p := range ps {
			args = append(args, strings.TrimSpace(p))
		}
	}
	if f.Category != "" {
		w = append(w, `EXISTS(SELECT 1 FROM json_each(s.categories) WHERE value=?)`)
		args = append(args, f.Category)
	}
	if f.Tech != "" {
		w = append(w, `EXISTS(SELECT 1 FROM service_tech t WHERE t.service_id=s.id AND t.name=?)`)
		args = append(args, f.Tech)
	}
	if f.Tag != "" {
		w = append(w, `EXISTS(SELECT 1 FROM json_each(COALESCE(a.tags,'[]')) WHERE value=?)`)
		args = append(args, strings.ToLower(f.Tag))
	}
	if f.Triage != "" {
		w = append(w, `COALESCE(a.triage,'')=?`)
		args = append(args, f.Triage)
	}
	if f.Origin != "" {
		w = append(w, `s.origin=?`)
		args = append(args, f.Origin)
	}
	if f.HostID > 0 {
		w = append(w, `s.host_id=?`)
		args = append(args, f.HostID)
	}
	if f.Favicon != "" {
		w = append(w, `s.favicon_hash=?`)
		args = append(args, f.Favicon)
	}
	if f.CertIssuer != "" {
		w = append(w, `s.cert_issuer=?`)
		args = append(args, f.CertIssuer)
	}
	if f.Title != "" {
		w = append(w, `s.title=?`)
		args = append(args, f.Title)
	}
	if f.Product != "" {
		w = append(w, `TRIM(s.product||' '||s.version)=?`)
		args = append(args, f.Product)
	}
	if f.Server != "" {
		w = append(w, `s.server=?`)
		args = append(args, f.Server)
	}
	if f.Web {
		w = append(w, `s.is_web=1`)
	}
	if f.RunID > 0 {
		w = append(w, `s.id IN (SELECT service_id FROM run_services WHERE run_id=?)`)
		args = append(args, f.RunID)
	}
	if f.Since > 0 {
		w = append(w, `s.last_changed>=?`)
		args = append(args, f.Since)
	}
	if len(w) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(w, " AND "), args
}

func (s *Store) ListServices(ctx context.Context, f ServiceFilter) ([]*Service, int, error) {
	where, args := f.where()
	where = addWhere(where, hostScope(ctx, "h"))
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*)`+serviceFrom+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := prioRank + ` DESC, s.curiosity DESC, s.id`
	switch f.Sort {
	case "address":
		order = `h.address, s.port`
	case "port":
		order = `s.port, h.address`
	case "first_seen":
		order = `s.first_seen DESC`
	case "last_seen":
		order = `s.last_seen DESC`
	case "last_changed":
		order = `s.last_changed DESC`
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+serviceCols+serviceFrom+where+` ORDER BY `+order+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Service
	var ids []int64
	for rows.Next() {
		sv, err := s.scanService(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sv)
		ids = append(ids, sv.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	rows.Close()
	if err := s.attachTech(ctx, out, ids, false); err != nil {
		return nil, 0, err
	}
	if out == nil {
		out = []*Service{}
	}
	return out, total, nil
}

func (s *Store) attachTech(ctx context.Context, svcs []*Service, ids []int64, evidence bool) error {
	if len(ids) == 0 {
		return nil
	}
	byID := map[int64]*Service{}
	for _, sv := range svcs {
		byID[sv.ID] = sv
		sv.Tech = []Tech{}
	}
	for start := 0; start < len(ids); start += 500 {
		end := min(start+500, len(ids))
		part := ids[start:end]
		rows, err := s.DB.QueryContext(ctx, `SELECT service_id, name, category, version, confidence, evidence FROM service_tech WHERE service_id IN (`+placeholders(len(part))+`) ORDER BY confidence DESC`, int64s(part)...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var t Tech
			var ev string
			rows.Scan(&id, &t.Name, &t.Category, &t.Version, &t.Confidence, &ev)
			if evidence {
				s.K.OpenJSON("service_tech.evidence", ev, &t.Evidence)
			}
			if sv := byID[id]; sv != nil {
				sv.Tech = append(sv.Tech, t)
			}
		}
		rows.Close()
	}
	return nil
}

func (s *Store) GetService(ctx context.Context, id int64) (*Service, error) {
	sv, err := s.scanService(s.DB.QueryRowContext(ctx, `SELECT `+serviceCols+serviceFrom+` WHERE s.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.attachTech(ctx, []*Service{sv}, []int64{id}, true)
	var httpE, tlsE, bannerE, reasonsE string
	s.DB.QueryRowContext(ctx, `SELECT http_enc, tls_enc, banner_enc, reasons FROM services WHERE id=?`, id).Scan(&httpE, &tlsE, &bannerE, &reasonsE)
	if httpE != "" {
		sv.HTTP = &fingerprint.HTTPInfo{}
		s.K.OpenJSON("services.http", httpE, sv.HTTP)
	}
	if tlsE != "" {
		sv.TLS = &fingerprint.TLSInfo{}
		s.K.OpenJSON("services.tls", tlsE, sv.TLS)
	}
	sv.Banner = s.K.OpenString("services.banner", bannerE)
	s.K.OpenJSON("services.reasons", reasonsE, &sv.Reasons)
	sv.Annotation, _ = s.GetAnnotation(ctx, "service", id)
	sv.Changes, _ = s.ListChanges(WithScope(ctx, ScopeAll), ChangeFilter{ServiceID: id, Limit: 50})
	sv.Vulns, _ = s.ListVulns(ctx, 0, id, 300)
	rows, err := s.DB.QueryContext(ctx, `SELECT rs.run_id, COALESCE(r.finished_at, r.created_at), rs.digest FROM run_services rs JOIN runs r ON r.id=rs.run_id WHERE rs.service_id=? ORDER BY rs.run_id DESC LIMIT 60`, id)
	if err == nil {
		for rows.Next() {
			var p HistoryPoint
			rows.Scan(&p.RunID, &p.At, &p.Digest)
			p.Up = true
			sv.History = append(sv.History, p)
		}
		rows.Close()
	}
	return sv, nil
}

// --- hosts --------------------------------------------------------------------

type HostFilter struct {
	Q      string
	State  string
	Tag    string
	JobID  int64
	Sort   string
	Limit  int
	Offset int
}

const hostCols = `h.id, h.address, h.hostname, h.state, h.origin, h.os_guess, h.first_seen, h.last_seen, h.last_probed, h.misses, h.probes, h.ups,
 h.history, h.hour_up, h.hour_probe, h.pattern, h.curiosity,
 (SELECT COUNT(*) FROM services s WHERE s.host_id=h.id AND s.status='open'),
 COALESCE((SELECT s.priority FROM services s WHERE s.host_id=h.id AND s.status='open' ORDER BY s.curiosity DESC LIMIT 1),''),
 COALESCE(a.tags,'[]'), COALESCE(a.triage,''), COALESCE(a.criticality,''), COALESCE(a.overrides_enc,'')`

const hostFrom = ` FROM hosts h LEFT JOIN annotations a ON a.entity_type='host' AND a.entity_id=h.id`

func (s *Store) scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var hu, hp, tags, ov string
	err := row.Scan(&h.ID, &h.Address, &h.Hostname, &h.State, &h.Origin, &h.OS, &h.FirstSeen, &h.LastSeen, &h.LastProbed, &h.Misses, &h.Probes, &h.Ups,
		&h.History, &hu, &hp, &h.Pattern, &h.Curiosity, &h.OpenServices, &h.TopPriority, &tags, &h.Triage, &h.Criticality, &ov)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(hu), &h.HourUp)
	json.Unmarshal([]byte(hp), &h.HourProbe)
	h.Tags = parseTags(tags)
	if ov != "" {
		var m map[string]string
		s.K.OpenJSON("annotations.overrides", ov, &m)
		s.applyHostOverrides(&h, m)
	}
	return &h, nil
}

func (s *Store) ListHosts(ctx context.Context, f HostFilter) ([]*Host, int, error) {
	var w []string
	var args []any
	if f.Q != "" {
		q := "%" + strings.ToLower(f.Q) + "%"
		w = append(w, `(LOWER(h.address) LIKE ? OR LOWER(h.hostname) LIKE ? OR LOWER(h.os_guess) LIKE ?)`)
		args = append(args, q, q, q)
	}
	if f.State != "" {
		w = append(w, `h.state=?`)
		args = append(args, f.State)
	}
	if f.Tag != "" {
		w = append(w, `EXISTS(SELECT 1 FROM json_each(COALESCE(a.tags,'[]')) WHERE value=?)`)
		args = append(args, strings.ToLower(f.Tag))
	}
	if f.JobID > 0 {
		w = append(w, `h.job_id=?`)
		args = append(args, f.JobID)
	}
	if c := hostScope(ctx, "h"); c != "" {
		w = append(w, c)
	}
	where := ""
	if len(w) > 0 {
		where = " WHERE " + strings.Join(w, " AND ")
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*)`+hostFrom+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := `h.curiosity DESC, h.id`
	switch f.Sort {
	case "address":
		order = `h.id` // insertion order roughly follows address scan order
	case "last_seen":
		order = `h.last_seen DESC`
	case "first_seen":
		order = `h.first_seen DESC`
	case "state":
		order = `h.state, h.curiosity DESC`
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+hostCols+hostFrom+where+` ORDER BY `+order+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Host{}
	for rows.Next() {
		h, err := s.scanHost(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

func (s *Store) GetHost(ctx context.Context, id int64) (*Host, error) {
	h, err := s.scanHost(s.DB.QueryRowContext(ctx, `SELECT `+hostCols+hostFrom+` WHERE h.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	h.Annotation, _ = s.GetAnnotation(ctx, "host", id)
	h.Services, _, _ = s.ListServices(WithScope(ctx, ScopeAll), ServiceFilter{HostID: id, Status: "all", Sort: "port", Limit: 1000})
	h.Changes, _ = s.ListChanges(WithScope(ctx, ScopeAll), ChangeFilter{HostID: id, Limit: 100})
	rows, err := s.DB.QueryContext(ctx, `SELECT rh.run_id, rh.at, rh.up FROM run_hosts rh WHERE rh.host_id=? ORDER BY rh.run_id DESC LIMIT 60`, id)
	if err == nil {
		for rows.Next() {
			var p HistoryPoint
			var up int
			rows.Scan(&p.RunID, &p.At, &up)
			p.Up = up == 1
			h.Timeline = append(h.Timeline, p)
		}
		rows.Close()
	}
	return h, nil
}

// --- annotations (analyst layer) -------------------------------------------------

func (s *Store) GetAnnotation(ctx context.Context, typ string, id int64) (*Annotation, error) {
	a := &Annotation{Tags: []string{}, Overrides: map[string]string{}}
	var tags, note, ov string
	err := s.DB.QueryRowContext(ctx, `SELECT tags, triage, owner, criticality, priority_override, note_enc, overrides_enc, updated_by, updated_at FROM annotations WHERE entity_type=? AND entity_id=?`, typ, id).
		Scan(&tags, &a.Triage, &a.Owner, &a.Criticality, &a.PriorityOverride, &note, &ov, &a.UpdatedBy, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	a.Tags = parseTags(tags)
	a.Note = s.K.OpenString("annotations.note", note)
	if ov != "" {
		s.K.OpenJSON("annotations.overrides", ov, &a.Overrides)
	}
	return a, nil
}

// AnnotationPatch: nil fields are left unchanged. In Overrides an empty
// string value removes that override (reverting to the scanned value).
type AnnotationPatch struct {
	Tags             *[]string          `json:"tags"`
	Triage           *string            `json:"triage"`
	Owner            *string            `json:"owner"`
	Criticality      *string            `json:"criticality"`
	PriorityOverride *string            `json:"priority_override"`
	Note             *string            `json:"note"`
	Overrides        map[string]*string `json:"overrides"`
}

func (s *Store) UpdateAnnotation(ctx context.Context, typ string, id int64, p AnnotationPatch, user string) (*Annotation, error) {
	var exists int
	switch typ {
	case "service":
		s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM services WHERE id=?`, id).Scan(&exists)
	case "host":
		s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE id=?`, id).Scan(&exists)
	default:
		return nil, errors.New("bad entity type")
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	a, err := s.GetAnnotation(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	allowed := serviceOverrideFields
	if typ == "host" {
		allowed = hostOverrideFields
	}
	if p.Tags != nil {
		a.Tags = NormalizeTags(*p.Tags)
	}
	if p.Triage != nil {
		if !validTriage[*p.Triage] {
			return nil, fmt.Errorf("invalid triage %q", *p.Triage)
		}
		a.Triage = *p.Triage
	}
	if p.Owner != nil {
		a.Owner = strings.TrimSpace(*p.Owner)
	}
	if p.Criticality != nil {
		a.Criticality = strings.TrimSpace(*p.Criticality)
	}
	if p.PriorityOverride != nil {
		if !validPriority[*p.PriorityOverride] {
			return nil, fmt.Errorf("invalid priority %q", *p.PriorityOverride)
		}
		a.PriorityOverride = *p.PriorityOverride
	}
	if p.Note != nil {
		if len(*p.Note) > 20000 {
			return nil, errors.New("note too long")
		}
		a.Note = *p.Note
	}
	for k, v := range p.Overrides {
		if !allowed[k] {
			return nil, fmt.Errorf("field %q cannot be overridden", k)
		}
		if v == nil || *v == "" {
			delete(a.Overrides, k)
		} else {
			a.Overrides[k] = *v
		}
	}
	ov := ""
	if len(a.Overrides) > 0 {
		ov = s.K.MustSealJSON("annotations.overrides", a.Overrides)
	}
	a.UpdatedBy, a.UpdatedAt = user, s.now()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO annotations(entity_type, entity_id, tags, triage, owner, criticality, priority_override, note_enc, overrides_enc, updated_by, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_type, entity_id) DO UPDATE SET tags=excluded.tags, triage=excluded.triage, owner=excluded.owner,
		criticality=excluded.criticality, priority_override=excluded.priority_override, note_enc=excluded.note_enc, overrides_enc=excluded.overrides_enc,
		updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
		typ, id, jsonStr(a.Tags), a.Triage, a.Owner, a.Criticality, a.PriorityOverride, s.K.SealString("annotations.note", a.Note), ov, user, a.UpdatedAt)
	return a, err
}

// --- manual entries (treated like scan data) ------------------------------------

type ManualService struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Name    string   `json:"name"`
	Product string   `json:"product"`
	Version string   `json:"version"`
	Title   string   `json:"title"`
	URL     string   `json:"url"`
	Note    string   `json:"note"`
	Tags    []string `json:"tags"`
}

type ManualHost struct {
	Address  string          `json:"address"`
	Hostname string          `json:"hostname"`
	Tags     []string        `json:"tags"`
	Note     string          `json:"note"`
	Services []ManualService `json:"services"`
}

// Enricher runs detection signatures on a manually entered service so that
// manual data is scored and categorised exactly like scanned data.
type Enricher func(ServiceObs, string) ServiceObs

// CreateManual inserts (or extends) a host with services entered by a user.
// User-provided descriptive values are also written to the analyst layer so
// later scans can update the observed layer without losing them.
func (s *Store) CreateManual(ctx context.Context, mh ManualHost, enrich Enricher, user string) (int64, []int64, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(mh.Address))
	if err != nil {
		return 0, nil, fmt.Errorf("invalid IP address %q", mh.Address)
	}
	addr := a.String()
	for _, ms := range mh.Services {
		if ms.Port < 1 || ms.Port > 65535 {
			return 0, nil, fmt.Errorf("invalid port %d", ms.Port)
		}
		if ms.Proto != "" && ms.Proto != "tcp" && ms.Proto != "udp" {
			return 0, nil, fmt.Errorf("invalid proto %q", ms.Proto)
		}
	}
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	now := s.now()
	ic := &ingestCtx{tx: tx, at: now, local: s.Now(), user: user}
	hr, err := s.loadHostTx(ctx, tx, `address=?`, addr)
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		res, err := tx.ExecContext(ctx, `INSERT INTO hosts(address, hostname, state, origin, first_seen, last_seen, updated_at) VALUES(?,?,'active','manual',?,?,?)`,
			addr, strings.TrimSpace(mh.Hostname), now, now, now)
		if err != nil {
			return 0, nil, err
		}
		id, _ := res.LastInsertId()
		hr = &hostRow{ID: id, Address: addr, Hostname: mh.Hostname, Track: analysis.Track{State: "active"}}
		created = true
	} else if err != nil {
		return 0, nil, err
	}
	if created {
		s.addChange(ctx, ic, hr.ID, 0, ChManual, "info", fmt.Sprintf("Ręcznie dodano host %s (%s)", addr, user), nil)
	}
	if len(mh.Tags) > 0 || mh.Note != "" {
		if err := s.mergeAnnotation(ctx, tx, "host", hr.ID, mh.Tags, mh.Note, user); err != nil {
			return 0, nil, err
		}
	}
	var ids []int64
	for _, ms := range mh.Services {
		if ms.Proto == "" {
			ms.Proto = "tcp"
		}
		o := ServiceObs{PortResult: scanner.PortResult{Port: ms.Port, Proto: ms.Proto, State: "open", Name: ms.Name, Product: ms.Product, Version: ms.Version}}
		if enrich != nil {
			o = enrich(o, hr.Hostname)
		}
		id, _, err := s.applyService(ctx, ic, hr.ID, addr, hr.Track.State, created, o, "manual")
		if err != nil {
			return 0, nil, err
		}
		if ms.Title != "" || ms.URL != "" {
			tx.ExecContext(ctx, `UPDATE services SET title=CASE WHEN ?!='' THEN ? ELSE title END, url=CASE WHEN ?!='' THEN ? ELSE url END WHERE id=?`,
				ms.Title, ms.Title, ms.URL, ms.URL, id)
		}
		ov := map[string]string{}
		for k, v := range map[string]string{"name": ms.Name, "product": ms.Product, "version": ms.Version, "title": ms.Title, "url": ms.URL} {
			if v != "" {
				ov[k] = v
			}
		}
		if len(ov) > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO annotations(entity_type, entity_id, overrides_enc, updated_by, updated_at) VALUES('service',?,?,?,?)
				ON CONFLICT(entity_type, entity_id) DO UPDATE SET overrides_enc=excluded.overrides_enc, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
				id, s.K.MustSealJSON("annotations.overrides", ov), user, now); err != nil {
				return 0, nil, err
			}
		}
		if len(ms.Tags) > 0 || ms.Note != "" {
			if err := s.mergeAnnotation(ctx, tx, "service", id, ms.Tags, ms.Note, user); err != nil {
				return 0, nil, err
			}
		}
		s.addChange(ctx, ic, hr.ID, id, ChManual, "info", fmt.Sprintf("Ręcznie dodano usługę %s:%d/%s %s (%s)", addr, ms.Port, ms.Proto, ms.Name, user), nil)
		ids = append(ids, id)
	}
	tx.ExecContext(ctx, `UPDATE hosts SET curiosity=COALESCE((SELECT MAX(curiosity) FROM services s WHERE s.host_id=hosts.id AND s.status='open'),0) WHERE id=?`, hr.ID)
	return hr.ID, ids, tx.Commit()
}

func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.ExecContext(ctx, `DELETE FROM annotations WHERE entity_type='service' AND entity_id IN (SELECT id FROM services WHERE host_id=?)`, id)
	tx.ExecContext(ctx, `DELETE FROM annotations WHERE entity_type='host' AND entity_id=?`, id)
	r, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) DeleteService(ctx context.Context, id int64) error {
	s.DB.ExecContext(ctx, `DELETE FROM annotations WHERE entity_type='service' AND entity_id=?`, id)
	r, err := s.DB.ExecContext(ctx, `DELETE FROM services WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- grouping -----------------------------------------------------------------------

type Group struct {
	By        string   `json:"by"`
	Key       string   `json:"key"`
	Label     string   `json:"label"`
	Services  int      `json:"services"`
	Hosts     int      `json:"hosts"`
	Curiosity int      `json:"max_curiosity"`
	Sample    []string `json:"sample"`
}

// Groups clusters similar open services so thousands of hosts stay readable.
func (s *Store) Groups(ctx context.Context, by string, limit int) ([]Group, error) {
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	var keyExpr, from, cond string
	from = ` FROM services s JOIN hosts h ON h.id=s.host_id`
	switch by {
	case "favicon":
		keyExpr, cond = "s.favicon_hash", "s.favicon_hash!=''"
	case "cert_issuer":
		keyExpr, cond = "s.cert_issuer", "s.cert_issuer!=''"
	case "title":
		keyExpr, cond = "s.title", "s.title!=''"
	case "server":
		keyExpr, cond = "s.server", "s.server!=''"
	case "product":
		keyExpr, cond = "TRIM(s.product||' '||s.version)", "s.product!=''"
	case "tech":
		keyExpr, cond = "t.name", "1=1"
		from += ` JOIN service_tech t ON t.service_id=s.id`
	case "category":
		keyExpr, cond = "c.value", "1=1"
		from += `, json_each(s.categories) c`
	default:
		return nil, fmt.Errorf("unknown grouping %q", by)
	}
	q := `SELECT ` + keyExpr + ` AS k, COUNT(DISTINCT s.id), COUNT(DISTINCT s.host_id), MAX(s.curiosity), GROUP_CONCAT(DISTINCT h.address)` + from +
		` WHERE s.status='open' AND ` + cond + andCond(hostScope(ctx, "h")) + ` GROUP BY k ORDER BY COUNT(DISTINCT s.id) DESC, MAX(s.curiosity) DESC LIMIT ?`
	rows, err := s.DB.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var sample sql.NullString
		if err := rows.Scan(&g.Key, &g.Services, &g.Hosts, &g.Curiosity, &sample); err != nil {
			return nil, err
		}
		g.By, g.Label = by, g.Key
		if sample.Valid {
			sp := strings.Split(sample.String, ",")
			if len(sp) > 6 {
				sp = sp[:6]
			}
			g.Sample = sp
		}
		out = append(out, g)
	}
	rows.Close()
	if by == "favicon" {
		for i := range out {
			var t, tech string
			s.DB.QueryRowContext(ctx, `SELECT title FROM services WHERE favicon_hash=? AND title!='' GROUP BY title ORDER BY COUNT(*) DESC LIMIT 1`, out[i].Key).Scan(&t)
			s.DB.QueryRowContext(ctx, `SELECT t.name FROM service_tech t JOIN services s ON s.id=t.service_id WHERE s.favicon_hash=? AND t.category NOT IN ('server','language','auth','info')
				GROUP BY t.name ORDER BY COUNT(*) DESC LIMIT 1`, out[i].Key).Scan(&tech)
			lbl := "mmh3 " + out[i].Key
			if tech != "" {
				lbl = tech + " · " + lbl
			} else if t != "" {
				lbl = t + " · " + lbl
			}
			out[i].Label = lbl
		}
	}
	return out, nil
}
