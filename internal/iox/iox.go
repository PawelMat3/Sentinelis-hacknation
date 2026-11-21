// Package iox implements import/export formats:
//   - targets: CSV (value,tags,note), JSON (strings or objects), plain text
//   - results: ASI JSON (asi-results/v1), flat CSV (one row per service),
//     nmap XML (-oX) - imports go through the regular ingest pipeline
//   - changes: CSV / JSON
package iox

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"asi/internal/fingerprint"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
)

const ResultsFormat = "asi-results/v1"

// Detect guesses the format of an uploaded file.
func Detect(name string, data []byte) string {
	n := strings.ToLower(name)
	trim := bytes.TrimSpace(data)
	switch {
	case strings.HasSuffix(n, ".xml") || bytes.Contains(trim[:min(len(trim), 512)], []byte("<nmaprun")):
		return "nmap"
	case strings.HasSuffix(n, ".json") || (len(trim) > 0 && (trim[0] == '{' || trim[0] == '[')):
		return "json"
	case strings.HasSuffix(n, ".csv"):
		return "csv"
	}
	if bytes.Contains(trim[:min(len(trim), 400)], []byte(",")) {
		return "csv"
	}
	return "text"
}

// --- targets --------------------------------------------------------------------

func ParseTargets(format string, data []byte) ([]store.TargetInput, error) {
	switch format {
	case "json":
		var raw []json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			var obj struct {
				Targets []json.RawMessage `json:"targets"`
			}
			if err2 := json.Unmarshal(data, &obj); err2 != nil || obj.Targets == nil {
				return nil, fmt.Errorf("JSON: expected array of strings/objects or {\"targets\":[...]}: %v", err)
			}
			raw = obj.Targets
		}
		var out []store.TargetInput
		for _, r := range raw {
			var s string
			if json.Unmarshal(r, &s) == nil {
				out = append(out, store.TargetInput{Value: s})
				continue
			}
			var t struct {
				Value  string   `json:"value"`
				Target string   `json:"target"`
				Tags   []string `json:"tags"`
				Note   string   `json:"note"`
			}
			if err := json.Unmarshal(r, &t); err != nil {
				return nil, err
			}
			if t.Value == "" {
				t.Value = t.Target
			}
			out = append(out, store.TargetInput{Value: t.Value, Tags: t.Tags, Note: t.Note})
		}
		return out, nil
	case "csv":
		r := csv.NewReader(bytes.NewReader(data))
		r.FieldsPerRecord = -1
		r.TrimLeadingSpace = true
		rows, err := r.ReadAll()
		if err != nil {
			return nil, err
		}
		col := map[string]int{"value": 0, "tags": 1, "note": 2}
		start := 0
		if len(rows) > 0 {
			h := strings.ToLower(strings.Join(rows[0], ","))
			if strings.Contains(h, "value") || strings.Contains(h, "target") || strings.Contains(h, "address") {
				col = map[string]int{}
				for i, c := range rows[0] {
					switch strings.ToLower(strings.TrimSpace(c)) {
					case "value", "target", "address", "ip", "cidr", "domain":
						col["value"] = i
					case "tags", "tag":
						col["tags"] = i
					case "note", "notes", "comment", "description":
						col["note"] = i
					}
				}
				start = 1
			}
		}
		var out []store.TargetInput
		for _, row := range rows[start:] {
			get := func(k string) string {
				if i, ok := col[k]; ok && i < len(row) {
					return strings.TrimSpace(row[i])
				}
				return ""
			}
			v := get("value")
			if v == "" || strings.HasPrefix(v, "#") {
				continue
			}
			out = append(out, store.TargetInput{Value: v, Tags: splitTags(get("tags")), Note: get("note")})
		}
		return out, nil
	default:
		var out []store.TargetInput
		for _, v := range targets.ParseList(string(data)) {
			out = append(out, store.TargetInput{Value: v})
		}
		return out, nil
	}
}

func splitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' || r == ',' || r == ' ' })
}

func TargetsCSV(w io.Writer, rows []store.TargetRow) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"value", "kind", "addr_count", "tags", "note", "source"})
	for _, t := range rows {
		cw.Write([]string{t.Value, t.Kind, strconv.FormatInt(t.Count, 10), strings.Join(t.Tags, ";"), t.Note, t.Source})
	}
	cw.Flush()
	return cw.Error()
}

// --- results export -------------------------------------------------------------------

type ExportTech struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
}

type ExportCert struct {
	Issuer     string `json:"issuer,omitempty"`
	Subject    string `json:"subject,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
}

type ExportService struct {
	Port       int                   `json:"port"`
	Proto      string                `json:"proto"`
	Status     string                `json:"status"`
	Origin     string                `json:"origin"`
	Name       string                `json:"name"`
	Product    string                `json:"product,omitempty"`
	Version    string                `json:"version,omitempty"`
	URL        string                `json:"url,omitempty"`
	HTTPStatus int                   `json:"http_status,omitempty"`
	Title      string                `json:"title,omitempty"`
	Server     string                `json:"server,omitempty"`
	Tech       []ExportTech          `json:"technologies,omitempty"`
	Categories []string              `json:"categories,omitempty"`
	Priority   string                `json:"priority"`
	Curiosity  int                   `json:"curiosity"`
	Cert       *ExportCert           `json:"cert,omitempty"`
	Favicon    string                `json:"favicon_hash,omitempty"`
	Tags       []string              `json:"tags,omitempty"`
	Triage     string                `json:"triage,omitempty"`
	Note       string                `json:"note,omitempty"`
	Overrides  map[string]string     `json:"overrides,omitempty"`
	FirstSeen  string                `json:"first_seen,omitempty"`
	LastSeen   string                `json:"last_seen,omitempty"`
	HTTP       *fingerprint.HTTPInfo `json:"http,omitempty"`
}

type ExportHost struct {
	Address   string          `json:"address"`
	Hostname  string          `json:"hostname,omitempty"`
	State     string          `json:"state"`
	OS        string          `json:"os,omitempty"`
	Pattern   string          `json:"availability_pattern,omitempty"`
	FirstSeen string          `json:"first_seen,omitempty"`
	LastSeen  string          `json:"last_seen,omitempty"`
	Tags      []string        `json:"tags,omitempty"`
	Triage    string          `json:"triage,omitempty"`
	Note      string          `json:"note,omitempty"`
	Services  []ExportService `json:"services"`
}

type ExportDoc struct {
	Format      string       `json:"format"`
	GeneratedAt string       `json:"generated_at"`
	Hosts       []ExportHost `json:"hosts"`
}

func ts(v int64) string {
	if v <= 0 {
		return ""
	}
	return time.Unix(v, 0).UTC().Format(time.RFC3339)
}

func parseTS(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

// ExportService converts a store service (effective view).
func ToExportService(sv *store.Service, note string, withHTTP bool) ExportService {
	es := ExportService{Port: sv.Port, Proto: sv.Proto, Status: sv.Status, Origin: sv.Origin, Name: sv.Name, Product: sv.Product, Version: sv.Version,
		URL: sv.URL, HTTPStatus: sv.HTTPStatus, Title: sv.Title, Server: sv.Server, Categories: sv.Categories, Priority: sv.Priority,
		Curiosity: sv.Curiosity, Favicon: sv.Favicon, Tags: sv.Tags, Triage: sv.Triage, Note: note, Overrides: sv.Overrides,
		FirstSeen: ts(sv.FirstSeen), LastSeen: ts(sv.LastSeen)}
	for _, t := range sv.Tech {
		es.Tech = append(es.Tech, ExportTech{t.Name, t.Version, t.Category, t.Confidence})
	}
	if sv.CertIssuer != "" || sv.CertNotAfter > 0 {
		es.Cert = &ExportCert{Issuer: sv.CertIssuer, Subject: sv.CertSubject, NotAfter: ts(sv.CertNotAfter), SelfSigned: sv.CertSelfSign}
	}
	if withHTTP && sv.HTTP != nil {
		h := *sv.HTTP
		h.TLS = sv.TLS
		es.HTTP = &h
	}
	return es
}

var CSVHeader = []string{"address", "hostname", "host_state", "port", "proto", "status", "origin", "name", "product", "version", "url", "http_status",
	"title", "server", "technologies", "categories", "priority", "curiosity", "cert_issuer", "cert_not_after", "cert_self_signed", "favicon_hash",
	"tags", "triage", "first_seen", "last_seen"}

func ServiceCSVRow(sv *store.Service) []string {
	var tech []string
	for _, t := range sv.Tech {
		s := t.Name
		if t.Version != "" {
			s += " " + t.Version
		}
		tech = append(tech, s)
	}
	return []string{sv.Address, sv.Hostname, sv.HostState, strconv.Itoa(sv.Port), sv.Proto, sv.Status, sv.Origin, sv.Name, sv.Product, sv.Version,
		sv.URL, strconv.Itoa(sv.HTTPStatus), csvSafe(sv.Title), csvSafe(sv.Server), strings.Join(tech, ";"), strings.Join(sv.Categories, ";"), sv.Priority,
		strconv.Itoa(sv.Curiosity), csvSafe(sv.CertIssuer), ts(sv.CertNotAfter), strconv.FormatBool(sv.CertSelfSign), sv.Favicon,
		strings.Join(sv.Tags, ";"), sv.Triage, ts(sv.FirstSeen), ts(sv.LastSeen)}
}

// csvSafe neutralises spreadsheet formula injection from hostile page titles.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// --- results import --------------------------------------------------------------------

// ParseResults converts an uploaded results file into host observations.
func ParseResults(format string, data []byte) ([]store.HostObs, error) {
	switch format {
	case "nmap":
		res, err := scanner.ParseNmapXML(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		var out []store.HostObs
		for _, h := range res {
			ho := store.HostObs{Address: h.Address, Hostname: h.Hostname, OS: h.OS, Up: h.Up}
			for _, p := range h.Ports {
				ho.Services = append(ho.Services, store.ServiceObs{PortResult: p})
			}
			out = append(out, ho)
		}
		return out, nil
	case "json":
		return parseJSONResults(data)
	case "csv":
		return parseCSVResults(data)
	}
	return nil, fmt.Errorf("unsupported results format %q (use json, csv or nmap xml)", format)
}

func parseJSONResults(data []byte) ([]store.HostObs, error) {
	var doc ExportDoc
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Hosts) > 0 {
		var out []store.HostObs
		for _, h := range doc.Hosts {
			if !targets.IsIP(h.Address) {
				return nil, fmt.Errorf("invalid address %q", h.Address)
			}
			ho := store.HostObs{Address: h.Address, Hostname: h.Hostname, OS: h.OS, Up: h.State != "inactive", ImportTags: h.Tags, ImportNote: h.Note}
			for _, s := range h.Services {
				if s.Status == "gone" {
					continue
				}
				so := store.ServiceObs{PortResult: scanner.PortResult{Port: s.Port, Proto: s.Proto, State: "open", Name: s.Name, Product: s.Product, Version: s.Version},
					HTTP: s.HTTP, ImportTags: s.Tags, ImportNote: s.Note}
				if so.HTTP == nil && (s.Title != "" || s.HTTPStatus > 0 || s.Server != "") {
					so.HTTP = &fingerprint.HTTPInfo{URL: s.URL, FinalURL: s.URL, StatusCode: s.HTTPStatus, Title: s.Title, Headers: map[string][]string{}}
					if s.Server != "" {
						so.HTTP.Headers["Server"] = []string{s.Server}
					}
				}
				ho.Services = append(ho.Services, so)
			}
			out = append(out, ho)
		}
		return out, nil
	}
	// flat array of rows
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("JSON: expected {\"format\":\"%s\",\"hosts\":[...]} or an array of service rows", ResultsFormat)
	}
	var recs []map[string]string
	for _, r := range rows {
		m := map[string]string{}
		for k, v := range r {
			switch x := v.(type) {
			case string:
				m[strings.ToLower(k)] = x
			case float64:
				m[strings.ToLower(k)] = strconv.FormatFloat(x, 'f', -1, 64)
			case []any:
				var parts []string
				for _, p := range x {
					parts = append(parts, fmt.Sprint(p))
				}
				m[strings.ToLower(k)] = strings.Join(parts, ";")
			}
		}
		recs = append(recs, m)
	}
	return fromRecords(recs)
}

func parseCSVResults(data []byte) ([]store.HostObs, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, errors.New("CSV needs a header row and at least one data row")
	}
	var recs []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		for i, h := range rows[0] {
			if i < len(row) {
				m[strings.ToLower(strings.TrimSpace(h))] = strings.TrimSpace(row[i])
			}
		}
		recs = append(recs, m)
	}
	return fromRecords(recs)
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func fromRecords(recs []map[string]string) ([]store.HostObs, error) {
	byAddr := map[string]*store.HostObs{}
	var order []string
	for i, m := range recs {
		addr := first(m, "address", "ip", "host", "ip_address")
		if !targets.IsIP(addr) {
			return nil, fmt.Errorf("row %d: invalid or missing address %q", i+1, addr)
		}
		ho, ok := byAddr[addr]
		if !ok {
			ho = &store.HostObs{Address: addr, Up: true}
			byAddr[addr] = ho
			order = append(order, addr)
		}
		if hn := first(m, "hostname", "fqdn", "domain"); hn != "" {
			ho.Hostname = hn
		}
		if first(m, "status") == "gone" {
			continue
		}
		port, _ := strconv.Atoi(first(m, "port"))
		if port == 0 {
			if t := first(m, "tags"); t != "" {
				ho.ImportTags = append(ho.ImportTags, splitTags(t)...)
			}
			continue
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("row %d: invalid port", i+1)
		}
		so := store.ServiceObs{PortResult: scanner.PortResult{Port: port, Proto: first(m, "proto", "protocol"), State: "open",
			Name: first(m, "name", "service"), Product: first(m, "product"), Version: first(m, "version"), Banner: first(m, "banner")},
			ImportTags: splitTags(first(m, "tags")), ImportNote: first(m, "note", "notes", "comment")}
		if so.Proto == "" {
			so.Proto = "tcp"
		}
		st, _ := strconv.Atoi(first(m, "http_status", "status_code"))
		if title, server, u := first(m, "title"), first(m, "server"), first(m, "url"); title != "" || server != "" || st > 0 {
			so.HTTP = &fingerprint.HTTPInfo{URL: u, FinalURL: u, StatusCode: st, Title: strings.TrimPrefix(title, "'"), Headers: map[string][]string{}}
			if server != "" {
				so.HTTP.Headers["Server"] = []string{strings.TrimPrefix(server, "'")}
			}
		}
		ho.Services = append(ho.Services, so)
	}
	out := make([]store.HostObs, 0, len(order))
	for _, a := range order {
		out = append(out, *byAddr[a])
	}
	return out, nil
}

// --- changes export -----------------------------------------------------------------------

func ChangesCSV(w io.Writer, rows []store.ChangeRow) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "time", "run_id", "kind", "severity", "address", "port", "summary"})
	for _, c := range rows {
		cw.Write([]string{strconv.FormatInt(c.ID, 10), ts(c.CreatedAt), strconv.FormatInt(c.RunID, 10), c.Kind, c.Severity, c.Address, strconv.Itoa(c.Port), csvSafe(c.Summary)})
	}
	cw.Flush()
	return cw.Error()
}

var _ = parseTS
