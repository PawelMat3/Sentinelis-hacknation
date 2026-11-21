package fingerprint

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Matcher types. Every matcher is evaluated only against data that was already
// collected passively - signatures can never trigger new kinds of requests
// except GET of a validated plain path.
const (
	MHeader    = "header"    // name (required) + optional pattern on value
	MCookie    = "cookie"    // pattern on cookie name
	MBody      = "body"      // pattern on main page body
	MTitle     = "title"     // pattern on <title>
	MGenerator = "generator" // pattern on <meta name=generator>
	MFavicon   = "favicon"   // value: comma-separated mmh3 hashes
	MPath      = "path"      // path + status list + optional pattern on body/title
	MCert      = "cert"      // field subject|issuer|san|any + pattern
	MHostname  = "hostname"  // pattern on hostname / vhost / cert SANs / final URL host
	MBanner    = "banner"    // pattern on raw service banner
	MProduct   = "product"   // pattern on "service product version" from nmap
	MPort      = "port"      // value: comma-separated ports
	MURL       = "url"       // pattern on final URL and redirect targets
)

var MatcherTypes = []string{MHeader, MCookie, MBody, MTitle, MGenerator, MFavicon, MPath, MCert, MHostname, MBanner, MProduct, MPort, MURL}

type Matcher struct {
	Type    string  `json:"type"`
	Name    string  `json:"name,omitempty"`
	Pattern string  `json:"pattern,omitempty"`
	Path    string  `json:"path,omitempty"`
	Status  []int   `json:"status,omitempty"`
	Field   string  `json:"field,omitempty"`
	Value   string  `json:"value,omitempty"`
	Weight  float64 `json:"weight"`
	Negate  bool    `json:"negate,omitempty"`
	re      *regexp.Regexp
}

type Definition struct {
	Matchers      []Matcher `json:"matchers"`
	Condition     string    `json:"condition,omitempty"`      // "any" (weighted) or "all"
	MinConfidence int       `json:"min_confidence,omitempty"` // 0..100, default 40
	Curiosity     int       `json:"curiosity,omitempty"`      // priority bonus when detected
	Tags          []string  `json:"tags,omitempty"`
}

type Signature struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	Builtin     bool       `json:"builtin"`
	Def         Definition `json:"definition"`
	compiled    bool
}

// Compile validates the signature and compiles regexes.
func (s *Signature) Compile() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("signature name required")
	}
	if len(s.Def.Matchers) == 0 {
		return fmt.Errorf("%s: at least one matcher required", s.Name)
	}
	if s.Def.Condition == "" {
		s.Def.Condition = "any"
	}
	if s.Def.Condition != "any" && s.Def.Condition != "all" {
		return fmt.Errorf("%s: condition must be any|all", s.Name)
	}
	if s.Def.MinConfidence <= 0 {
		s.Def.MinConfidence = 40
	}
	if s.Def.Curiosity < 0 || s.Def.Curiosity > 50 {
		return fmt.Errorf("%s: curiosity must be 0..50", s.Name)
	}
	for i := range s.Def.Matchers {
		m := &s.Def.Matchers[i]
		ok := false
		for _, t := range MatcherTypes {
			if m.Type == t {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s: unknown matcher type %q", s.Name, m.Type)
		}
		if m.Weight <= 0 {
			m.Weight = 0.5
		}
		m.Weight = math.Min(m.Weight, 0.99)
		if m.Pattern != "" {
			if len(m.Pattern) > 500 {
				return fmt.Errorf("%s: pattern too long", s.Name)
			}
			re, err := regexp.Compile("(?i)" + m.Pattern)
			if err != nil {
				return fmt.Errorf("%s: bad regex %q: %v", s.Name, m.Pattern, err)
			}
			m.re = re
		}
		switch m.Type {
		case MHeader:
			if m.Name == "" {
				return fmt.Errorf("%s: header matcher needs name", s.Name)
			}
		case MPath:
			if !SafePath(m.Path) {
				return fmt.Errorf("%s: unsafe path %q (only plain GET paths like /login, /version are allowed)", s.Name, m.Path)
			}
			if len(m.Status) == 0 {
				m.Status = []int{200}
			}
		case MFavicon, MPort:
			if m.Value == "" {
				return fmt.Errorf("%s: %s matcher needs value", s.Name, m.Type)
			}
		case MCookie, MBody, MTitle, MGenerator, MBanner, MProduct, MURL, MHostname:
			if m.re == nil && m.Name == "" {
				return fmt.Errorf("%s: %s matcher needs pattern", s.Name, m.Type)
			}
		case MCert:
			if m.re == nil {
				return fmt.Errorf("%s: cert matcher needs pattern", s.Name)
			}
		}
	}
	s.compiled = true
	return nil
}

// match evaluates one matcher; returns hit, evidence text and captured version.
func (m *Matcher) match(ev *Evidence) (bool, string, string) {
	h := ev.HTTP
	find := func(s string) (bool, string) {
		if m.re == nil || s == "" {
			return false, ""
		}
		sm := m.re.FindStringSubmatch(s)
		if sm == nil {
			return false, ""
		}
		v := ""
		if i := m.re.SubexpIndex("version"); i > 0 && i < len(sm) {
			v = sm[i]
		}
		return true, v
	}
	switch m.Type {
	case MHeader:
		if h == nil {
			return false, "", ""
		}
		val := ""
		found := false
		for k, vs := range h.Headers {
			if strings.EqualFold(k, m.Name) {
				found = true
				val = strings.Join(vs, ", ")
			}
		}
		if !found {
			return false, "", ""
		}
		if m.re == nil {
			return true, "nagłówek " + m.Name, ""
		}
		ok, v := find(val)
		return ok, fmt.Sprintf("nagłówek %s: %s", m.Name, clip(val, 80)), v
	case MCookie:
		if h == nil {
			return false, "", ""
		}
		for _, c := range h.Cookies {
			if (m.Name != "" && strings.EqualFold(c.Name, m.Name)) || (m.re != nil && m.re.MatchString(c.Name)) {
				return true, "ciasteczko " + c.Name, ""
			}
		}
	case MBody:
		if h == nil {
			return false, "", ""
		}
		body := string(h.body)
		if body == "" {
			body = h.BodyExcerpt
		}
		if ok, v := find(body); ok {
			return true, "fragment HTML /" + clip(m.Pattern, 40), v
		}
	case MTitle:
		if h != nil {
			if ok, v := find(h.Title); ok {
				return true, "tytuł: " + clip(h.Title, 60), v
			}
		}
	case MGenerator:
		if h != nil {
			if ok, v := find(h.Generator); ok {
				return true, "meta generator: " + clip(h.Generator, 60), v
			}
		}
	case MFavicon:
		if h != nil && h.FaviconHash != "" {
			for _, v := range strings.Split(m.Value, ",") {
				if strings.TrimSpace(v) == h.FaviconHash {
					return true, "favicon mmh3=" + h.FaviconHash, ""
				}
			}
		}
	case MPath:
		if h == nil {
			return false, "", ""
		}
		for _, p := range h.Paths {
			if p.Path != m.Path || p.Soft404 {
				continue
			}
			okStatus := false
			for _, st := range m.Status {
				if st == p.Status {
					okStatus = true
				}
			}
			if !okStatus {
				return false, "", ""
			}
			if m.re == nil {
				return true, fmt.Sprintf("ścieżka %s → %d", p.Path, p.Status), ""
			}
			content := string(p.body)
			if content == "" {
				content = p.Excerpt
			}
			if ok, v := find(content + "\n" + p.Title); ok {
				return true, fmt.Sprintf("ścieżka %s → %d (treść pasuje)", p.Path, p.Status), v
			}
		}
	case MCert:
		if h == nil || h.TLS == nil {
			return false, "", ""
		}
		t := h.TLS
		var fields []string
		switch m.Field {
		case "subject":
			fields = []string{t.Subject}
		case "issuer":
			fields = []string{t.Issuer}
		case "san":
			fields = t.SANs
		default:
			fields = append([]string{t.Subject, t.Issuer}, t.SANs...)
		}
		for _, f := range fields {
			if ok, v := find(f); ok {
				return true, "certyfikat: " + clip(f, 80), v
			}
		}
	case MHostname:
		cands := []string{ev.Hostname}
		if h != nil {
			cands = append(cands, h.VHost)
			if h.TLS != nil {
				cands = append(cands, h.TLS.SANs...)
				cands = append(cands, h.TLS.SubjectCN)
			}
		}
		for _, c := range cands {
			if ok, v := find(c); ok {
				return true, "nazwa hosta: " + c, v
			}
		}
	case MBanner:
		if ok, v := find(ev.Banner); ok {
			return true, "baner: " + clip(ev.Banner, 60), v
		}
	case MProduct:
		s := strings.TrimSpace(ev.Service + " " + ev.Product + " " + ev.Version)
		if ok, v := find(s); ok {
			if v == "" && m.re.SubexpIndex("version") < 0 {
				v = ""
			}
			return true, "usługa: " + clip(s, 60), v
		}
	case MPort:
		for _, v := range strings.Split(m.Value, ",") {
			if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && p == ev.Port {
				return true, fmt.Sprintf("port %d", ev.Port), ""
			}
		}
	case MURL:
		if h != nil {
			cands := []string{h.FinalURL}
			for _, r := range h.Redirects {
				cands = append(cands, r.To)
			}
			for _, c := range cands {
				if ok, v := find(c); ok {
					return true, "URL: " + clip(c, 80), v
				}
			}
		}
	}
	return false, "", ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Match evaluates the signature. Confidence combines matched weights as
// independent evidence: 1 - Π(1 - w_i). Negated matchers veto the detection.
func (s *Signature) Match(ev *Evidence) *Detection {
	if !s.compiled {
		if err := s.Compile(); err != nil {
			return nil
		}
	}
	miss := 1.0
	var evs []string
	version := ""
	hits, needed := 0, 0
	for i := range s.Def.Matchers {
		m := &s.Def.Matchers[i]
		ok, e, v := m.match(ev)
		if m.Negate {
			if ok {
				return nil
			}
			continue
		}
		needed++
		if !ok {
			continue
		}
		hits++
		miss *= 1 - m.Weight
		evs = append(evs, e)
		if version == "" && v != "" {
			version = v
		}
	}
	if hits == 0 || (s.Def.Condition == "all" && hits < needed) {
		return nil
	}
	conf := int(math.Round((1 - miss) * 100))
	if conf < s.Def.MinConfidence {
		return nil
	}
	return &Detection{Name: s.Name, Category: s.Category, Version: version, Confidence: conf, SignatureID: s.ID,
		Evidence: evs, Curiosity: s.Def.Curiosity, Tags: s.Def.Tags}
}

// Set is a compiled collection of enabled signatures.
type Set struct {
	sigs  []*Signature
	paths []string
}

func NewSet(sigs []*Signature) (*Set, []error) {
	var errs []error
	set := &Set{}
	pathFreq := map[string]int{}
	for _, s := range sigs {
		if !s.Enabled {
			continue
		}
		if err := s.Compile(); err != nil {
			errs = append(errs, err)
			continue
		}
		set.sigs = append(set.sigs, s)
		for _, m := range s.Def.Matchers {
			if m.Type == MPath {
				pathFreq[m.Path]++
			}
		}
	}
	for p := range pathFreq {
		set.paths = append(set.paths, p)
	}
	sort.Slice(set.paths, func(i, j int) bool {
		if pathFreq[set.paths[i]] != pathFreq[set.paths[j]] {
			return pathFreq[set.paths[i]] > pathFreq[set.paths[j]]
		}
		return set.paths[i] < set.paths[j]
	})
	return set, errs
}

// Paths returns the passive path probes required by enabled signatures,
// most-used first.
func (s *Set) Paths() []string { return s.paths }

func (s *Set) Len() int { return len(s.sigs) }

// Evaluate returns detections sorted by confidence, de-duplicated by name.
func (s *Set) Evaluate(ev *Evidence) []Detection {
	byName := map[string]*Detection{}
	for _, sig := range s.sigs {
		d := sig.Match(ev)
		if d == nil {
			continue
		}
		if prev, ok := byName[d.Name]; ok {
			// combine independent signatures for the same technology
			c := 1 - (1-float64(prev.Confidence)/100)*(1-float64(d.Confidence)/100)
			prev.Confidence = int(math.Round(c * 100))
			prev.Evidence = append(prev.Evidence, d.Evidence...)
			if prev.Version == "" {
				prev.Version = d.Version
			}
			if d.Curiosity > prev.Curiosity {
				prev.Curiosity = d.Curiosity
			}
			continue
		}
		byName[d.Name] = d
	}
	out := make([]Detection, 0, len(byName))
	for _, d := range byName {
		if d.Confidence > 99 {
			d.Confidence = 99
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})
	return out
}
