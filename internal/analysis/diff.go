package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Snapshot is the comparable state of a service in one scan run. Volatile
// values (dates, session cookie values, response time) are intentionally
// excluded so that only meaningful changes are reported.
type Snapshot struct {
	Name       string   `json:"name"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	Status     int      `json:"status,omitempty"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"server,omitempty"`
	PoweredBy  string   `json:"powered_by,omitempty"`
	FinalURL   string   `json:"final_url,omitempty"`
	Tech       []string `json:"tech,omitempty"` // "Name version" sorted
	Cookies    []string `json:"cookies,omitempty"`
	CertSHA256 string   `json:"cert_sha256,omitempty"`
	CertIssuer string   `json:"cert_issuer,omitempty"`
	CertExpiry string   `json:"cert_expiry,omitempty"`
	Favicon    string   `json:"favicon,omitempty"`
	// RespMS is the main page response time. It is not part of the digest
	// (it varies on every scan); LatencyShift reports only large shifts.
	RespMS int64 `json:"resp_ms,omitempty"`
}

func (s Snapshot) Normalize() Snapshot {
	sort.Strings(s.Tech)
	sort.Strings(s.Cookies)
	return s
}

// Digest is a stable short hash of the snapshot.
func (s Snapshot) Digest() string {
	s.RespMS = 0
	b, _ := json.Marshal(s.Normalize())
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

var fieldLabels = map[string]string{"name": "usługa", "product": "produkt", "version": "wersja", "status": "kod HTTP",
	"title": "tytuł", "server": "Server", "powered_by": "X-Powered-By", "final_url": "przekierowanie", "tech": "technologie",
	"cookies": "ciasteczka", "cert_sha256": "certyfikat", "cert_issuer": "wystawca cert.", "cert_expiry": "ważność cert.", "favicon": "favicon",
	"resp_ms": "czas odpowiedzi"}

func Label(field string) string {
	if l, ok := fieldLabels[field]; ok {
		return l
	}
	return field
}

// DiffSnapshots lists changed fields between a (old) and b (new).
func DiffSnapshots(a, b Snapshot) []FieldChange {
	a, b = a.Normalize(), b.Normalize()
	var out []FieldChange
	cmp := func(f, x, y string) {
		if x != y {
			out = append(out, FieldChange{f, x, y})
		}
	}
	cmp("name", a.Name, b.Name)
	cmp("product", a.Product, b.Product)
	cmp("version", a.Version, b.Version)
	if a.Status != b.Status {
		cmp("status", strconv.Itoa(a.Status), strconv.Itoa(b.Status))
	}
	cmp("title", a.Title, b.Title)
	cmp("server", a.Server, b.Server)
	cmp("powered_by", a.PoweredBy, b.PoweredBy)
	cmp("final_url", a.FinalURL, b.FinalURL)
	cmp("tech", strings.Join(a.Tech, ", "), strings.Join(b.Tech, ", "))
	cmp("cookies", strings.Join(a.Cookies, ", "), strings.Join(b.Cookies, ", "))
	if a.CertSHA256 != b.CertSHA256 {
		cmp("cert_sha256", short(a.CertSHA256), short(b.CertSHA256))
	}
	cmp("cert_issuer", a.CertIssuer, b.CertIssuer)
	cmp("cert_expiry", a.CertExpiry, b.CertExpiry)
	cmp("favicon", a.Favicon, b.Favicon)
	return out
}

// LatencyShift reports a significant change of the HTTP response time between
// two scans: at least 3x slower/faster and at least 250 ms apart, so normal
// jitter of real services does not produce changes.
func LatencyShift(oldMS, newMS int64) (FieldChange, bool) {
	if oldMS <= 0 || newMS <= 0 {
		return FieldChange{}, false
	}
	hi, lo := max(oldMS, newMS), min(oldMS, newMS)
	if hi < 3*lo || hi-lo < 250 {
		return FieldChange{}, false
	}
	return FieldChange{"resp_ms", fmtMS(oldMS), fmtMS(newMS)}, true
}

func fmtMS(ms int64) string {
	if ms >= 10000 {
		return strconv.FormatInt(ms/1000, 10) + " s"
	}
	return strconv.FormatInt(ms, 10) + " ms"
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// ChangeSeverity ranks a service change for reporting.
func ChangeSeverity(ch []FieldChange) string {
	for _, c := range ch {
		switch c.Field {
		case "tech", "product", "name", "cert_sha256", "final_url":
			return "medium"
		}
	}
	return "low"
}

// CertExpiry formats an expiry date for snapshots.
func CertExpiry(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}
