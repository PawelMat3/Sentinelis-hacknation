// Package fingerprint collects passive HTTP/HTTPS metadata (status, redirects,
// title, headers, cookies, TLS certificate, favicon hash, a bounded set of
// GET-only path probes) and evaluates detection signatures against it.
//
// Safety contract: only GET requests, no credentials, no form submission, no
// query payloads, bounded body size, off-host redirects are recorded but never
// followed, every request passes the per-run rate limiter.
package fingerprint

import "time"

type Redirect struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status"`
}

type Cookie struct {
	Name     string `json:"name"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httponly"`
	SameSite string `json:"samesite,omitempty"`
	// Only a short prefix of the value is kept (data minimisation) - enough to
	// recognise formats, not enough to hijack sessions.
	ValuePrefix string `json:"value_prefix,omitempty"`
	ValueLen    int    `json:"value_len"`
}

type TLSInfo struct {
	Version       string    `json:"version"`
	Cipher        string    `json:"cipher"`
	Subject       string    `json:"subject"`
	SubjectCN     string    `json:"subject_cn"`
	Issuer        string    `json:"issuer"`
	IssuerCN      string    `json:"issuer_cn"`
	SANs          []string  `json:"sans,omitempty"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Serial        string    `json:"serial"`
	SigAlg        string    `json:"sig_alg"`
	KeyType       string    `json:"key_type"`
	SHA256        string    `json:"sha256"`
	SelfSigned    bool      `json:"self_signed"`
	Expired       bool      `json:"expired"`
	NotYetValid   bool      `json:"not_yet_valid"`
	DaysLeft      int       `json:"days_left"`
	HostnameMatch bool      `json:"hostname_match"`
}

type PathResult struct {
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Title    string `json:"title,omitempty"`
	Length   int    `json:"length"`
	Location string `json:"location,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	Soft404  bool   `json:"soft_404,omitempty"` // same page as "/" - ignored by path signatures
	body     []byte
}

type HTTPInfo struct {
	URL         string              `json:"url"`
	FinalURL    string              `json:"final_url"`
	Scheme      string              `json:"scheme"`
	VHost       string              `json:"vhost,omitempty"`
	StatusCode  int                 `json:"status"`
	Title       string              `json:"title"`
	Headers     map[string][]string `json:"headers"`
	Cookies     []Cookie            `json:"cookies,omitempty"`
	Redirects   []Redirect          `json:"redirects,omitempty"`
	BodyLen     int                 `json:"body_len"`
	BodySHA256  string              `json:"body_sha256,omitempty"`
	BodyExcerpt string              `json:"body_excerpt,omitempty"`
	Generator   string              `json:"generator,omitempty"`
	TLS         *TLSInfo            `json:"tls,omitempty"`
	FaviconHash string              `json:"favicon_hash,omitempty"`
	FaviconURL  string              `json:"favicon_url,omitempty"`
	Paths       []PathResult        `json:"paths,omitempty"`
	Error       string              `json:"error,omitempty"`
	DurationMS  int64               `json:"duration_ms"`
	ResponseMS  int64               `json:"response_ms,omitempty"` // main page: request -> full body (latency tracking)
	Requests    int                 `json:"requests"`
	body        []byte
}

// Header returns the first value of a header (case-insensitive).
func (h *HTTPInfo) Header(name string) string {
	if h == nil {
		return ""
	}
	for k, v := range h.Headers {
		if equalFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// Body returns the full (bounded) body of the main page, when still in memory.
func (h *HTTPInfo) Body() []byte { return h.body }

// SetBody is used by importers/tests to attach a body for signature matching.
func (h *HTTPInfo) SetBody(b []byte) { h.body = b }

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Evidence is everything a signature may look at for one service.
type Evidence struct {
	Address  string
	Hostname string
	Port     int
	Service  string
	Product  string
	Version  string
	Banner   string
	HTTP     *HTTPInfo
}

// Detection is a matched signature with weighted confidence.
type Detection struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Version     string   `json:"version,omitempty"`
	Confidence  int      `json:"confidence"` // 0..100
	SignatureID int64    `json:"signature_id,omitempty"`
	Evidence    []string `json:"evidence"`
	Curiosity   int      `json:"curiosity,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}
