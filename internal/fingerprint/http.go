package fingerprint

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"asi/internal/ratelimit"
)

// Prober performs passive, bounded HTTP(S) fingerprinting of one service.
type Prober struct {
	UserAgent    string
	Timeout      time.Duration
	MaxBody      int64
	MaxPaths     int
	MaxRedirects int
	Limiter      *ratelimit.Limiter
	// TransportFor lets the simulator / tests inject a RoundTripper. When nil a
	// real network transport dialing dialAddr is used.
	TransportFor func(dialAddr, sni string) http.RoundTripper
	Now          func() time.Time
}

func NewProber(l *ratelimit.Limiter) *Prober {
	return &Prober{
		UserAgent:    "Sentinelis/1.0 (+passive attack-surface inventory; contact: security team)",
		Timeout:      8 * time.Second,
		MaxBody:      512 << 10,
		MaxPaths:     32,
		MaxRedirects: 5,
		Limiter:      l,
	}
}

// Target identifies a web service to fingerprint.
type Target struct {
	Address string
	Port    int
	Scheme  string // "", "http" or "https"
	VHost   string // hostname to use for Host header / SNI (when scanned by name)
	Paths   []string
	TLSHint bool // nmap reported ssl tunnel / https service
}

var webPorts = map[int]bool{80: true, 81: true, 443: true, 591: true, 2082: true, 2083: true, 2086: true, 2087: true, 3000: true,
	4443: true, 5000: true, 5001: true, 5601: true, 7001: true, 7443: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true,
	8443: true, 8800: true, 8888: true, 9000: true, 9090: true, 9200: true, 9443: true, 10000: true, 10443: true}

var tlsPorts = map[int]bool{443: true, 2083: true, 2087: true, 4443: true, 5001: true, 7443: true, 8443: true, 9443: true, 10443: true}

// IsWebCandidate decides whether a discovered port should be HTTP-probed.
func IsWebCandidate(port int, service, tunnel string) bool {
	s := strings.ToLower(service)
	if strings.Contains(s, "http") || s == "https" || strings.Contains(s, "ssl/http") || s == "www" {
		return true
	}
	if s == "" || s == "unknown" || strings.HasSuffix(s, "?") || tunnel == "ssl" {
		return webPorts[port] || tunnel == "ssl"
	}
	return webPorts[port] && (s == "tcpwrapped" || strings.Contains(s, "proxy"))
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func hostPort(h string, port int) string { return net.JoinHostPort(h, strconv.Itoa(port)) }

func (p *Prober) transport(dialAddr, sni string) http.RoundTripper {
	if p.TransportFor != nil {
		return p.TransportFor(dialAddr, sni)
	}
	d := &net.Dialer{Timeout: p.Timeout}
	suites := []uint16{}
	for _, c := range tls.CipherSuites() {
		suites = append(suites, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() { // legacy IoT still uses them; we only observe
		suites = append(suites, c.ID)
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, dialAddr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // we inspect the certificate ourselves
			ServerName:         sni,
			MinVersion:         tls.VersionTLS10,
			CipherSuites:       suites,
		},
		TLSHandshakeTimeout:   p.Timeout,
		ResponseHeaderTimeout: p.Timeout,
		MaxIdleConnsPerHost:   1,
		DisableCompression:    false,
		ForceAttemptHTTP2:     false,
	}
}

// Probe fingerprints one service. It never returns nil.
func (p *Prober) Probe(ctx context.Context, t Target) *HTTPInfo {
	start := time.Now()
	schemes := []string{"http", "https"}
	if t.Scheme != "" {
		schemes = []string{t.Scheme}
	} else if t.TLSHint || tlsPorts[t.Port] {
		schemes = []string{"https", "http"}
	}
	// Take the first scheme that gives a real page. An error or a 4xx/5xx on
	// the hinted scheme (e.g. nmap guessed ssl/http, the TLS side answers 404
	// while the plain side serves the app) makes us try the other one and keep
	// the better answer.
	var info *HTTPInfo
	for _, sc := range schemes {
		cand := p.probeScheme(ctx, sc, t)
		if info == nil || better(cand, info) {
			info = cand
		}
		if (info.Error == "" && info.StatusCode < 400) || ctx.Err() != nil {
			break
		}
	}
	info.DurationMS = time.Since(start).Milliseconds()
	return info
}

// better reports whether probe result a is more useful than b.
func better(a, b *HTTPInfo) bool {
	if (a.Error == "") != (b.Error == "") {
		return a.Error == ""
	}
	return a.Error == "" && a.StatusCode < 400 && b.StatusCode >= 400
}

type session struct {
	p      *Prober
	client *http.Client
	info   *HTTPInfo
	host   string // host[:port] used in URLs
	base   *url.URL
}

func (p *Prober) probeScheme(ctx context.Context, scheme string, t Target) *HTTPInfo {
	urlHost := t.Address
	sni := ""
	if t.VHost != "" {
		urlHost = t.VHost
		if net.ParseIP(t.VHost) == nil {
			sni = t.VHost
		}
	}
	defPort := (scheme == "http" && t.Port == 80) || (scheme == "https" && t.Port == 443)
	hp := urlHost
	if !defPort || strings.Contains(urlHost, ":") {
		hp = hostPort(urlHost, t.Port)
	}
	base, _ := url.Parse(scheme + "://" + hp + "/")
	info := &HTTPInfo{URL: base.String(), Scheme: scheme, VHost: t.VHost, Headers: map[string][]string{}}
	rt := p.transport(hostPort(t.Address, t.Port), sni)
	if tr, ok := rt.(*http.Transport); ok {
		defer tr.CloseIdleConnections()
	}
	s := &session{p: p, info: info, base: base, host: hp,
		client: &http.Client{Transport: rt, Timeout: p.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

	// 1. Main page with manual, same-origin-only redirect following.
	cur := base.String()
	var resp *http.Response
	var body []byte
	for hop := 0; ; hop++ {
		r, b, err := s.get(ctx, cur)
		if err != nil {
			info.Error = shortErr(err)
			return info
		}
		resp, body = r, b
		collectCookies(info, r)
		if info.TLS == nil && r.TLS != nil {
			info.TLS = tlsInfo(r.TLS, t.VHost, t.Address, p.now())
		}
		loc := r.Header.Get("Location")
		if r.StatusCode < 300 || r.StatusCode > 399 || loc == "" || hop >= p.MaxRedirects {
			break
		}
		next, err := url.Parse(cur)
		if err == nil {
			next, err = next.Parse(loc)
		}
		if err != nil {
			break
		}
		info.Redirects = append(info.Redirects, Redirect{From: cur, To: next.String(), Status: r.StatusCode})
		if next.Scheme != base.Scheme || next.Host != base.Host {
			break // off-origin: record only, never follow
		}
		cur = next.String()
	}
	info.FinalURL = cur
	info.StatusCode = resp.StatusCode
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		info.Headers[k] = v
	}
	info.body = body
	info.BodyLen = len(body)
	if len(body) > 0 {
		h := sha256.Sum256(body)
		info.BodySHA256 = hex.EncodeToString(h[:])
	}
	info.Title = ExtractTitle(body)
	info.Generator = metaGenerator(body)
	info.BodyExcerpt = excerpt(body, 1024)

	// 2. Favicon (declared icon or /favicon.ico), same origin only.
	favURL := base.ResolveReference(&url.URL{Path: "/favicon.ico"})
	if href := iconHref(body); href != "" {
		if u, err := url.Parse(cur); err == nil {
			if fu, err := u.Parse(href); err == nil && fu.Host == base.Host && fu.Scheme == base.Scheme {
				favURL = fu
			}
		}
	}
	if r, b, err := s.get(ctx, favURL.String()); err == nil && r.StatusCode == 200 && len(b) > 0 && !looksHTML(b) {
		info.FaviconHash = FaviconHash(b)
		info.FaviconURL = favURL.String()
	}

	// 3. Passive path probes (GET only, no redirects followed).
	n := 0
	for _, path := range t.Paths {
		if n >= p.MaxPaths || ctx.Err() != nil {
			break
		}
		if !SafePath(path) {
			continue
		}
		n++
		u := base.ResolveReference(&url.URL{Path: path})
		r, b, err := s.get(ctx, u.String())
		if err != nil {
			continue
		}
		pr := PathResult{Path: path, Status: r.StatusCode, Length: len(b), Title: ExtractTitle(b), Location: r.Header.Get("Location"), Excerpt: excerpt(b, 256), body: b}
		pr.Soft404 = softEcho(info, pr)
		info.Paths = append(info.Paths, pr)
	}
	return info
}

func (s *session) get(ctx context.Context, u string) (*http.Response, []byte, error) {
	if err := s.p.Limiter.Wait(ctx); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", s.p.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	s.info.Requests++
	t0 := time.Now() // after the rate limiter: measures the service, not our pacing
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, s.p.MaxBody))
	if s.info.ResponseMS == 0 {
		s.info.ResponseMS = max(1, time.Since(t0).Milliseconds()) // first (main page) request
	}
	return resp, b, nil
}

// softEcho detects "soft 404": the server answers every path with its main
// page (single-page apps, front controllers such as Adminer). Such answers
// say nothing about the path, so path signatures must not match them.
func softEcho(info *HTTPInfo, pr PathResult) bool {
	if pr.Status != 200 || info.StatusCode != 200 {
		return false
	}
	if len(pr.body) > 0 && info.BodySHA256 != "" {
		h := sha256.Sum256(pr.body)
		if hex.EncodeToString(h[:]) == info.BodySHA256 {
			return true
		}
	}
	if pr.Title == "" || pr.Title != info.Title {
		return false
	}
	d := pr.Length - info.BodyLen
	if d < 0 {
		d = -d
	}
	return d <= max(256, info.BodyLen/10) // same page, only per-request tokens differ
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

var safePathRe = regexp.MustCompile(`^/[A-Za-z0-9._~\-/]{0,120}$`)

// SafePath enforces that signature paths are plain resource paths: no query
// strings, no traversal, no encoded payloads.
func SafePath(p string) bool { return safePathRe.MatchString(p) && !strings.Contains(p, "..") }

func collectCookies(info *HTTPInfo, r *http.Response) {
	for _, c := range r.Cookies() {
		dup := false
		for _, e := range info.Cookies {
			if e.Name == c.Name {
				dup = true
			}
		}
		if dup {
			continue
		}
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		pref := c.Value
		if len(pref) > 6 {
			pref = pref[:6] + "…"
		}
		info.Cookies = append(info.Cookies, Cookie{Name: c.Name, Domain: c.Domain, Path: c.Path, Secure: c.Secure,
			HttpOnly: c.HttpOnly, SameSite: ss, ValuePrefix: pref, ValueLen: len(c.Value)})
	}
}

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	genRe   = regexp.MustCompile(`(?is)<meta[^>]+name=["']?generator["']?[^>]*content=["']([^"']+)["']|<meta[^>]+content=["']([^"']+)["'][^>]*name=["']?generator`)
	iconRe  = regexp.MustCompile(`(?is)<link[^>]+rel=["']?(?:shortcut )?icon["']?[^>]*href=["']([^"']+)["']|<link[^>]+href=["']([^"']+)["'][^>]*rel=["']?(?:shortcut )?icon`)
	wsRe    = regexp.MustCompile(`\s+`)
)

// ExtractTitle returns the decoded, whitespace-collapsed <title>.
func ExtractTitle(b []byte) string {
	m := titleRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(wsRe.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func metaGenerator(b []byte) string {
	m := genRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	if len(m[1]) > 0 {
		return string(m[1])
	}
	return string(m[2])
}

func iconHref(b []byte) string {
	m := iconRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	if len(m[1]) > 0 {
		return html.UnescapeString(string(m[1]))
	}
	return html.UnescapeString(string(m[2]))
}

func looksHTML(b []byte) bool {
	n := len(b)
	if n > 256 {
		n = 256
	}
	s := strings.ToLower(string(b[:n]))
	return strings.Contains(s, "<html") || strings.Contains(s, "<!doctype")
}

func excerpt(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.ToValidUTF8(string(b), "�")
}

var tlsVersions = map[uint16]string{tls.VersionTLS10: "TLS1.0", tls.VersionTLS11: "TLS1.1", tls.VersionTLS12: "TLS1.2", tls.VersionTLS13: "TLS1.3"}

// TLSFromCert builds TLSInfo from a certificate (used by prober and simulator).
func TLSFromCert(c *x509.Certificate, version uint16, cipher uint16, vhost, addr string, now time.Time) *TLSInfo {
	sum := sha256.Sum256(c.Raw)
	ti := &TLSInfo{
		Version:   tlsVersions[version],
		Cipher:    tls.CipherSuiteName(cipher),
		Subject:   c.Subject.String(),
		SubjectCN: c.Subject.CommonName,
		Issuer:    c.Issuer.String(),
		IssuerCN:  c.Issuer.CommonName,
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
		Serial:    c.SerialNumber.Text(16),
		SigAlg:    c.SignatureAlgorithm.String(),
		KeyType:   c.PublicKeyAlgorithm.String(),
		SHA256:    hex.EncodeToString(sum[:]),
	}
	ti.SANs = append(ti.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		ti.SANs = append(ti.SANs, ip.String())
	}
	ti.SelfSigned = c.Subject.String() == c.Issuer.String() && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	ti.Expired = now.After(c.NotAfter)
	ti.NotYetValid = now.Before(c.NotBefore)
	ti.DaysLeft = int(c.NotAfter.Sub(now).Hours() / 24)
	name := vhost
	if name == "" {
		name = addr
	}
	ti.HostnameMatch = c.VerifyHostname(name) == nil
	if ti.Version == "" && version != 0 {
		ti.Version = fmt.Sprintf("0x%04x", version)
	}
	return ti
}

func tlsInfo(cs *tls.ConnectionState, vhost, addr string, now time.Time) *TLSInfo {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil
	}
	return TLSFromCert(cs.PeerCertificates[0], cs.Version, cs.CipherSuite, vhost, addr, now)
}
