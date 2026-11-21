package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
)

// Insight is a heuristic observation about headers, cookies or TLS that is not
// a technology detection but matters for triage ("interesting header/cookie").
type Insight struct {
	Code   string `json:"code"`
	Kind   string `json:"kind"` // header | cookie | tls
	Text   string `json:"text"`
	Points int    `json:"points"`
}

var (
	versionDigits  = regexp.MustCompile(`\d+\.\d+`)
	sessionCookie  = regexp.MustCompile(`(?i)sess|sid|auth|token|jwt|login`)
	infraHeaderRe  = regexp.MustCompile(`(?i)^(x-backend-server|x-upstream|x-served-by|x-server|x-host|x-forwarded-server|x-internal|x-real-server|x-node|x-pod|x-instance|x-cache-host|x-debug.*|x-env.*|x-environment)$`)
	interestingHdr = []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime", "X-Jenkins", "kbn-version", "X-OWA-Version"}
)

// SlowResponseMS is the main page response time reported as an insight.
const SlowResponseMS = 400

// Insights derives header/cookie/TLS observations from collected HTTP data.
func Insights(h *HTTPInfo) []Insight {
	if h == nil || h.Error != "" {
		return nil
	}
	var out []Insight
	// Version disclosure
	for _, name := range append([]string{"Server"}, interestingHdr...) {
		v := h.Header(name)
		if v != "" && versionDigits.MatchString(v) {
			out = append(out, Insight{"version-disclosure", "header", fmt.Sprintf("Ujawnienie wersji w nagłówku %s: %s", name, clip(v, 60)), 4})
			break
		}
	}
	// Infrastructure-revealing headers
	for k, v := range h.Headers {
		if infraHeaderRe.MatchString(k) {
			out = append(out, Insight{"infra-header", "header", fmt.Sprintf("Nagłówek ujawniający infrastrukturę: %s: %s", k, clip(strings.Join(v, ","), 50)), 6})
		}
	}
	// CORS
	if h.Header("Access-Control-Allow-Origin") == "*" && strings.EqualFold(h.Header("Access-Control-Allow-Credentials"), "true") {
		out = append(out, Insight{"cors-wildcard-credentials", "header", "CORS: Allow-Origin * razem z Allow-Credentials", 10})
	}
	if h.Scheme == "https" && h.StatusCode > 0 && h.StatusCode < 400 {
		var missing []string
		for _, n := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
			if h.Header(n) == "" {
				missing = append(missing, n)
			}
		}
		if len(missing) >= 3 {
			out = append(out, Insight{"missing-security-headers", "header", "Brak nagłówków bezpieczeństwa: " + strings.Join(missing, ", "), 3})
		}
	}
	// Latency (e.g. a throttling proxy, overloaded backend, tarpit)
	if h.ResponseMS >= SlowResponseMS {
		out = append(out, Insight{"slow-response", "http", fmt.Sprintf("Wolna odpowiedź HTTP: %d ms (strona główna)", h.ResponseMS), 1})
	}
	// Cookies
	for _, c := range h.Cookies {
		if h.Scheme == "https" && !c.Secure && sessionCookie.MatchString(c.Name) {
			out = append(out, Insight{"cookie-not-secure", "cookie", "Ciasteczko sesyjne bez flagi Secure: " + c.Name, 4})
		}
		if !c.HttpOnly && sessionCookie.MatchString(c.Name) {
			out = append(out, Insight{"cookie-not-httponly", "cookie", "Ciasteczko sesyjne bez flagi HttpOnly: " + c.Name, 3})
		}
	}
	// TLS
	if t := h.TLS; t != nil {
		switch {
		case t.Expired:
			out = append(out, Insight{"tls-expired", "tls", fmt.Sprintf("Certyfikat TLS wygasł %s", t.NotAfter.Format("2006-01-02")), 15})
		case t.NotYetValid:
			out = append(out, Insight{"tls-not-yet-valid", "tls", "Certyfikat TLS jeszcze nieważny", 8})
		case t.DaysLeft <= 14:
			out = append(out, Insight{"tls-expiring", "tls", fmt.Sprintf("Certyfikat TLS wygasa za %d dni", t.DaysLeft), 8})
		}
		if t.SelfSigned {
			out = append(out, Insight{"tls-self-signed", "tls", "Certyfikat samopodpisany: " + clip(t.SubjectCN, 60), 8})
		}
		if !t.HostnameMatch && h.VHost != "" {
			out = append(out, Insight{"tls-hostname-mismatch", "tls", "Certyfikat nie pasuje do nazwy " + h.VHost, 5})
		}
		if t.Version == "TLS1.0" || t.Version == "TLS1.1" {
			out = append(out, Insight{"tls-legacy-protocol", "tls", "Przestarzały protokół " + t.Version, 6})
		}
		if strings.Contains(strings.ToUpper(t.SigAlg), "SHA1") || strings.Contains(strings.ToUpper(t.SigAlg), "MD5") {
			out = append(out, Insight{"tls-weak-signature", "tls", "Słaby algorytm podpisu certyfikatu: " + t.SigAlg, 5})
		}
	}
	return out
}

var wpComponentRe = regexp.MustCompile(`(?i)/wp-content/(plugins|themes)/([a-z0-9_\-]{2,60})/[^"'\s>]*?\?ver=([0-9][0-9.]{0,15})`)

// Components extracts versioned CMS components (WordPress plugins and themes)
// referenced by the page source - purely passive, from the already fetched HTML.
func Components(h *HTTPInfo) []Detection {
	if h == nil {
		return nil
	}
	body := string(h.body)
	if body == "" {
		body = h.BodyExcerpt
	}
	seen := map[string]bool{}
	var out []Detection
	for _, m := range wpComponentRe.FindAllStringSubmatch(body, 60) {
		kind, name, ver := strings.ToLower(m[1]), strings.ToLower(m[2]), strings.TrimSuffix(m[3], ".")
		label := "Wtyczka WordPress: " + name
		if kind == "themes" {
			label = "Motyw WordPress: " + name
		}
		if seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, Detection{Name: label, Category: "cms-plugin", Version: ver, Confidence: 85,
			Evidence: []string{"zasób /wp-content/" + kind + "/" + name + "/…?ver=" + ver + " w kodzie strony"}})
	}
	return out
}
