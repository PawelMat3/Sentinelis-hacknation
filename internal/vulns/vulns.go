// Package vulns maps detected products+versions to CPE names and looks up
// known vulnerabilities (CVE) in the NIST NVD API 2.0. It is purely passive:
// only the product name and version leave the system, the scanned host is
// never contacted again.
//
// Caveat shown in the UI: matching is version-based, so distribution
// back-ports (e.g. Ubuntu patching OpenSSH without changing the version) can
// produce false positives - results are "to verify", not confirmed findings.
package vulns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Vuln is one known vulnerability applicable to a product version.
type Vuln struct {
	CVE       string  `json:"cve"`
	CVSS      float64 `json:"cvss"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	Published string  `json:"published"`
	CPE       string  `json:"cpe"`
	Product   string  `json:"product"`
	Version   string  `json:"version"`
}

// cpeMap: product / technology name (lowercase) -> NVD vendor:product list.
var cpeMap = map[string][]string{
	"wordpress":                      {"wordpress:wordpress"},
	"joomla":                         {"joomla:joomla\\!"},
	"drupal":                         {"drupal:drupal"},
	"typo3":                          {"typo3:typo3"},
	"moodle":                         {"moodle:moodle"},
	"mediawiki":                      {"mediawiki:mediawiki"},
	"prestashop":                     {"prestashop:prestashop"},
	"ghost":                          {"ghost:ghost"},
	"nginx":                          {"f5:nginx", "nginx:nginx"},
	"apache httpd":                   {"apache:http_server"},
	"microsoft iis":                  {"microsoft:internet_information_services"},
	"microsoft iis httpd":            {"microsoft:internet_information_services"},
	"lighttpd":                       {"lighttpd:lighttpd"},
	"openresty":                      {"openresty:openresty"},
	"apache tomcat":                  {"apache:tomcat"},
	"jetty":                          {"eclipse:jetty"},
	"php":                            {"php:php"},
	"jenkins":                        {"jenkins:jenkins"},
	"grafana":                        {"grafana:grafana"},
	"kibana":                         {"elastic:kibana"},
	"elasticsearch":                  {"elastic:elasticsearch"},
	"phpmyadmin":                     {"phpmyadmin:phpmyadmin"},
	"webmin":                         {"webmin:webmin"},
	"openssh":                        {"openbsd:openssh"},
	"vsftpd":                         {"beasts:vsftpd"},
	"proftpd":                        {"proftpd:proftpd"},
	"mysql":                          {"oracle:mysql"},
	"mariadb":                        {"mariadb:mariadb"},
	"postgresql":                     {"postgresql:postgresql"},
	"postgresql db":                  {"postgresql:postgresql"},
	"redis":                          {"redis:redis"},
	"redis key-value store":          {"redis:redis"},
	"samba smbd":                     {"samba:samba"},
	"exim smtpd":                     {"exim:exim"},
	"dovecot imapd":                  {"dovecot:dovecot"},
	"werkzeug (serwer deweloperski)": {"palletsprojects:werkzeug"},
	"roundcube":                      {"roundcube:webmail"},
	"zabbix":                         {"zabbix:zabbix"},
	"nextcloud":                      {"nextcloud:nextcloud_server"},
	"gitlab":                         {"gitlab:gitlab"},
	"confluence":                     {"atlassian:confluence_server", "atlassian:confluence_data_center"},
	"angular":                        {"angular:angular"},
	"express":                        {"expressjs:express"},
}

var versionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})`)

// CPEs returns CPE 2.3 match strings for a product and version, or nil when
// the product is unknown or the version is too vague to be meaningful.
func CPEs(product, version string) []string {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return nil
	}
	v := m[1]
	if !strings.Contains(v, ".") { // "Drupal 10" / "PHP 7" - too vague
		return nil
	}
	for _, pre := range []string{"Wtyczka WordPress: ", "Motyw WordPress: "} {
		if strings.HasPrefix(product, pre) {
			slug := strings.ReplaceAll(strings.TrimPrefix(product, pre), "-", "_")
			// NVD lists WordPress extensions with target_sw=wordpress; vendor unknown -> wildcard
			return []string{"cpe:2.3:a:*:" + slug + ":" + v + ":*:*:*:*:wordpress:*:*"}
		}
	}
	vp := cpeMap[strings.ToLower(strings.TrimSpace(product))]
	var out []string
	for _, x := range vp {
		out = append(out, "cpe:2.3:a:"+x+":"+v)
	}
	return out
}

// Cache persists NVD answers (the API is rate limited).
type Cache interface {
	GetCVE(ctx context.Context, cpe string, maxAge time.Duration) ([]Vuln, bool)
	PutCVE(ctx context.Context, cpe string, v []Vuln)
}

// Client queries the NVD API 2.0 with rate limiting and caching.
type Client struct {
	BaseURL string
	APIKey  string // optional (ASI_NVD_API_KEY): raises the limit 5 -> 50 req/30s
	HTTP    *http.Client
	Cache   Cache
	MaxAge  time.Duration

	mu   sync.Mutex
	last time.Time
}

func NewClient(apiKey string, cache Cache) *Client {
	return &Client{BaseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0", APIKey: apiKey, Cache: cache,
		HTTP: &http.Client{Timeout: 40 * time.Second}, MaxAge: 7 * 24 * time.Hour}
}

func (c *Client) wait(ctx context.Context) error {
	gap := 6500 * time.Millisecond
	if c.APIKey != "" {
		gap = 700 * time.Millisecond
	}
	c.mu.Lock()
	d := time.Until(c.last.Add(gap))
	if d < 0 {
		d = 0
	}
	c.last = time.Now().Add(d)
	c.mu.Unlock()
	if d == 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type nvdResp struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
				BaseSeverity string `json:"baseSeverity"` // v2 keeps it outside cvssData
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Parse converts an NVD API response into Vulns (highest CVSS first).
func Parse(b []byte, cpe string) ([]Vuln, error) {
	var r nvdResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	out := []Vuln{}
	for _, v := range r.Vulnerabilities {
		x := Vuln{CVE: v.CVE.ID, CPE: cpe}
		if len(v.CVE.Published) >= 10 {
			x.Published = v.CVE.Published[:10]
		}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				x.Summary = d.Value
				break
			}
		}
		if len(x.Summary) > 400 {
			x.Summary = x.Summary[:400] + "…"
		}
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if ms := v.CVE.Metrics[k]; len(ms) > 0 {
				x.CVSS = ms[0].CVSSData.BaseScore
				x.Severity = ms[0].CVSSData.BaseSeverity
				if x.Severity == "" {
					x.Severity = ms[0].BaseSeverity
				}
				break
			}
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVSS > out[j].CVSS })
	return out, nil
}

// Lookup returns CVEs applicable to one CPE match string (cached).
func (c *Client) Lookup(ctx context.Context, cpe string) ([]Vuln, error) {
	if c.Cache != nil {
		if v, ok := c.Cache.GetCVE(ctx, cpe, c.MaxAge); ok {
			return v, nil
		}
	}
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	u := c.BaseURL + "?resultsPerPage=500&virtualMatchString=" + url.QueryEscape(cpe)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "Sentinelis/1.0")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD HTTP %d", resp.StatusCode)
	}
	v, err := Parse(b, cpe)
	if err != nil {
		return nil, err
	}
	if c.Cache != nil {
		c.Cache.PutCVE(ctx, cpe, v)
	}
	return v, nil
}

// Points converts the worst CVSS into curiosity points.
func Points(maxCVSS float64) int {
	switch {
	case maxCVSS >= 9:
		return 35
	case maxCVSS >= 7:
		return 25
	case maxCVSS >= 4:
		return 12
	case maxCVSS > 0:
		return 5
	}
	return 0
}
