package vulns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCPEs(t *testing.T) {
	if c := CPEs("Apache httpd", "2.4.57"); len(c) != 1 || c[0] != "cpe:2.3:a:apache:http_server:2.4.57" {
		t.Fatalf("%v", c)
	}
	if c := CPEs("OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6"); len(c) != 1 || !strings.HasSuffix(c[0], "openssh:8.9") {
		t.Fatalf("%v", c)
	}
	if c := CPEs("Wtyczka WordPress: contact-form-7", "5.3.1"); len(c) != 1 || c[0] != "cpe:2.3:a:*:contact_form_7:5.3.1:*:*:*:*:wordpress:*:*" {
		t.Fatalf("%v", c)
	}
	if CPEs("Drupal", "10") != nil || CPEs("Unknown thing", "1.2") != nil || CPEs("nginx", "") != nil {
		t.Fatal("vague or unknown must yield nil")
	}
	if len(CPEs("nginx", "1.18.0")) != 2 {
		t.Fatal("nginx has two vendors in NVD")
	}
}

const sample = `{"totalResults":2,"vulnerabilities":[
{"cve":{"id":"CVE-2021-41773","published":"2021-10-05T09:15:07.593","descriptions":[{"lang":"en","value":"Path traversal in Apache 2.4.49"}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}},
{"cve":{"id":"CVE-2021-42013","published":"2021-10-07T16:15:09.270","descriptions":[{"lang":"en","value":"RCE"}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}`

type memCache map[string][]Vuln

func (m memCache) GetCVE(_ context.Context, c string, _ time.Duration) ([]Vuln, bool) {
	v, ok := m[c]
	return v, ok
}
func (m memCache) PutCVE(_ context.Context, c string, v []Vuln) { m[c] = v }

func TestLookupParsesAndCaches(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.URL.RawQuery, "virtualMatchString=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.49") {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		w.Write([]byte(sample))
	}))
	defer srv.Close()
	c := NewClient("k", memCache{})
	c.BaseURL = srv.URL
	v, err := c.Lookup(context.Background(), "cpe:2.3:a:apache:http_server:2.4.49")
	if err != nil || len(v) != 2 || v[0].CVE != "CVE-2021-42013" || v[0].CVSS != 9.8 || v[0].Published != "2021-10-07" {
		t.Fatalf("%v %+v", err, v)
	}
	c.Lookup(context.Background(), "cpe:2.3:a:apache:http_server:2.4.49")
	if calls != 1 {
		t.Fatalf("cache not used, calls=%d", calls)
	}
	if Points(9.8) <= Points(7.5) || Points(0) != 0 {
		t.Fatal("points")
	}
}
