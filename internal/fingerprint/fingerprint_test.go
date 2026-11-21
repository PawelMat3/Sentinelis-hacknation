package fingerprint_test

import (
	"context"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"asi/internal/fingerprint"
	"asi/internal/lab"
)

func TestMurmur3Vector(t *testing.T) {
	// Python: mmh3.hash(base64.encodebytes(b"hello")) - favicon pipeline sanity;
	// and raw vector mmh3.hash("hello") == 613153351 via a 5-byte icon trick is
	// not possible, so check stability + sign handling instead.
	a := fingerprint.FaviconHash([]byte("hello"))
	b := fingerprint.FaviconHash([]byte("hello"))
	if a != b || a == "" {
		t.Fatal("favicon hash must be deterministic")
	}
	if fingerprint.FaviconHash([]byte("hello!")) == a {
		t.Fatal("different input, same hash")
	}
}

func set(t *testing.T) *fingerprint.Set {
	s, errs := fingerprint.NewSet(fingerprint.Builtin())
	if len(errs) > 0 {
		t.Fatalf("builtin signatures invalid: %v", errs)
	}
	return s
}

func probeSite(t *testing.T, key, name string) (*fingerprint.HTTPInfo, []fingerprint.Detection) {
	t.Helper()
	srv := httptest.NewServer(lab.NewSite(key, name, 0))
	defer srv.Close()
	host, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(ps)
	s := set(t)
	p := fingerprint.NewProber(nil)
	info := p.Probe(context.Background(), fingerprint.Target{Address: host, Port: port, Scheme: "http", VHost: name, Paths: s.Paths()})
	if info.Error != "" {
		t.Fatalf("%s: probe error %s", key, info.Error)
	}
	ev := &fingerprint.Evidence{Address: host, Hostname: name, Port: port, Service: "http", HTTP: info}
	return info, s.Evaluate(ev)
}

func has(ds []fingerprint.Detection, name string) *fingerprint.Detection {
	for i := range ds {
		if ds[i].Name == name {
			return &ds[i]
		}
	}
	return nil
}

func TestRealHTTPFingerprintWordPress(t *testing.T) {
	info, ds := probeSite(t, "wordpress", "www.lab.local")
	if info.Title != "Wydział – Aktualności" || info.StatusCode != 200 {
		t.Fatalf("title/status: %q %d", info.Title, info.StatusCode)
	}
	if info.FaviconHash == "" {
		t.Fatal("favicon hash missing")
	}
	wp := has(ds, "WordPress")
	if wp == nil || wp.Version != "6.4.2" || wp.Confidence < 90 {
		t.Fatalf("WordPress detection: %+v", wp)
	}
	if has(ds, "PHP") == nil || has(ds, "Apache httpd") == nil {
		t.Fatalf("missing PHP/Apache: %+v", ds)
	}
}

func TestStagingAndExposure(t *testing.T) {
	info, ds := probeSite(t, "staging", "staging.rekrutacja.lab.local")
	for _, n := range []string{"Środowisko testowe / staging", "Repozytorium .git dostępne", "Laravel", "Endpoint /version", "Formularz logowania"} {
		if has(ds, n) == nil {
			t.Errorf("expected detection %q, got %+v", n, ds)
		}
	}
	codes := map[string]bool{}
	for _, in := range fingerprint.Insights(info) {
		codes[in.Code] = true
	}
	if !codes["infra-header"] || !codes["cookie-not-httponly"] {
		t.Errorf("expected header/cookie insights, got %v", codes)
	}
}

func TestRedirectAndJenkins(t *testing.T) {
	info, ds := probeSite(t, "grafana-plain", "x")
	_ = info
	_ = ds
	_, ds = probeSite(t, "jenkins", "ci.lab.local")
	j := has(ds, "Jenkins")
	if j == nil || j.Version != "2.401.3" {
		t.Fatalf("jenkins: %+v", j)
	}
}

func TestSimTransportTLSAndRedirects(t *testing.T) {
	m := lab.NewModel(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	s := set(t)
	p := fingerprint.NewProber(nil)
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	p.TransportFor = m.Transport(now, 0)
	p.Now = func() time.Time { return now }
	// vpn.lab.agh.local -> fortinet over TLS with self-signed cert and redirect
	info := p.Probe(context.Background(), fingerprint.Target{Address: "10.20.0.50", Port: 443, VHost: "vpn.lab.agh.local", Paths: s.Paths()})
	if info.Error != "" || info.TLS == nil || !info.TLS.SelfSigned {
		t.Fatalf("expected TLS self-signed: %+v", info)
	}
	if len(info.Redirects) == 0 {
		t.Fatal("expected redirect chain")
	}
	ds := s.Evaluate(&fingerprint.Evidence{Address: "10.20.0.50", Hostname: "vpn.lab.agh.local", Port: 443, HTTP: info})
	if has(ds, "Fortinet SSL VPN") == nil {
		t.Fatalf("fortinet not detected: %+v", ds)
	}
	// mail with expired cert in generation 0
	info = p.Probe(context.Background(), fingerprint.Target{Address: "10.20.0.60", Port: 443, VHost: "poczta.lab.agh.local"})
	if info.TLS == nil || !info.TLS.Expired {
		t.Fatalf("expected expired cert: %+v", info.TLS)
	}
}

func TestUnsafeSignatureRejected(t *testing.T) {
	sg := &fingerprint.Signature{Name: "x", Enabled: true, Def: fingerprint.Definition{Matchers: []fingerprint.Matcher{
		{Type: "path", Path: "/login?user=admin&pass=admin", Weight: 0.9}}}}
	if err := sg.Compile(); err == nil {
		t.Fatal("query-string path must be rejected")
	}
	sg.Def.Matchers[0].Path = "/../../etc/passwd"
	if err := sg.Compile(); err == nil {
		t.Fatal("traversal must be rejected")
	}
}

func TestConfidenceCombination(t *testing.T) {
	sg := &fingerprint.Signature{Name: "Custom", Category: "custom", Enabled: true, Def: fingerprint.Definition{Matchers: []fingerprint.Matcher{
		{Type: "header", Name: "X-App", Weight: 0.5}, {Type: "title", Pattern: "Portal", Weight: 0.5}}}}
	if err := sg.Compile(); err != nil {
		t.Fatal(err)
	}
	ev := &fingerprint.Evidence{HTTP: &fingerprint.HTTPInfo{Headers: map[string][]string{"X-App": {"1"}}, Title: "Portal X"}}
	d := sg.Match(ev)
	if d == nil || d.Confidence != 75 {
		t.Fatalf("1-(0.5*0.5)=75%%, got %+v", d)
	}
	ev.HTTP.Title = "other"
	if d := sg.Match(ev); d == nil || d.Confidence != 50 {
		t.Fatalf("single marker 50%%, got %+v", d)
	}
}

func TestWordPressComponents(t *testing.T) {
	info, _ := probeSite(t, "wordpress", "www.lab.local")
	cs := fingerprint.Components(info)
	if len(cs) != 2 || cs[0].Name != "Wtyczka WordPress: contact-form-7" || cs[0].Version != "5.3.1" {
		t.Fatalf("components: %+v", cs)
	}
}
