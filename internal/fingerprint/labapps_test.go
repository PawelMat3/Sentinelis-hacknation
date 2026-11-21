package fingerprint_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"asi/internal/fingerprint"
)

// Minimal stand-ins for the services in the organisers' Docker lab
// (custom-network / modern / modern-proxy / vulnerable stacks): only the
// markers the signatures rely on, as served by the real applications.
var labApps = map[string]struct {
	want, version string
	h             http.HandlerFunc
}{
	"gitea": {"Gitea", "1.22.6", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.SetCookie(w, &http.Cookie{Name: "i_like_gitea", Value: "x", HttpOnly: true})
			io.WriteString(w, `<html><head><title>Gitea: Git with a cup of tea</title></head><body><footer>Powered by Gitea Version: 1.22.6 Page: 2ms</footer></body></html>`)
		case "/api/v1/version":
			io.WriteString(w, `{"version":"1.22.6"}`)
		default:
			http.NotFound(w, r)
		}
	}},
	"traefik": {"Traefik", "3.1.7", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
		case "/dashboard/":
			io.WriteString(w, `<!DOCTYPE html><html><head><title>Traefik</title></head><body><div id="q-app"></div></body></html>`)
		case "/api/version":
			io.WriteString(w, `{"Version":"3.1.7","Codename":"comte","startDate":"2026-11-21T10:00:00Z"}`)
		case "/api/overview":
			io.WriteString(w, `{"http":{"routers":{"total":1},"services":{"total":2},"middlewares":{"total":0}}}`)
		default:
			http.NotFound(w, r)
		}
	}},
	"toxiproxy": {"Toxiproxy", "2.12.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Toxiproxy-Request-Id", "dc0su6n5d1p000apnmj0")
		switch r.URL.Path {
		case "/proxies":
			io.WriteString(w, `{"wordpress":{"name":"wordpress","listen":"[::]:8666","upstream":"wordpress:80","enabled":true,"Logger":{},"toxics":[]}}`)
		case "/version":
			io.WriteString(w, "{\"version\": \"2.12.0\"}\n")
		default:
			http.NotFound(w, r)
		}
	}},
	"rabbitmq": {"RabbitMQ Management", "", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<!DOCTYPE html><html><head><title>RabbitMQ Management</title><script src="js/rabbitmq.js"></script></head></html>`)
	}},
	"npm": {"Nginx Proxy Manager", "", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<!doctype html><html><head><title>Nginx Proxy Manager</title></head><body></body></html>`)
	}},
	"dvwa": {"DVWA", "1.10", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login.php", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "security", Value: "low"})
		io.WriteString(w, `<html><head><title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title><link rel="stylesheet" href="dvwa/css/login.css"></head></html>`)
	}},
	"httpbin": {"httpbin", "0.9.2", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<html><head><title>httpbin.org</title></head><body><h2 class="title">httpbin.org<small><pre class="version">0.9.2</pre></small></h2><p>A simple HTTP Request &amp; Response Service.</p></body></html>`)
	}},
}

func probeHandler(t *testing.T, h http.Handler) (*fingerprint.HTTPInfo, []fingerprint.Detection) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	host, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(ps)
	s := set(t)
	info := fingerprint.NewProber(nil).Probe(context.Background(), fingerprint.Target{Address: host, Port: port, Scheme: "http", Paths: s.Paths()})
	if info.Error != "" {
		t.Fatalf("probe error %s", info.Error)
	}
	return info, s.Evaluate(&fingerprint.Evidence{Address: host, Port: port, Service: "http", HTTP: info})
}

func TestLabApplicationsDetected(t *testing.T) {
	if n := len(set(t).Paths()); n > fingerprint.NewProber(nil).MaxPaths {
		t.Fatalf("builtin signatures need %d probe paths, prober allows %d", n, fingerprint.NewProber(nil).MaxPaths)
	}
	for key, app := range labApps {
		_, ds := probeHandler(t, app.h)
		d := has(ds, app.want)
		if d == nil {
			t.Errorf("%s: %q not detected, got %+v", key, app.want, ds)
			continue
		}
		if app.version != "" && d.Version != app.version {
			t.Errorf("%s: version %q, want %q", key, d.Version, app.version)
		}
	}
}

func TestAMQPProductSignature(t *testing.T) {
	ds := set(t).Evaluate(&fingerprint.Evidence{Port: 5673, Service: "amqp", Product: "RabbitMQ", Version: "3.13.7"})
	if d := has(ds, "RabbitMQ (AMQP)"); d == nil || d.Version != "3.13.7" {
		t.Fatalf("AMQP: %+v", ds)
	}
	// low version intensity: nmap knows only the protocol
	ds = set(t).Evaluate(&fingerprint.Evidence{Port: 5673, Service: "amqp", Product: "Advanced Message Queue Protocol"})
	if has(ds, "Broker AMQP") == nil {
		t.Fatalf("generic AMQP: %+v", ds)
	}
}

func TestResponseTimeMeasured(t *testing.T) {
	info, _ := probeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			time.Sleep(450 * time.Millisecond) // like Toxiproxy LATENCY_MS
		}
		io.WriteString(w, "<title>slow</title>")
	}))
	if info.ResponseMS < 440 || info.ResponseMS > 5000 {
		t.Fatalf("response time %d ms", info.ResponseMS)
	}
	slow := false
	for _, in := range fingerprint.Insights(info) {
		slow = slow || in.Code == "slow-response"
	}
	if !slow {
		t.Fatal("slow-response insight expected")
	}
}

func TestSoftNotFoundIgnoredByPathSignatures(t *testing.T) {
	// front controller (Adminer-like): every path returns the login page
	page := `<html><head><title>Login - Adminer</title></head><body>"openapi" "swagger" version: 6.3.0 <a href="https://www.adminer.org/">Adminer</a></body></html>`
	info, ds := probeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "adminer_sid", Value: r.URL.Path})
		io.WriteString(w, page)
	}))
	for _, bad := range []string{"Swagger / OpenAPI", "Endpoint /version", "Spring Boot Actuator", "Repozytorium .git dostępne"} {
		if has(ds, bad) != nil {
			t.Errorf("soft-404 page matched path signature %q", bad)
		}
	}
	if has(ds, "Adminer") == nil {
		t.Errorf("Adminer itself must still be detected: %+v", ds)
	}
	soft := 0
	for _, p := range info.Paths {
		if p.Soft404 {
			soft++
		}
	}
	if soft == 0 {
		t.Fatal("expected soft-404 path results")
	}
}

func TestGenericHealthEndpointIsNotGrafana(t *testing.T) {
	_, ds := probeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			io.WriteString(w, `{"ok":true,"liveEnabled":true,"version":"0.1.0"}`)
			return
		}
		io.WriteString(w, `<html><head><title>Krypto Radar</title></head></html>`)
	}))
	if has(ds, "Grafana") != nil {
		t.Fatalf("generic /api/health must not be Grafana: %+v", ds)
	}
}

func TestTLSHintFallsBackToPlainHTTP(t *testing.T) {
	// nmap reported ssl/http, but the port serves the app over plain HTTP
	srv := httptest.NewServer(labApps["traefik"].h)
	defer srv.Close()
	host, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(ps)
	s := set(t)
	info := fingerprint.NewProber(nil).Probe(context.Background(), fingerprint.Target{Address: host, Port: port, TLSHint: true, Paths: s.Paths()})
	if info.Error != "" || info.Scheme != "http" {
		t.Fatalf("expected plain http fallback, got scheme=%q err=%q", info.Scheme, info.Error)
	}
	if has(s.Evaluate(&fingerprint.Evidence{Port: port, HTTP: info}), "Traefik") == nil {
		t.Fatal("Traefik not detected after fallback")
	}
}
