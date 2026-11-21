// Package lab provides a realistic, deterministic test infrastructure:
//   - a catalogue of simulated web applications (CMS, CI, cameras, staging…),
//   - a network Model mapping IPs to hosts whose availability depends on the
//     hour of day and whose services evolve between scan generations,
//   - an http.RoundTripper so the real fingerprint code can run on it, and
//   - a real TCP/TLS lab server for live demos with nmap.
package lab

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

type Page struct {
	Status  int
	Headers map[string]string
	Cookies []*http.Cookie
	Body    string
}

type Site struct {
	Key     string
	Label   string
	Root    Page
	Favicon []byte
	Paths   map[string]Page
	TLS     string // "" plain HTTP, else cert kind
	Name    string // hostname used in cert / staging names
}

func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Paths[r.URL.Path]
	switch {
	case r.URL.Path == "/" || r.URL.Path == "":
		p, ok = s.Root, true
	case r.URL.Path == "/favicon.ico" && s.Favicon != nil:
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(s.Favicon)
		return
	}
	if !ok {
		p = Page{Status: 404, Body: "<html><head><title>404 Not Found</title></head><body>Not Found</body></html>"}
		if srv := s.Root.Headers["Server"]; srv != "" {
			p.Headers = map[string]string{"Server": srv}
		}
	}
	for k, v := range p.Headers {
		w.Header().Set(k, v)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	for _, c := range p.Cookies {
		http.SetCookie(w, c)
	}
	st := p.Status
	if st == 0 {
		st = 200
	}
	w.WriteHeader(st)
	w.Write([]byte(p.Body))
}

// FakeIcon produces deterministic pseudo-icon bytes per product, so favicon
// hashes group identical products across hosts.
func FakeIcon(product string) []byte {
	h := sha256.Sum256([]byte("icon:" + product))
	var b bytes.Buffer
	b.Write([]byte{0, 0, 1, 0, 1, 0, 16, 16})
	for i := 0; i < 24; i++ {
		b.Write(h[:])
	}
	return b.Bytes()
}

func html(title, head, body string) string {
	return fmt.Sprintf("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title>%s</head><body>%s</body></html>", title, head, body)
}

func hdrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func cookie(name, val string, secure, httpOnly bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: val, Path: "/", Secure: secure, HttpOnly: httpOnly}
}

const loginForm = `<form method="post" action="#"><input name="user" type="text"><input name="pass" type="password"><button>Zaloguj</button></form>`

// SiteKeys lists all site templates.
var SiteKeys = []string{"wordpress", "moodle", "typo3", "drupal", "joomla", "jenkins", "grafana", "gitlab", "phpmyadmin",
	"staging", "actuator", "flaskdebug", "camera", "printer", "mikrotik", "nginx-default", "apache-default", "iis",
	"dirlist", "admin", "api", "fortinet", "owa", "elastic", "kibana", "synology", "tomcat", "nextcloud"}

// NewSite builds a site template. v selects a version variant (0 = initial,
// 1 = upgraded) so that rescans can observe changes.
func NewSite(key, name string, v int) *Site {
	s := &Site{Key: key, Name: name, Paths: map[string]Page{}}
	nginx := "nginx/1.18.0"
	if v > 0 {
		nginx = "nginx/1.24.0"
	}
	switch key {
	case "wordpress":
		ver := "6.4.2"
		if v > 0 {
			ver = "6.5.3"
		}
		s.Label = "WordPress"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.57 (Debian)", "X-Powered-By", "PHP/8.1.27", "Link", `<http://`+name+`/wp-json/>; rel="https://api.w.org/"`),
			Body: html("Wydział – Aktualności", `<meta name="generator" content="WordPress `+ver+`"><link rel="stylesheet" href="/wp-content/themes/agh/style.css">`,
				`<h1>Aktualności</h1><link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1"><link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css?ver=1.0"><script src="/wp-includes/js/jquery.js"></script><footer>Powered by WordPress `+ver+`</footer>`)}
		s.Paths["/wp-login.php"] = Page{Body: html("Zaloguj się ‹ Wydział — WordPress", "", `<form id="loginform"><input id="user_login"><input type="password" name="pwd"><input id="wp-submit" type="submit"></form>`),
			Cookies: []*http.Cookie{cookie("wordpress_test_cookie", "WP%20Cookie%20check", false, false)}}
		s.Paths["/robots.txt"] = Page{Headers: hdrs("Content-Type", "text/plain"), Body: "User-agent: *\nDisallow: /wp-admin/\n"}
		s.Favicon = FakeIcon("wordpress")
	case "moodle":
		s.Label = "Moodle"
		s.Root = Page{Headers: hdrs("Server", nginx), Cookies: []*http.Cookie{cookie("MoodleSessionelearn", "a8f3k2l1m9", true, true)},
			Body: html("e-Learning: Strona główna", `<meta name="keywords" content="moodle, e-Learning">`, `<script>M.cfg = {"wwwroot":"https://`+name+`"};</script>`)}
		s.Favicon = FakeIcon("moodle")
		s.TLS = CertValid
	case "typo3":
		s.Label = "TYPO3"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.52 (Ubuntu)"), Body: html("Uczelnia – strona główna", `<meta name="generator" content="TYPO3 CMS">`, `<link href="/typo3conf/ext/site/Resources/Public/main.css">`)}
		s.Favicon = FakeIcon("typo3")
	case "drupal":
		s.Label = "Drupal"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.57 (Debian)", "X-Generator", "Drupal 10 (https://www.drupal.org)", "X-Drupal-Cache", "HIT"),
			Body: html("Instytut | Strona główna", `<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">`, `<img src="/sites/default/files/logo.png">`)}
		s.Favicon = FakeIcon("drupal")
	case "joomla":
		s.Label = "Joomla"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.29 (Ubuntu)", "X-Powered-By", "PHP/7.2.24"),
			Body: html("Koło naukowe", `<meta name="generator" content="Joomla! - Open Source Content Management">`, `<script src="/media/jui/js/jquery.min.js"></script>`)}
		s.Paths["/administrator/"] = Page{Body: html("Koło naukowe - Administration", "", "Joomla! Administrator "+loginForm)}
		s.Favicon = FakeIcon("joomla")
	case "jenkins":
		ver := "2.401.3"
		if v > 0 {
			ver = "2.440.1"
		}
		s.Label = "Jenkins"
		s.Root = Page{Headers: hdrs("Server", "Jetty(10.0.13)", "X-Jenkins", ver, "X-Hudson", "1.395", "X-Jenkins-Session", "3fa1c2"),
			Cookies: []*http.Cookie{cookie("JSESSIONID.8f2a", "node0abc", false, true)},
			Body:    html("Dashboard [Jenkins]", "", `<div id="jenkins">Jenkins `+ver+`</div>`)}
		s.Favicon = FakeIcon("jenkins")
	case "grafana":
		s.Label = "Grafana"
		s.Root = Page{Status: 302, Headers: hdrs("Location", "/login", "Cache-Control", "no-store")}
		s.Paths["/login"] = Page{Body: html("Grafana", "", `<script>window.grafanaBootData = {"settings":{"buildInfo":{"version":"10.2.3"}}};</script>`+loginForm)}
		s.Paths["/api/health"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"commit":"1e84fede","database":"ok","version":"10.2.3"}`}
		s.Favicon = FakeIcon("grafana")
		s.TLS = CertSelfSigned
	case "gitlab":
		s.Label = "GitLab"
		s.Root = Page{Status: 302, Headers: hdrs("Server", "nginx", "Location", "/users/sign_in", "X-Gitlab-Meta", `{"correlation_id":"01H"}`),
			Cookies: []*http.Cookie{cookie("_gitlab_session", "7c1f9d", true, true)}}
		s.Paths["/users/sign_in"] = Page{Headers: hdrs("Server", "nginx"), Body: html("Sign in · GitLab", "", loginForm)}
		s.Favicon = FakeIcon("gitlab")
		s.TLS = CertValid
	case "phpmyadmin":
		s.Label = "phpMyAdmin"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.41 (Ubuntu)", "X-Powered-By", "PHP/7.4.3"),
			Cookies: []*http.Cookie{cookie("phpMyAdmin", "e1b2c3", false, true), cookie("pma_lang", "pl", false, true)},
			Body:    html("phpMyAdmin", "", `<div id="pma_navigation">phpMyAdmin</div>`+loginForm)}
		s.Favicon = FakeIcon("phpmyadmin")
	case "staging":
		s.Label = "Aplikacja (STAGING)"
		s.Root = Page{Headers: hdrs("Server", nginx, "X-Powered-By", "PHP/7.4.3", "X-Environment", "staging", "X-Backend-Server", "app-stg-02.internal"),
			Cookies: []*http.Cookie{cookie("laravel_session", "eyJpdiI6", false, false), cookie("XSRF-TOKEN", "eyJ0b2", false, false)},
			Body:    html("Rekrutacja – STAGING", "", `<div class="banner">Środowisko testowe – NOT FOR PRODUCTION</div>`+loginForm)}
		s.Paths["/.git/HEAD"] = Page{Headers: hdrs("Content-Type", "text/plain"), Body: "ref: refs/heads/develop\n"}
		s.Paths["/version"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"app":"rekrutacja","version":"3.2.0-rc1","env":"staging"}`}
		s.Paths["/login"] = Page{Body: html("Logowanie", "", loginForm)}
		s.Favicon = FakeIcon("laravel-app")
	case "actuator":
		s.Label = "Spring Boot"
		s.Root = Page{Status: 404, Headers: hdrs("Content-Type", "text/html"), Body: html("Error", "", `<h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p>`)}
		s.Paths["/actuator"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"}}}`}
		s.Paths["/actuator/health"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"status":"UP"}`}
	case "flaskdebug":
		s.Label = "Flask (debug)"
		s.Root = Page{Status: 500, Headers: hdrs("Server", "Werkzeug/2.0.1 Python/3.8.10"), Body: html("TypeError // Werkzeug Debugger", "", `<div class="debugger">Werkzeug Debugger – Traceback; __debugger__=yes</div>`)}
	case "camera":
		s.Label = "Kamera IP"
		s.Root = Page{Headers: hdrs("Server", "App-webs/"), Body: html("Network Camera", "", `<script>location.href="/doc/page/login.asp"</script>`)}
		s.Paths["/doc/page/login.asp"] = Page{Headers: hdrs("Server", "App-webs/"), Body: html("Login", "", loginForm)}
		s.Favicon = FakeIcon("ipcam")
	case "printer":
		s.Label = "Drukarka"
		s.Root = Page{Headers: hdrs("Server", "HP HTTP Server; HP LaserJet M404dn"), Body: html("HP LaserJet M404dn &nbsp;&nbsp;&nbsp;", "", "Stan urządzenia: Gotowe")}
		s.Favicon = FakeIcon("hp-printer")
	case "mikrotik":
		s.Label = "MikroTik"
		s.Root = Page{Body: html("RouterOS router configuration page", "", "mikrotik routeros webfig")}
		s.Favicon = FakeIcon("mikrotik")
	case "nginx-default":
		s.Label = "nginx (domyślna)"
		s.Root = Page{Headers: hdrs("Server", nginx), Body: html("Welcome to nginx!", "", "<h1>Welcome to nginx!</h1>")}
	case "apache-default":
		s.Label = "Apache (domyślna)"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.52 (Ubuntu)"), Body: html("Apache2 Ubuntu Default Page: It works", "", "It works!")}
		s.Paths["/server-status"] = Page{Body: html("Apache Status", "", "<h1>Apache Server Status for "+name+"</h1>")}
	case "iis":
		s.Label = "IIS"
		s.Root = Page{Headers: hdrs("Server", "Microsoft-IIS/10.0", "X-Powered-By", "ASP.NET", "X-AspNet-Version", "4.0.30319"),
			Cookies: []*http.Cookie{cookie("ASP.NET_SessionId", "qwe123", false, true)},
			Body:    html("IIS Windows Server", "", `<form><input type="hidden" name="__VIEWSTATE" value="abc"></form>`)}
		s.Favicon = FakeIcon("iis")
	case "dirlist":
		s.Label = "Listowanie katalogów"
		s.Root = Page{Headers: hdrs("Server", "Apache/2.4.38 (Debian)"), Body: html("Index of /", "", `<h1>Index of /</h1><a href="backup/">backup/</a><a href="dump.sql.gz">dump.sql.gz</a>`)}
	case "admin":
		s.Label = "Panel admina"
		s.Root = Page{Headers: hdrs("Server", nginx), Cookies: []*http.Cookie{cookie("PHPSESSID", "p9s8d7", false, false)},
			Body: html("Panel administracyjny – logowanie", "", loginForm)}
		s.Paths["/admin"] = Page{Status: 302, Headers: hdrs("Location", "/")}
		s.Favicon = FakeIcon("custom-admin")
	case "api":
		s.Label = "REST API"
		s.Root = Page{Headers: hdrs("X-Powered-By", "Express", "Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true"),
			Body: html("API Docs", "", `<div id="swagger-ui"></div><script src="swagger-ui-bundle.js"></script>`)}
		s.Paths["/openapi.json"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"openapi":"3.0.1","info":{"title":"USOS-like API","version":"1.4.2"}}`}
		s.Paths["/version"] = Page{Headers: hdrs("Content-Type", "application/json"), Body: `{"version":"1.4.2"}`}
		s.TLS = CertExpiring
	case "fortinet":
		s.Label = "FortiGate SSL VPN"
		s.Root = Page{Status: 302, Headers: hdrs("Location", "/remote/login?lang=en")}
		s.Paths["/remote/login"] = Page{Body: html("SSL VPN", "", `<script src="/remote/fgt_lang?lang=en"></script>`+loginForm)}
		s.TLS = CertSelfSigned
	case "owa":
		s.Label = "Outlook Web Access"
		s.Root = Page{Status: 302, Headers: hdrs("Server", "Microsoft-IIS/10.0", "X-OWA-Version", "15.2.1118.40", "Location", "/owa/")}
		s.Paths["/owa/"] = Page{Headers: hdrs("Server", "Microsoft-IIS/10.0", "X-OWA-Version", "15.2.1118.40"), Body: html("Outlook", "", `<form action="/owa/auth/owaauth.dll">`+loginForm+`</form>`)}
		s.TLS = CertExpired
		if v > 0 {
			s.TLS = CertValid
		}
	case "elastic":
		s.Label = "Elasticsearch"
		s.Root = Page{Headers: hdrs("Content-Type", "application/json", "X-elastic-product", "Elasticsearch"),
			Body: `{"name":"es01","cluster_name":"logs","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}`}
	case "kibana":
		s.Label = "Kibana"
		s.Root = Page{Status: 302, Headers: hdrs("kbn-name", "kibana", "kbn-version", "7.10.2", "Location", "/app/home")}
	case "synology":
		s.Label = "Synology NAS"
		s.Root = Page{Headers: hdrs("Server", nginx), Body: html("DiskStation – Synology", "", `<script>SYNO.SDS.Session = {};</script>`)}
		s.Favicon = FakeIcon("synology")
		s.TLS = CertSelfSigned
	case "tomcat":
		s.Label = "Apache Tomcat"
		s.Root = Page{Body: html("Apache Tomcat/9.0.31", "", "<h1>Apache Tomcat/9.0.31</h1>If you're seeing this, you've successfully installed Tomcat.")}
		s.Paths["/manager/html"] = Page{Status: 401, Headers: hdrs("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)}
		s.Favicon = FakeIcon("tomcat")
	case "nextcloud":
		s.Label = "Nextcloud"
		s.Root = Page{Status: 302, Headers: hdrs("Server", "Apache/2.4.57 (Debian)", "Location", "/login")}
		s.Paths["/login"] = Page{Headers: hdrs("Server", "Apache/2.4.57 (Debian)"), Cookies: []*http.Cookie{cookie("oc1a2b3c4d5e", "x", true, true)}, Body: html("Nextcloud", "", "nextcloud "+loginForm)}
		s.Favicon = FakeIcon("nextcloud")
		s.TLS = CertValid
	default:
		s.Label = key
		s.Root = Page{Headers: hdrs("Server", nginx), Body: html(strings.ToUpper(key), "", key)}
	}
	return s
}
