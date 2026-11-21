package fingerprint

// Built-in, passive detection signatures. They are seeded into the database on
// start (analysts may disable them, and add their own via the UI/API).
//
// Weight guide: 0.9+ unique marker (meta generator, vendor header),
// 0.6-0.8 strong but shared marker, 0.3-0.5 weak hint. Confidence of a
// detection = 1 - Π(1 - w) over matched markers.

func hdr(name, pat string, w float64) Matcher {
	return Matcher{Type: MHeader, Name: name, Pattern: pat, Weight: w}
}
func ck(pat string, w float64) Matcher    { return Matcher{Type: MCookie, Pattern: pat, Weight: w} }
func body(pat string, w float64) Matcher  { return Matcher{Type: MBody, Pattern: pat, Weight: w} }
func title(pat string, w float64) Matcher { return Matcher{Type: MTitle, Pattern: pat, Weight: w} }
func gen(pat string, w float64) Matcher   { return Matcher{Type: MGenerator, Pattern: pat, Weight: w} }
func prod(pat string, w float64) Matcher  { return Matcher{Type: MProduct, Pattern: pat, Weight: w} }
func bnr(pat string, w float64) Matcher   { return Matcher{Type: MBanner, Pattern: pat, Weight: w} }
func hostn(pat string, w float64) Matcher { return Matcher{Type: MHostname, Pattern: pat, Weight: w} }
func port(v string, w float64) Matcher    { return Matcher{Type: MPort, Value: v, Weight: w} }
func certm(field, pat string, w float64) Matcher {
	return Matcher{Type: MCert, Field: field, Pattern: pat, Weight: w}
}
func path(p string, status []int, pat string, w float64) Matcher {
	return Matcher{Type: MPath, Path: p, Status: status, Pattern: pat, Weight: w}
}

func sig(name, cat, desc string, curiosity int, ms ...Matcher) *Signature {
	return &Signature{Name: name, Category: cat, Description: desc, Enabled: true, Builtin: true,
		Def: Definition{Matchers: ms, Curiosity: curiosity}}
}

func sigAll(name, cat, desc string, curiosity int, ms ...Matcher) *Signature {
	s := sig(name, cat, desc, curiosity, ms...)
	s.Def.Condition = "all"
	return s
}

var ok200 = []int{200}

// Builtin returns fresh copies of the built-in signatures.
func Builtin() []*Signature {
	return []*Signature{
		// --- CMS ---------------------------------------------------------
		sig("WordPress", "cms", "WordPress CMS", 5,
			gen(`WordPress ?(?P<version>[\d.]+)?`, 0.95), body(`/wp-(content|includes)/`, 0.8),
			hdr("Link", `api\.w\.org`, 0.7), ck(`^wordpress_|^wp-settings`, 0.6),
			path("/wp-login.php", ok200, `user_login|wp-submit`, 0.7), path("/feed/", ok200, `wordpress.org/?v=(?P<version>[d.]+)`, 0.9)),
		sig("Joomla", "cms", "Joomla! CMS", 5,
			gen(`Joomla!? ?(?P<version>[\d.]+)?`, 0.95), body(`/media/(jui|system)/|com_content|Joomla!`, 0.6),
			path("/administrator/", ok200, `joomla`, 0.7)),
		sig("Drupal", "cms", "Drupal CMS", 5,
			gen(`Drupal ?(?P<version>\d+)?`, 0.95), hdr("X-Generator", `Drupal ?(?P<version>\d+)?`, 0.95),
			hdr("X-Drupal-Cache", "", 0.85), hdr("X-Drupal-Dynamic-Cache", "", 0.85), body(`/sites/default/files|drupal-settings-json|Drupal\.settings`, 0.7)),
		sig("TYPO3", "cms", "TYPO3 CMS", 5, gen(`TYPO3 ?(?P<version>[\d.]+)?`, 0.95), body(`typo3conf|typo3temp`, 0.75)),
		sig("Moodle", "cms", "Platforma e-learningowa Moodle", 5,
			ck(`^MoodleSession`, 0.9), body(`content="moodle,|M\.cfg = |/theme/styles\.php`, 0.75)),
		sig("MediaWiki", "cms", "MediaWiki", 0, gen(`MediaWiki ?(?P<version>[\d.]+)?`, 0.95), body(`mediawiki|mw-head`, 0.5)),
		sig("Magento", "cms", "Magento e-commerce", 5, ck(`^mage-|^frontend$`, 0.5), body(`Mage\.Cookies|/static/frontend/|mage/cookies`, 0.75)),
		sig("PrestaShop", "cms", "PrestaShop e-commerce", 5, gen(`PrestaShop`, 0.95), ck(`^PrestaShop-`, 0.9)),
		sig("Ghost", "cms", "Ghost CMS", 0, gen(`Ghost ?(?P<version>[\d.]+)?`, 0.95)),
		sig("Confluence", "collaboration", "Atlassian Confluence", 10,
			hdr("X-Confluence-Request-Time", "", 0.9), body(`ajs-version-number" content="(?P<version>[\d.]+)`, 0.6), title(`Confluence`, 0.4)),
		sig("Jira", "collaboration", "Atlassian Jira", 10, hdr("X-AREQUESTID", "", 0.6), ck(`^atlassian\.xsrf\.token$`, 0.6), title(`\bJira\b`, 0.6)),
		sig("Nextcloud", "collaboration", "Nextcloud / ownCloud", 5, title(`Nextcloud|ownCloud`, 0.8), body(`oc_requesttoken|nextcloud`, 0.6), ck(`^oc[a-z0-9]{10}$|^nc_session`, 0.6)),

		// --- servers / languages / frameworks --------------------------------
		sig("nginx", "server", "Serwer HTTP nginx", 0, hdr("Server", `nginx(?:/(?P<version>[\d.]+))?`, 0.95), prod(`\bnginx(?: (?P<version>[\d.]+))?`, 0.85)),
		sig("Apache httpd", "server", "Serwer Apache HTTP Server", 0, hdr("Server", `^Apache(?:/(?P<version>[\d.]+))?`, 0.95), prod(`Apache httpd(?: (?P<version>[\d.]+))?`, 0.9)),
		sig("Microsoft IIS", "server", "Microsoft Internet Information Services", 0, hdr("Server", `Microsoft-IIS(?:/(?P<version>[\d.]+))?`, 0.95), prod(`Microsoft IIS httpd(?: (?P<version>[\d.]+))?`, 0.9)),
		sig("LiteSpeed", "server", "LiteSpeed Web Server", 0, hdr("Server", `LiteSpeed`, 0.95)),
		sig("Caddy", "server", "Caddy", 0, hdr("Server", `^Caddy`, 0.95)),
		sig("lighttpd", "server", "lighttpd", 0, hdr("Server", `lighttpd(?:/(?P<version>[\d.]+))?`, 0.95)),
		sig("OpenResty", "server", "OpenResty", 0, hdr("Server", `openresty(?:/(?P<version>[\d.]+))?`, 0.95)),
		sig("Envoy", "server", "Envoy proxy", 0, hdr("Server", `^envoy`, 0.9), hdr("X-Envoy-Upstream-Service-Time", "", 0.8)),
		sig("Apache Tomcat", "server", "Apache Tomcat", 5, title(`Apache Tomcat(?:/(?P<version>[\d.]+))?`, 0.9), body(`Apache Tomcat(?:/(?P<version>[\d.]+))?`, 0.6), prod(`Apache Tomcat`, 0.9)),
		sig("Jetty", "server", "Eclipse Jetty", 0, hdr("Server", `Jetty\(?(?P<version>[\d.v]+)?`, 0.95)),
		sig("Werkzeug (serwer deweloperski)", "debug", "Serwer deweloperski Flask/Werkzeug wystawiony do sieci", 15, hdr("Server", `Werkzeug(?:/(?P<version>[\d.]+))?`, 0.95)),
		sig("PHP", "language", "PHP", 0, hdr("X-Powered-By", `PHP(?:/(?P<version>[\d.]+))?`, 0.95), ck(`^PHPSESSID$`, 0.7)),
		sig("ASP.NET", "framework", "Microsoft ASP.NET", 0, hdr("X-AspNet-Version", `(?P<version>[\d.]+)`, 0.95), hdr("X-Powered-By", `ASP\.NET`, 0.9),
			ck(`^ASP\.NET_SessionId$|^\.ASPXAUTH$|^\.AspNetCore\.`, 0.9), body(`__VIEWSTATE`, 0.8)),
		sig("Java Servlet", "language", "Kontener serwletów Java", 0, ck(`^JSESSIONID$`, 0.7)),
		sig("Express", "framework", "Node.js Express", 0, hdr("X-Powered-By", `^Express`, 0.95)),
		sig("Next.js", "framework", "Next.js", 0, hdr("X-Powered-By", `Next\.js`, 0.95), body(`__NEXT_DATA__|/_next/static`, 0.9)),
		sig("Angular", "framework", "Angular", 0, body(`ng-version="(?P<version>[\d.]+)"`, 0.9)),
		sig("Laravel", "framework", "Laravel (PHP)", 0, ck(`^laravel_session$`, 0.9), ck(`^XSRF-TOKEN$`, 0.3)),
		sig("Django", "framework", "Django (Python)", 0, ck(`^csrftoken$`, 0.6), body(`csrfmiddlewaretoken`, 0.7)),
		sig("Ruby on Rails", "framework", "Ruby on Rails", 0, body(`name="csrf-param" content="authenticity_token"`, 0.85), hdr("X-Runtime", "", 0.35)),
		sig("Spring Boot", "framework", "Spring Boot (Java)", 5, body(`Whitelabel Error Page`, 0.9), path("/actuator/health", ok200, `"status"`, 0.8)),
		sig("Cloudflare", "waf-cdn", "Cloudflare CDN/WAF", 0, hdr("CF-RAY", "", 0.95), hdr("Server", `^cloudflare`, 0.9)),
		sig("F5 BIG-IP", "network-device", "Load balancer F5 BIG-IP (ciasteczko może ujawniać adresy wewnętrzne)", 10, ck(`^BIGipServer`, 0.95), hdr("Server", `BigIP|BIG-IP`, 0.9)),

		// --- devops / monitoring / admin -----------------------------------
		sig("Jenkins", "devops", "Serwer CI Jenkins", 25, hdr("X-Jenkins", `(?P<version>[\d.]+)`, 0.98), hdr("X-Hudson", "", 0.9), title(`\[Jenkins\]|^Jenkins`, 0.6)),
		sig("GitLab", "devops", "GitLab", 15, ck(`^_gitlab_session$`, 0.95), hdr("X-Gitlab-Meta", "", 0.9), title(`GitLab`, 0.6)),
		sig("Grafana", "monitoring", "Grafana", 15, title(`^Grafana`, 0.7), body(`grafanaBootData|grafana-app`, 0.85), ck(`^grafana_session`, 0.9),
			path("/api/health", ok200, `(?s)"database"\s*:\s*"[^"]*".*"version"\s*:\s*"(?P<version>[\d.]+)`, 0.7)),
		sig("Kibana", "monitoring", "Kibana", 20, hdr("kbn-name", "", 0.95), hdr("kbn-version", `(?P<version>[\d.]+)`, 0.95), title(`Kibana`, 0.7)),
		sig("Prometheus", "monitoring", "Prometheus", 15, title(`Prometheus Time Series`, 0.9), path("/metrics", ok200, `# (HELP|TYPE) `, 0.6)),
		sig("Zabbix", "monitoring", "Zabbix", 15, title(`Zabbix`, 0.8), ck(`^zbx_session`, 0.9)),
		sig("Portainer", "devops", "Portainer (zarządzanie kontenerami)", 25, title(`Portainer`, 0.9)),
		sig("Docker Registry", "devops", "Rejestr obrazów Docker", 25, hdr("Docker-Distribution-Api-Version", "", 0.95)),
		sig("SonarQube", "devops", "SonarQube", 10, title(`SonarQube`, 0.9)),
		sig("Gitea", "devops", "Serwer Git Gitea (repozytoria kodu)", 20,
			ck(`^i_like_gitea$`, 0.95), title(`Gitea`, 0.7), body(`Powered by Gitea[^<]{0,40}?Version:\s*(?P<version>[\d.]+)`, 0.9),
			path("/api/v1/version", ok200, `"version"\s*:\s*"(?P<version>[\d.]+)`, 0.5)),
		sig("Traefik", "admin-panel", "Reverse proxy Traefik – panel i API konfiguracji (api.insecure)", 30,
			title(`^Traefik`, 0.8), path("/api/version", ok200, `"Version"\s*:\s*"(?P<version>[\d.]+)"\s*,\s*"Codename"`, 0.95),
			path("/api/overview", ok200, `"routers"\s*:.*"services"\s*:`, 0.8)),
		sig("Nginx Proxy Manager", "admin-panel", "Nginx Proxy Manager – panel zarządzania reverse proxy", 25,
			title(`Nginx Proxy Manager`, 0.95), body(`Nginx Proxy Manager`, 0.7)),
		sig("Toxiproxy", "exposure", "API Toxiproxy bez uwierzytelnienia – pozwala sterować ruchem (opóźnienia, zrywanie połączeń)", 35,
			hdr("X-Toxiproxy-Request-Id", "", 0.95), path("/proxies", ok200, `(?s)"upstream"\s*:\s*"[^"]*".*?"toxics"\s*:`, 0.9),
			path("/version", ok200, `^\s*\{\s*"version"\s*:\s*"(?P<version>\d+\.\d+\.\d+)"\s*\}\s*$`, 0.3)),
		sig("RabbitMQ Management", "admin-panel", "Panel zarządzania brokera RabbitMQ", 25,
			title(`RabbitMQ Management`, 0.95), body(`rabbitmq`, 0.4)),
		sig("RabbitMQ (AMQP)", "messaging", "Broker komunikatów RabbitMQ (AMQP) dostępny sieciowo", 15,
			prod(`rabbitmq(?:\s+(?P<version>[\d.]+))?`, 0.95)),
		sig("Broker AMQP", "messaging", "Broker komunikatów AMQP (np. RabbitMQ, ActiveMQ, Qpid) dostępny sieciowo", 15,
			prod(`^amqps?\b|Advanced Message Queu`, 0.9)),
		sig("DVWA", "staging", "Damn Vulnerable Web Application – celowo podatna aplikacja szkoleniowa", 45,
			title(`Damn Vulnerable Web Application(?:\s*\(DVWA\))?\s*v?(?P<version>[\d.]+)?`, 0.98), body(`dvwa/(css|images|js)/`, 0.7)),
		sig("httpbin", "debug", "httpbin – usługa testowa odbijająca żądania HTTP (narzędzie deweloperskie)", 15,
			title(`^httpbin`, 0.9), body(`A simple HTTP Request &amp; Response Service`, 0.8), body(`<pre class="version">\s*(?P<version>[\d.]+)`, 0.3)),
		sig("phpMyAdmin", "admin-panel", "Panel zarządzania bazą MySQL", 30, title(`phpMyAdmin`, 0.9), ck(`^phpMyAdmin|^pma_lang`, 0.9), path("/phpmyadmin/", ok200, `phpMyAdmin`, 0.8)),
		sig("Adminer", "admin-panel", "Adminer (panel bazy danych)", 30, title(`Adminer`, 0.8), body(`adminer\.org`, 0.7)),
		sig("Webmin", "admin-panel", "Panel administracyjny Webmin", 25, title(`Webmin`, 0.8), hdr("Server", `MiniServ(?:/(?P<version>[\d.]+))?`, 0.95)),
		sig("cPanel / WHM", "admin-panel", "Panel hostingowy cPanel/WHM", 20, title(`cPanel|WHM Login`, 0.8), port("2082,2083,2086,2087", 0.3)),
		sig("Tomcat Manager", "admin-panel", "Aplikacja Tomcat Manager (wymaga uwierzytelnienia)", 30, path("/manager/html", []int{401, 403}, "", 0.7), hdr("WWW-Authenticate", `Tomcat Manager`, 0.9)),
		sig("Spring Boot Actuator", "exposure", "Publicznie dostępne endpointy Actuator", 25, path("/actuator", ok200, `_links`, 0.9)),
		sig("Panel administracyjny", "admin-panel", "Strona logowania / panel administracyjny", 25,
			path("/admin", []int{200, 401, 403}, "", 0.45), path("/admin/", []int{200, 401, 403}, "", 0.45),
			path("/login", ok200, `type=["']?password`, 0.6),
			Matcher{Type: MTitle, Pattern: `\b(admin|administrat|panel|dashboard|backoffice|zarządzani)`, Weight: 0.5},
			hostn(`(^|[.-])(admin|panel|manage|backoffice|cms)([.-]|$)`, 0.5)),
		sig("Formularz logowania", "auth", "Strona zawiera formularz z polem hasła (bez prób logowania)", 8, body(`<input[^>]+type=["']?password`, 0.8)),

		// --- staging / test environments -------------------------------------
		sig("Środowisko testowe / staging", "staging", "Oznaki środowiska nieprodukcyjnego (staging, test, dev, UAT)", 30,
			hostn(`(^|[.-])(staging|stage|stg|test|testing|dev|devel|develop|uat|qa|preprod|pre-prod|sandbox|beta)([.-]|\d|$)`, 0.7),
			title(`\b(staging|test(ing)? (server|environment|site|instance)|development|dev environment|uat|pre-?prod|sandbox|środowisko testowe|wersja testowa)\b`, 0.7),
			hdr("X-Environment", `stag|test|dev|uat|qa`, 0.9), hdr("X-Env", `stag|test|dev|uat|qa`, 0.9),
			body(`(staging environment|this is a (test|staging) (site|server)|środowisko testowe|wersja testowa|NOT FOR PRODUCTION)`, 0.6),
			certm("san", `(^|[.-])(staging|dev|test|uat)\.`, 0.6)),

		// --- debug / exposures -------------------------------------------------
		sig("Tryb debugowania aplikacji", "debug", "Strona ujawnia tryb debug (Werkzeug/Django/Symfony/Laravel)", 35,
			body(`Werkzeug Debugger|__debugger__`, 0.9), body(`You're seeing this error because you have <code>DEBUG = True</code>`, 0.95),
			hdr("X-Debug-Token-Link", "", 0.95), body(`Whoops! There was an error|Ignition`, 0.6)),
		sig("Listowanie katalogów", "exposure", "Włączony directory listing", 20, title(`^Index of /`, 0.9), body(`<title>Index of /|Directory listing for /`, 0.9)),
		sig("Repozytorium .git dostępne", "exposure", "Plik /.git/HEAD dostępny publicznie", 40, path("/.git/HEAD", ok200, `^ref: refs/`, 0.95)),
		sig("Apache server-status", "exposure", "Publiczna strona mod_status", 20, path("/server-status", ok200, `Apache Server Status`, 0.95)),
		sig("phpinfo()", "exposure", "Publiczna strona phpinfo()", 25, path("/phpinfo.php", ok200, `phpinfo\(\)|PHP Version (?P<version>[\d.]+)`, 0.9)),
		sig("Swagger / OpenAPI", "api", "Dokumentacja API dostępna publicznie", 15, body(`swagger-ui`, 0.8), path("/swagger-ui.html", ok200, `swagger`, 0.8), path("/openapi.json", ok200, `"(openapi|swagger)"`, 0.8)),
		sig("Endpoint /version", "info", "Endpoint ujawniający wersję oprogramowania", 10,
			path("/version", ok200, `"?version"?\s*[:=]\s*"?(?P<version>[\w.\-]+)`, 0.7), path("/api/version", ok200, `"?version"?\s*[:=]\s*"?(?P<version>[\w.\-]+)`, 0.7)),
		sig("robots.txt ujawnia ścieżki", "info", "robots.txt wskazuje wrażliwe ścieżki", 5, path("/robots.txt", ok200, `disallow:\s*/(admin|administrator|backend|panel|private|staging|test)`, 0.6)),
		sig("security.txt", "info", "Opublikowany kontakt bezpieczeństwa (RFC 9116)", 0, path("/.well-known/security.txt", ok200, `contact:`, 0.9)),
		sig("Strona domyślna serwera", "exposure", "Nieskonfigurowana strona domyślna", 10, title(`Apache2 (Ubuntu|Debian) Default Page|^It works!|Welcome to nginx!|IIS Windows Server|Test Page for the (Apache|nginx)`, 0.9)),
		sig("Elasticsearch", "database", "Elasticsearch REST API bez uwierzytelnienia", 30, body(`"cluster_name"\s*:|You Know, for Search`, 0.9), prod(`elasticsearch`, 0.8)),

		// --- VPN / edge / mail ---------------------------------------------------
		sig("Fortinet SSL VPN", "vpn", "Portal FortiGate SSL VPN", 15, urlm(`/remote/login`, 0.9), body(`fgt_lang|/remote/login`, 0.85)),
		sig("Cisco ASA / AnyConnect", "vpn", "Portal Cisco ASA WebVPN", 15, body(`/\+CSCOE\+/`, 0.95), urlm(`/\+CSCOE\+/`, 0.95)),
		sig("Pulse / Ivanti Connect Secure", "vpn", "Portal Ivanti Connect Secure", 15, urlm(`/dana-na/`, 0.95), body(`dana-na`, 0.8)),
		sig("Citrix ADC / Gateway", "vpn", "Citrix NetScaler", 15, ck(`^NSC_`, 0.85), urlm(`/vpn/index\.html|/logon/LogonPoint`, 0.9)),
		sig("Microsoft Exchange OWA", "mail", "Outlook Web Access", 10, hdr("X-OWA-Version", `(?P<version>[\d.]+)`, 0.95), urlm(`/owa/`, 0.8), body(`/owa/auth/`, 0.9)),
		sig("Roundcube", "mail", "Roundcube Webmail", 5, title(`Roundcube Webmail`, 0.9), ck(`^roundcube_sessid`, 0.9)),

		// --- IoT / embedded / network devices -------------------------------------
		sig("Kamera IP / rejestrator", "iot", "Interfejs kamery IP, NVR lub DVR", 20,
			title(`(ip ?camera|network camera|webcam|\bnvr\b|\bdvr\b|kamera)`, 0.75), hdr("Server", `App-webs|DNVRS-Webs|Hikvision-Webs|uc-httpd`, 0.85),
			body(`/doc/page/login\.asp|webcomponents/plugin|live ?view`, 0.5), prod(`rtsp`, 0.6)),
		sig("Wbudowany serwer WWW (IoT)", "iot", "Serwer HTTP typowy dla urządzeń wbudowanych", 15, hdr("Server", `GoAhead|Boa/|mini_httpd|thttpd|lwIP|RomPager|Allegro|micro_httpd|Embedthis`, 0.85)),
		sig("Drukarka sieciowa", "iot", "Interfejs drukarki / urządzenia wielofunkcyjnego", 10,
			title(`laserjet|officejet|printer|drukark|epson|brother|kyocera|lexmark|xerox|ricoh|canon`, 0.7), prod(`jetdirect|printer|ipp`, 0.8), port("9100,631", 0.35)),
		sig("MikroTik RouterOS", "network-device", "Router MikroTik", 20, title(`RouterOS|mikrotik`, 0.9), prod(`MikroTik`, 0.9)),
		sig("Ubiquiti UniFi", "network-device", "Kontroler Ubiquiti UniFi", 15, title(`UniFi`, 0.85)),
		sig("Synology DSM", "iot", "NAS Synology DiskStation", 15, title(`Synology|DiskStation`, 0.85), body(`SYNO\.(SDS|Core)`, 0.7)),
		sig("QNAP QTS", "iot", "NAS QNAP", 15, title(`QNAP|QTS`, 0.8)),
		sig("MQTT broker", "iot", "Broker MQTT (IoT)", 20, port("1883,8883", 0.5), prod(`mqtt|mosquitto`, 0.9)),
		sig("Modbus/TCP (ICS)", "iot", "Protokół przemysłowy Modbus wystawiony do sieci", 40, port("502", 0.6), prod(`modbus`, 0.9)),

		// --- non-HTTP services --------------------------------------------------
		sig("OpenSSH", "remote-access", "Serwer OpenSSH", 0, prod(`OpenSSH(?: (?P<version>[\w.]+))?`, 0.95), bnr(`SSH-2\.0-OpenSSH_(?P<version>[\w.]+)`, 0.95)),
		sig("Telnet", "remote-access", "Nieszyfrowany dostęp Telnet", 30, prod(`^telnet`, 0.9), port("23", 0.5)),
		sig("RDP", "remote-access", "Pulpit zdalny Microsoft RDP", 20, prod(`ms-wbt-server|Remote Desktop|rdp`, 0.9), port("3389", 0.6)),
		sig("VNC", "remote-access", "Zdalny pulpit VNC", 30, prod(`\bvnc\b`, 0.9), port("5900,5901", 0.5), bnr(`^RFB \d`, 0.95)),
		sig("SMB", "remote-access", "Udostępnianie plików SMB/NetBIOS", 20, prod(`microsoft-ds|netbios-ssn|Samba`, 0.85), port("445,139", 0.5)),
		sig("FTP", "remote-access", "Serwer FTP (transmisja nieszyfrowana)", 10, prod(`^ftp|vsftpd|ProFTPD|FileZilla`, 0.9), bnr(`^220[ -]`, 0.6)),
		sig("MySQL / MariaDB", "database", "Baza danych MySQL/MariaDB dostępna sieciowo", 30, prod(`mysql|mariadb`, 0.9), port("3306", 0.5)),
		sig("PostgreSQL", "database", "Baza PostgreSQL dostępna sieciowo", 30, prod(`postgresql`, 0.9), port("5432", 0.5)),
		sig("MongoDB", "database", "Baza MongoDB dostępna sieciowo", 30, prod(`mongodb`, 0.9), port("27017", 0.5)),
		sig("Redis", "database", "Redis dostępny sieciowo", 35, prod(`redis`, 0.9), port("6379", 0.5)),
		sig("Microsoft SQL Server", "database", "MS SQL Server dostępny sieciowo", 30, prod(`ms-sql|Microsoft SQL Server`, 0.9), port("1433", 0.5)),
		sig("Memcached", "database", "Memcached dostępny sieciowo", 30, prod(`memcache`, 0.9), port("11211", 0.5)),
		sig("SMTP", "mail", "Serwer pocztowy SMTP", 0, prod(`smtp|postfix|exim|sendmail`, 0.85)),
	}
}

func urlm(pat string, w float64) Matcher { return Matcher{Type: MURL, Pattern: pat, Weight: w} }
