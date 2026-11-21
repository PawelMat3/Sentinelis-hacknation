package lab

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service is a simulated network service.
type Service struct {
	Port    int
	Name    string
	Product string
	Version string
	Banner  string
	Tunnel  string
	Site    string // site template key, "" for non-HTTP services
	SiteVer int
}

// Host is a simulated host as visible in one scan generation.
type Host struct {
	Address  string
	Hostname string
	Profile  string
	Pattern  string // always | business | night | flaky | decommissioned | new
	Services []Service
}

// Model is a deterministic synthetic network: the same IP always maps to the
// same machine; availability depends on the time of day; services evolve with
// the scan generation (run sequence number of a job).
type Model struct {
	Base    time.Time
	Density uint64 // per-mille of addresses that host a machine
	Loc     *time.Location
	names   map[string]namedHost
	certs   *certStore
	mu      sync.Mutex
	sites   map[string]*Site
}

type namedHost struct {
	ip, profile string
}

func NewModel(base time.Time) *Model {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		loc = time.UTC
	}
	return &Model{Base: base, Density: 45, Loc: loc, certs: newCertStore(base), sites: map[string]*Site{},
		names: map[string]namedHost{
			"www.lab.agh.local":                {"10.20.0.10", "named-www"},
			"staging.rekrutacja.lab.agh.local": {"10.20.0.20", "named-staging"},
			"admin.lab.agh.local":              {"10.20.0.30", "named-admin"},
			"jenkins.dev.lab.agh.local":        {"10.20.0.40", "named-jenkins"},
			"vpn.lab.agh.local":                {"10.20.0.50", "named-vpn"},
			"poczta.lab.agh.local":             {"10.20.0.60", "named-mail"},
			"elearning.lab.agh.local":          {"10.20.0.70", "named-moodle"},
		}}
}

// Names lists simulated DNS names (for demo targets).
func (m *Model) Names() []string {
	var out []string
	for n := range m.names {
		out = append(out, n)
	}
	return out
}

func hsh(parts ...string) uint64 {
	f := fnv.New64a()
	for _, p := range parts {
		f.Write([]byte(p))
		f.Write([]byte{0})
	}
	// extra avalanche (fnv is weak on similar inputs)
	x := f.Sum64()
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

var ssh = func(v string) Service {
	return Service{Port: 22, Name: "ssh", Product: "OpenSSH", Version: v, Banner: "SSH-2.0-OpenSSH_" + strings.ReplaceAll(v, " ", "_")}
}

func web(port int, site string, tls bool) Service {
	s := Service{Port: port, Name: "http", Site: site}
	if tls {
		s.Name, s.Tunnel = "https", "ssl"
	}
	return s
}

type profile struct {
	name   string
	weight uint64
	build  func(r uint64) []Service
}

var profiles = []profile{
	{"linux-web", 16, func(r uint64) []Service {
		site := []string{"nginx-default", "typo3", "drupal", "apache-default", "wordpress"}[r%5]
		return []Service{ssh("8.9p1 Ubuntu 3ubuntu0.6"), web(80, site, false), web(443, site, true)}
	}},
	{"wordpress", 7, func(r uint64) []Service {
		return []Service{ssh("9.2p1 Debian 2+deb12u2"), web(80, "wordpress", false)}
	}},
	{"windows", 10, func(r uint64) []Service {
		return []Service{{Port: 135, Name: "msrpc", Product: "Microsoft Windows RPC"}, {Port: 139, Name: "netbios-ssn", Product: "Microsoft Windows netbios-ssn"},
			{Port: 445, Name: "microsoft-ds"}, {Port: 3389, Name: "ms-wbt-server", Product: "Microsoft Terminal Services"}, web(80, "iis", false)}
	}},
	{"db", 6, func(r uint64) []Service {
		out := []Service{ssh("8.4p1 Debian 5+deb11u3")}
		if r%2 == 0 {
			out = append(out, Service{Port: 3306, Name: "mysql", Product: "MySQL", Version: "8.0.35"})
		} else {
			out = append(out, Service{Port: 5432, Name: "postgresql", Product: "PostgreSQL DB", Version: "14.10"})
		}
		if r%3 == 0 {
			out = append(out, Service{Port: 6379, Name: "redis", Product: "Redis key-value store", Version: "6.0.16"})
		}
		return out
	}},
	{"devops", 4, func(r uint64) []Service {
		return []Service{ssh("8.9p1 Ubuntu 3ubuntu0.6"), web(8080, "jenkins", false), web(3000, "grafana", true)}
	}},
	{"gitlab", 2, func(r uint64) []Service { return []Service{ssh("8.9p1 Ubuntu 3ubuntu0.6"), web(443, "gitlab", true)} }},
	{"camera", 5, func(r uint64) []Service {
		return []Service{web(80, "camera", false), {Port: 554, Name: "rtsp", Product: "Hikvision 7513 POE IP camera rtspd"}}
	}},
	{"printer", 5, func(r uint64) []Service {
		return []Service{web(80, "printer", false), {Port: 9100, Name: "jetdirect"}, {Port: 631, Name: "ipp", Product: "HP LaserJet printer ipp"}}
	}},
	{"router", 3, func(r uint64) []Service {
		out := []Service{web(80, "mikrotik", false), {Port: 8291, Name: "unknown"}, {Port: 22, Name: "ssh", Product: "MikroTik RouterOS sshd"}}
		if r%2 == 0 {
			out = append(out, Service{Port: 23, Name: "telnet", Product: "MikroTik router telnetd"})
		}
		return out
	}},
	{"nas", 2, func(r uint64) []Service {
		return []Service{web(5001, "synology", true), {Port: 445, Name: "netbios-ssn", Product: "Samba smbd", Version: "4.6.2"}}
	}},
	{"api", 3, func(r uint64) []Service { return []Service{ssh("9.6p1 Ubuntu 3ubuntu13"), web(443, "api", true)} }},
	{"java", 3, func(r uint64) []Service {
		return []Service{web(8080, "actuator", false), web(8081, "tomcat", false), {Port: 8009, Name: "ajp13", Product: "Apache Jserv"}}
	}},
	{"mail", 2, func(r uint64) []Service {
		return []Service{{Port: 25, Name: "smtp", Product: "Postfix smtpd"}, {Port: 143, Name: "imap", Product: "Dovecot imapd"}, web(443, "owa", true)}
	}},
	{"elk", 2, func(r uint64) []Service {
		return []Service{{Port: 9200, Name: "http", Product: "Elasticsearch REST API", Version: "7.10.2", Site: "elastic"}, web(5601, "kibana", false)}
	}},
	{"legacy", 3, func(r uint64) []Service {
		return []Service{{Port: 21, Name: "ftp", Product: "vsftpd", Version: "3.0.3", Banner: "220 (vsFTPd 3.0.3)"},
			{Port: 23, Name: "telnet", Product: "BusyBox telnetd"}, web(80, "apache-default", false)}
	}},
	{"dirlist", 2, func(r uint64) []Service { return []Service{ssh("7.9p1 Debian 10+deb10u2"), web(80, "dirlist", false)} }},
	{"dev", 2, func(r uint64) []Service {
		return []Service{ssh("8.2p1 Ubuntu 4ubuntu0.11"), web(5000, "flaskdebug", false)}
	}},
	{"phpmyadmin", 2, func(r uint64) []Service {
		return []Service{web(80, "phpmyadmin", false), {Port: 3306, Name: "mysql", Product: "MySQL", Version: "5.7.33-0ubuntu0.18.04.1"}}
	}},
	{"nextcloud", 2, func(r uint64) []Service { return []Service{web(443, "nextcloud", true)} }},
	{"ssh-only", 12, func(r uint64) []Service { return []Service{ssh("8.9p1 Ubuntu 3ubuntu0.6")} }},
	{"ics", 1, func(r uint64) []Service {
		return []Service{{Port: 502, Name: "modbus", Product: "Modbus TCP"}, web(80, "printer", false)}
	}},
	{"mqtt", 2, func(r uint64) []Service {
		return []Service{{Port: 1883, Name: "mqtt", Product: "Mosquitto version 1.6.9"}}
	}},
}

var profileTotal = func() uint64 {
	var t uint64
	for _, p := range profiles {
		t += p.weight
	}
	return t
}()

func namedServices(profile string) []Service {
	switch profile {
	case "named-www":
		return []Service{ssh("8.9p1 Ubuntu 3ubuntu0.6"), web(80, "typo3", false), web(443, "typo3", true)}
	case "named-staging":
		return []Service{web(80, "staging", false), ssh("8.2p1 Ubuntu 4ubuntu0.11")}
	case "named-admin":
		return []Service{web(443, "admin", true), web(8080, "phpmyadmin", false)}
	case "named-jenkins":
		return []Service{web(8080, "jenkins", false), ssh("8.9p1 Ubuntu 3ubuntu0.6")}
	case "named-vpn":
		return []Service{web(443, "fortinet", true)}
	case "named-mail":
		return []Service{{Port: 25, Name: "smtp", Product: "Postfix smtpd"}, web(443, "owa", true)}
	case "named-moodle":
		return []Service{web(443, "moodle", true), web(80, "nginx-default", false)}
	}
	return nil
}

// Describe returns the static machine at addr (an IP or simulated name).
func (m *Model) Describe(addr string) (Host, bool) {
	if nh, ok := m.names[addr]; ok {
		h, _ := m.Describe(nh.ip)
		h.Hostname = addr
		return h, true
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return Host{}, false
	}
	for name, nh := range m.names {
		if nh.ip == addr {
			return Host{Address: addr, Hostname: name, Profile: nh.profile, Pattern: "always", Services: namedServices(nh.profile)}, true
		}
	}
	if hsh(addr, "exists")%1000 >= m.Density {
		return Host{}, false
	}
	r := hsh(addr, "profile")
	pick := r % profileTotal
	var p profile
	for _, pp := range profiles {
		if pick < pp.weight {
			p = pp
			break
		}
		pick -= pp.weight
	}
	h := Host{Address: addr, Profile: p.name, Services: p.build(r >> 8)}
	av := hsh(addr, "avail") % 100
	switch {
	case av < 78:
		h.Pattern = "always"
	case av < 86:
		h.Pattern = "business"
	case av < 89:
		h.Pattern = "night"
	case av < 93:
		h.Pattern = "flaky"
	case av < 96:
		h.Pattern = "decommissioned"
	default:
		h.Pattern = "new"
	}
	oct := strings.Split(addr, ".")
	switch p.name {
	case "dev":
		h.Hostname = fmt.Sprintf("dev-%s.lab.agh.local", oct[3])
	case "api":
		h.Hostname = fmt.Sprintf("api-test-%s.lab.agh.local", oct[3])
	case "devops":
		h.Hostname = fmt.Sprintf("ci-%s.lab.agh.local", oct[3])
	case "windows":
		h.Hostname = fmt.Sprintf("ws-%s-%s.ad.lab.agh.local", oct[2], oct[3])
	}
	return h, true
}

// Probe returns the host as visible at time t in scan generation gen.
func (m *Model) Probe(addr string, t time.Time, gen int) (Host, bool) {
	h, ok := m.Describe(addr)
	if !ok {
		return Host{}, false
	}
	ip := h.Address
	hour := t.In(m.Loc).Hour()
	switch h.Pattern {
	case "business":
		if hour < 7 || hour >= 19 {
			return h, false
		}
	case "night":
		if hour >= 6 && hour < 20 {
			return h, false
		}
	case "flaky":
		if hsh(ip, "flap", strconv.FormatInt(t.Unix()/20, 10))%100 >= 55 {
			return h, false
		}
	case "decommissioned":
		if gen >= 3 {
			return h, false
		}
	case "new":
		if gen < 2 {
			return h, false
		}
	}
	// Generation-dependent drift.
	c := hsh(ip, "change")
	svcs := append([]Service(nil), h.Services...)
	if c%6 == 0 && gen >= 2 {
		for i := range svcs {
			svcs[i].SiteVer = 1
			if svcs[i].Product == "OpenSSH" {
				svcs[i].Version = "9.6p1 Ubuntu 3ubuntu13.5"
				svcs[i].Banner = "SSH-2.0-OpenSSH_9.6p1_Ubuntu-3ubuntu13.5"
			}
		}
	}
	if c%10 == 2 && gen >= 3 && len(svcs) > 1 {
		svcs = svcs[:len(svcs)-1] // a service disappears
	}
	if c%9 == 1 && gen >= 4 {
		svcs = append(svcs, web(8888, []string{"admin", "phpmyadmin", "dirlist"}[c%3], false)) // new risky service
	}
	if c%40 == 3 && gen >= 3 {
		svcs = append(svcs, web(8443, "staging", false))
	}
	if c%13 == 5 && gen >= 7 {
		svcs = append(svcs, web(9443, "grafana", true)) // late newcomer: monitoring exposed
	}
	if c%12 == 4 && gen >= 9 && len(svcs) > 1 {
		svcs = svcs[1:] // late decommissioning of a service
	}
	h.Services = svcs
	return h, true
}

func (m *Model) site(key, name string, ver int) *Site {
	k := fmt.Sprintf("%s|%s|%d", key, name, ver)
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sites[k]; ok {
		return s
	}
	s := NewSite(key, name, ver)
	m.sites[k] = s
	return s
}
