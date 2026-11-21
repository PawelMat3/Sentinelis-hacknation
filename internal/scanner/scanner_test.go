package scanner

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/clock"
	"asi/internal/lab"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up" reason="syn-ack"/><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="staging.example.org" type="user"/><hostname name="h5.example.org" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0" tunnel="ssl"/></port>
<port protocol="tcp" portid="25"><state state="closed" reason="reset"/><service name="smtp"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	res, err := ParseNmapXML(strings.NewReader(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].Up || res[1].Up {
		t.Fatalf("hosts: %+v", res)
	}
	h := res[0]
	if h.Hostname != "staging.example.org" || len(h.Ports) != 2 {
		t.Fatalf("host parse: %+v", h)
	}
	if h.Ports[1].Name != "https" || h.Ports[0].CPE == "" {
		t.Fatalf("ports: %+v", h.Ports)
	}
	m := mapDomains(res, []string{"staging.example.org"})
	if m[0].Target != "staging.example.org" {
		t.Fatal("domain mapping")
	}
}

// A host that answers discovery but has no open port in scope is alive; a
// host reported "up" only because of -Pn (reason user-set) with no open port
// is not evidence of life.
const liveNoPortsXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up" reason="echo-reply"/><address addr="10.0.0.7" addrtype="ipv4"/>
<ports><extraports state="closed" count="100"><extrareasons reason="reset" count="100"/></extraports></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.0.0.8" addrtype="ipv4"/>
<ports><extraports state="filtered" count="100"><extrareasons reason="no-response" count="100"/></extraports></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.0.0.10" addrtype="ipv4"/>
<ports><extraports state="closed" count="100"><extrareasons reason="reset" count="100"/></extraports></ports></host>
</nmaprun>`

func TestParseNmapXMLLiveHostWithoutOpenPorts(t *testing.T) {
	res, err := ParseNmapXML(strings.NewReader(liveNoPortsXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 {
		t.Fatalf("hosts: %+v", res)
	}
	if !res[3].Up || len(res[3].Ports) != 0 {
		t.Errorf("-Pn host answering with RST (closed ports) must be up: %+v", res[3])
	}
	if !res[0].Up || len(res[0].Ports) != 0 {
		t.Errorf("host answering discovery without open ports must be up: %+v", res[0])
	}
	if res[1].Up {
		t.Errorf("-Pn host without open ports must not count as up: %+v", res[1])
	}
	if !res[2].Up || len(res[2].Ports) != 1 {
		t.Errorf("-Pn host with an open port must be up: %+v", res[2])
	}
}

func TestNmapArgsSafe(t *testing.T) {
	n := &Nmap{Path: "nmap"}
	extra, err := ParseExtra("--version-light --script http-title,ssl-cert --max-retries 1")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(n.Args(Options{Ports: "top:100", RatePPS: 200, Timing: "T3", ServiceDetection: true, Extra: extra}), " ")
	for _, want := range []string{"-iL -", "--max-rate 200", "-sT", "--top-ports 100", "-sV", "--script http-title,ssl-cert"} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q: %s", want, args)
		}
	}
	if strings.Contains(" "+args+" ", " --open ") {
		t.Errorf("--open hides live hosts without open ports: %s", args)
	}
	for _, bad := range []string{"-oN /tmp/x", "--script vuln", "--script=http-brute", "-T5", "--data-length 100", "; rm -rf /", "-iL /etc/passwd"} {
		if _, err := ParseExtra(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if ValidateTiming("T5") == nil || ValidateTiming("T3") != nil {
		t.Fatal("timing validation")
	}
}

func TestPorts(t *testing.T) {
	p, err := ExpandPorts("22,80,8000-8002,T:443")
	if err != nil || len(p) != 6 {
		t.Fatalf("%v %v", p, err)
	}
	if ValidatePorts("1-65535") != nil || ValidatePorts("80;ls") == nil || ValidatePorts("top:100") != nil {
		t.Fatal("validate ports")
	}
}

func TestSimEngineTimeOfDay(t *testing.T) {
	base := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	m := lab.NewModel(base)
	fc := clock.NewFake(base)
	s := &Sim{Model: m, Clock: fc, CostPerHost: 10 * time.Millisecond}
	var targets []string
	for i := 0; i < 2048; i++ {
		targets = append(targets, "10.20."+itoa(i/256)+"."+itoa(i%256))
	}
	noon := time.Date(2026, 11, 20, 12, 0, 0, 0, m.Loc)
	night := time.Date(2026, 11, 20, 2, 0, 0, 0, m.Loc)
	up := func(at time.Time) int {
		r, err := s.Scan(context.Background(), targets, Options{Ports: "top:200", ServiceDetection: true, Now: at, Generation: 1})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, h := range r {
			if h.Up {
				n++
			}
		}
		return n
	}
	a, b := up(noon), up(night)
	if a < 40 || b < 40 || a == b {
		t.Fatalf("expected time-of-day dependent availability, noon=%d night=%d", a, b)
	}
	if fc.Now().Sub(base) != 2*2048*10*time.Millisecond {
		t.Fatalf("virtual clock should advance by scan cost, got %v", fc.Now().Sub(base))
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
