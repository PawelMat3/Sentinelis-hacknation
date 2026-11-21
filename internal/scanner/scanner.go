// Package scanner contains discovery engines behind one interface:
//   - nmap:   production engine (parallel chunks, --max-rate, XML output)
//   - native: dependency-free TCP-connect scanner (fallback when nmap missing)
//   - sim:    deterministic simulated network for demos and tests
package scanner

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PortResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Name    string `json:"name"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Extra   string `json:"extra,omitempty"`
	Tunnel  string `json:"tunnel,omitempty"`
	Banner  string `json:"banner,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type HostResult struct {
	Address  string       `json:"address"`
	Hostname string       `json:"hostname,omitempty"`
	Target   string       `json:"target,omitempty"` // original scope entry (domain) if different
	Up       bool         `json:"up"`
	Reason   string       `json:"reason,omitempty"`
	OS       string       `json:"os,omitempty"`
	Ports    []PortResult `json:"ports,omitempty"`
}

type Options struct {
	Ports            string // "top:100" or nmap-style list "22,80,443,8000-8100"
	RatePPS          int    // per-engine-invocation max packet/connection rate
	Timing           string // T0..T4
	ServiceDetection bool
	Privileged       bool
	Extra            []string // validated extra nmap flags
	HostTimeout      time.Duration
	Generation       int       // scan sequence number (simulator only)
	Now              time.Time // scan start (simulator only)
}

type Engine interface {
	Name() string
	Scan(ctx context.Context, targets []string, o Options) ([]HostResult, error)
}

var portsRe = regexp.MustCompile(`^(top:\d{1,5}|[0-9TU:,\-]+)$`)

// ValidatePorts checks a port spec.
func ValidatePorts(spec string) error {
	spec = strings.TrimSpace(spec)
	if len(spec) > 2000 || !portsRe.MatchString(spec) {
		return fmt.Errorf("invalid port spec %q (use e.g. top:1000 or 22,80,443,8000-8100)", spec)
	}
	if strings.HasPrefix(spec, "top:") {
		n, _ := strconv.Atoi(spec[4:])
		if n < 1 || n > 65535 {
			return fmt.Errorf("top:N must be 1..65535")
		}
		return nil
	}
	_, err := ExpandPorts(spec)
	return err
}

// TopPorts is a frequency-ordered list of the most common TCP ports (subset of
// nmap-services ranking, extended with typical web/admin/IoT ports).
var TopPorts = []int{80, 443, 22, 21, 23, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
	9200, 5601, 6379, 27017, 11211, 1883, 8883, 502, 9090, 9443, 8291, 2082, 2083, 2086, 2087, 5001, 8089, 7001, 4443, 10443}

// ExpandPorts converts a spec to a sorted unique port list (TCP only).
func ExpandPorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "top:") {
		n, _ := strconv.Atoi(spec[4:])
		if n > len(TopPorts) {
			n = len(TopPorts)
		}
		out := append([]int(nil), TopPorts[:n]...)
		sort.Ints(out)
		return out, nil
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "T:")
		if part == "" || strings.HasPrefix(part, "U:") {
			continue
		}
		lo, hi := part, part
		if i := strings.Index(part, "-"); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, e1 := strconv.Atoi(lo)
		b, e2 := strconv.Atoi(hi)
		if e1 != nil || e2 != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		for p := a; p <= b; p++ {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no TCP ports in %q", spec)
	}
	return out, nil
}

// Safe extra nmap arguments. Anything else is rejected - prevents command
// injection (e.g. -oN /etc/…, --script exploit) and intrusive options.
var allowedExtra = map[string]*regexp.Regexp{
	"--version-light":        nil,
	"--version-all":          nil,
	"--version-intensity":    regexp.MustCompile(`^[0-9]$`),
	"--max-retries":          regexp.MustCompile(`^[0-5]$`),
	"--min-hostgroup":        regexp.MustCompile(`^\d{1,4}$`),
	"--max-hostgroup":        regexp.MustCompile(`^\d{1,4}$`),
	"--max-rtt-timeout":      regexp.MustCompile(`^\d{1,5}ms$`),
	"--initial-rtt-timeout":  regexp.MustCompile(`^\d{1,5}ms$`),
	"--defeat-rst-ratelimit": nil,
	"--script":               regexp.MustCompile(`^(banner|http-title|http-headers|ssl-cert|http-favicon|http-server-header|ssh-hostkey)(,(banner|http-title|http-headers|ssl-cert|http-favicon|http-server-header|ssh-hostkey))*$`),
	"-Pn":                    nil,
	"-n":                     nil,
	"-R":                     nil,
	"-O":                     nil,
	"--osscan-limit":         nil,
	"-6":                     nil,
}

// ParseExtra validates "extra nmap flags" from job config.
func ParseExtra(s string) ([]string, error) {
	f := strings.Fields(s)
	var out []string
	for i := 0; i < len(f); i++ {
		arg := f[i]
		val := ""
		if j := strings.Index(arg, "="); j > 0 {
			arg, val = arg[:j], arg[j+1:]
		}
		re, ok := allowedExtra[arg]
		if !ok {
			return nil, fmt.Errorf("nmap flag %q is not on the safety allowlist", f[i])
		}
		if re == nil {
			if val != "" {
				return nil, fmt.Errorf("flag %s takes no value", arg)
			}
			out = append(out, arg)
			continue
		}
		if val == "" {
			if i+1 >= len(f) {
				return nil, fmt.Errorf("flag %s needs a value", arg)
			}
			i++
			val = f[i]
		}
		if !re.MatchString(val) {
			return nil, fmt.Errorf("value %q not allowed for %s", val, arg)
		}
		out = append(out, arg, val)
	}
	return out, nil
}

var timingRe = regexp.MustCompile(`^T[0-4]$`)

func ValidateTiming(t string) error {
	if !timingRe.MatchString(t) {
		return fmt.Errorf("timing must be T0..T4 (T5 'insane' is disallowed for safety)")
	}
	return nil
}

// Engines registry.
type Registry map[string]Engine

func (r Registry) Get(name string) (Engine, error) {
	e, ok := r[name]
	if !ok {
		return nil, fmt.Errorf("scan engine %q not available", name)
	}
	return e, nil
}

func (r Registry) Names() []string {
	var n []string
	for k := range r {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}
