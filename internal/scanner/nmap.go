package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// Nmap runs the nmap binary on a chunk of targets. Targets are passed on
// stdin (-iL -), never as argv, so scope entries cannot inject flags.
type Nmap struct {
	Path       string
	Privileged bool // raw sockets available (root / CAP_NET_RAW): SYN scan + ICMP discovery
}

func (n *Nmap) Name() string { return "nmap" }

// Version returns the nmap version line or an error when unavailable.
func (n *Nmap) Version() (string, error) {
	out, err := exec.Command(n.Path, "--version").Output()
	if err != nil {
		return "", err
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	return strings.TrimSpace(line), nil
}

// Args builds the nmap command line (exported for transparency in the UI).
func (n *Nmap) Args(o Options) []string {
	args := []string{"-oX", "-", "-iL", "-", "--noninteractive", "--max-retries", "2"}
	timing := o.Timing
	if timing == "" {
		timing = "T3"
	}
	args = append(args, "-"+timing)
	if o.RatePPS > 0 {
		args = append(args, "--max-rate", strconv.Itoa(o.RatePPS))
	}
	ht := o.HostTimeout
	if ht <= 0 {
		ht = 0
	}
	if ht > 0 {
		args = append(args, "--host-timeout", fmt.Sprintf("%ds", int(ht.Seconds())))
	}
	if n.Privileged || o.Privileged {
		args = append(args, "--privileged", "-sS", "-PE", "-PS21,22,25,80,443,445,3389,8080", "-PA80,443", "-PP")
	} else {
		args = append(args, "-sT", "-PS21,22,25,80,135,443,445,3389,8080,8443")
	}
	if strings.HasPrefix(o.Ports, "top:") {
		args = append(args, "--top-ports", o.Ports[4:])
	} else if o.Ports != "" {
		args = append(args, "-p", o.Ports)
	}
	if o.ServiceDetection {
		args = append(args, "-sV", "--version-intensity", "5")
	}
	// No --open: it drops hosts that answer host discovery but have no open
	// port in scope from the XML, and they would be recorded as down
	// (false "suspect"/"inactive" transitions). Non-open ports are filtered
	// in ParseNmapXML instead.
	args = append(args, "--reason")
	args = append(args, o.Extra...)
	return args
}

func (n *Nmap) Scan(ctx context.Context, targets []string, o Options) ([]HostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, n.Path, n.Args(o)...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err() // window closed / paused: chunk will be retried
	}
	if err != nil {
		return nil, fmt.Errorf("nmap: %v: %s", err, strings.TrimSpace(lastLine(stderr.String())))
	}
	res, err := ParseNmapXML(&stdout)
	if err != nil {
		return nil, err
	}
	return mapDomains(res, targets), nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// mapDomains attaches the user-supplied domain to results scanned by name.
func mapDomains(res []HostResult, targets []string) []HostResult {
	names := map[string]bool{}
	for _, t := range targets {
		names[strings.ToLower(t)] = true
	}
	for i := range res {
		if res[i].Hostname != "" && names[strings.ToLower(res[i].Hostname)] {
			res[i].Target = strings.ToLower(res[i].Hostname)
		}
	}
	return res
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames struct {
		Names []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Extra []struct {
			State string `xml:"state,attr"`
		} `xml:"extraports"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State  string `xml:"state,attr"`
				Reason string `xml:"reason,attr"`
			} `xml:"state"`
			Service struct {
				Name      string   `xml:"name,attr"`
				Product   string   `xml:"product,attr"`
				Version   string   `xml:"version,attr"`
				ExtraInfo string   `xml:"extrainfo,attr"`
				Tunnel    string   `xml:"tunnel,attr"`
				CPE       []string `xml:"cpe"`
			} `xml:"service"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []struct {
			Name     string `xml:"name,attr"`
			Accuracy int    `xml:"accuracy,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

// ParseNmapXML parses nmap -oX output (also used to import external results).
func ParseNmapXML(r io.Reader) ([]HostResult, error) {
	var run nmapRun
	dec := xml.NewDecoder(r)
	dec.Strict = false
	if err := dec.Decode(&run); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	var out []HostResult
	for _, h := range run.Hosts {
		hr := HostResult{Up: h.Status.State == "up", Reason: h.Status.Reason}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				hr.Address = a.Addr
				break
			}
		}
		if hr.Address == "" {
			continue
		}
		for _, n := range h.Hostnames.Names {
			if hr.Hostname == "" || n.Type == "user" {
				hr.Hostname = strings.ToLower(n.Name)
			}
		}
		if len(h.OS.Matches) > 0 {
			hr.OS = h.OS.Matches[0].Name
		}
		answered := false // the host itself replied on some port (open or RST)
		for _, e := range h.Ports.Extra {
			if e.State == "closed" {
				answered = true
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State == "closed" {
				answered = true
			}
			if p.State.State != "open" {
				continue
			}
			pr := PortResult{Port: p.PortID, Proto: p.Protocol, State: p.State.State, Name: p.Service.Name,
				Product: p.Service.Product, Version: p.Service.Version, Extra: p.Service.ExtraInfo, Tunnel: p.Service.Tunnel}
			if len(p.Service.CPE) > 0 {
				pr.CPE = p.Service.CPE[0]
			}
			for _, s := range p.Scripts {
				if s.ID == "banner" {
					pr.Banner = s.Output
				}
			}
			if pr.Tunnel == "ssl" && pr.Name == "http" {
				pr.Name = "https"
			}
			hr.Ports = append(hr.Ports, pr)
		}
		if len(hr.Ports) > 0 {
			hr.Up = true
		} else if hr.Reason == "user-set" && !answered {
			// -Pn: nmap marks every target "up" without probing it; with no
			// open or closed (RST) port there is no evidence the host is alive.
			hr.Up = false
		}
		out = append(out, hr)
	}
	return out, nil
}
