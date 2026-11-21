package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"asi/internal/recon"
	"asi/internal/store"
	"asi/internal/targets"
	"asi/internal/vulns"
)

// SetVulnClient enables the CVE escalation step.
func (m *Manager) SetVulnClient(c *vulns.Client) { m.vulns = c }

func (m *Manager) VulnLookupEnabled() bool { return m.vulns != nil }

// lookupVulns maps versions seen in the run to CPEs and stores known CVEs.
func (m *Manager) lookupVulns(ctx context.Context, run *store.Run) {
	bg := context.WithoutCancel(ctx)
	cands, err := m.st.VulnCandidates(bg, run.ID)
	if err != nil {
		m.cfg.Logf("run #%d vulns: %v", run.ID, err)
		return
	}
	seen := map[string]bool{}
	found := 0
	for _, c := range cands {
		key := fmt.Sprintf("%d|%s", c.ServiceID, strings.Join(vulns.CPEs(c.Product, c.Version), ","))
		if seen[key] {
			continue
		}
		seen[key] = true
		var all []vulns.Vuln
		dup := map[string]bool{}
		for _, cpe := range vulns.CPEs(c.Product, c.Version) {
			if ctx.Err() != nil {
				return
			}
			list, err := m.vulns.Lookup(ctx, cpe)
			if err != nil {
				m.cfg.Logf("run #%d vulns %s: %v", run.ID, cpe, err)
				continue
			}
			for _, v := range list {
				if !dup[v.CVE] {
					dup[v.CVE] = true
					v.Product, v.Version = c.Product, c.Version
					all = append(all, v)
				}
			}
		}
		if len(all) > 0 {
			if err := m.st.SaveVulns(bg, run.ID, run.JobID, c, all); err != nil {
				m.cfg.Logf("run #%d save vulns: %v", run.ID, err)
			}
			found += len(all)
		}
	}
	m.cfg.Logf("run #%d: CVE lookup done - %d candidate component(s), %d known CVE(s)", run.ID, len(seen), found)
}

// MaxQuickSubdomains caps how many resolving subdomains a quick scan covers.
const MaxQuickSubdomains = 128

// SubdomainBase returns the domain to enumerate subdomains for: a leading
// "www." label is dropped (www.example.org -> example.org).
func SubdomainBase(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if strings.HasPrefix(d, "www.") && strings.Count(d, ".") >= 2 {
		return d[4:]
	}
	return d
}

// PublicDomain reports whether Certificate Transparency can know the name:
// single-label names (localhost, docker service names) and local-only
// suffixes are never sent to crt.sh.
func PublicDomain(d string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if !strings.Contains(d, ".") {
		return false
	}
	for _, suf := range []string{".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".home.arpa", ".test", ".example", ".invalid", ".localdomain"} {
		if strings.HasSuffix(d, suf) {
			return false
		}
	}
	return true
}

// findQuickJob returns the most recent quick job with the given name.
func (m *Manager) findQuickJob(ctx context.Context, name string) *store.Job {
	jobs, err := m.st.ListJobs(store.WithScope(context.WithoutCancel(ctx), store.ScopeAll))
	if err != nil {
		return nil
	}
	for i := len(jobs) - 1; i >= 0; i-- {
		if jobs[i].Quick && jobs[i].Name == name {
			return jobs[i]
		}
	}
	return nil
}

// QuickScanRequest is the "type a target and press Scan" input.
type QuickScanRequest struct {
	Target     string `json:"target"`
	Subdomains bool   `json:"subdomains"`
	Vulns      bool   `json:"vulns"`
	Profile    string `json:"profile"` // auto (default) | fast | standard | full
	Authorized bool   `json:"authorized"`
}

type QuickScanResult struct {
	Job        *store.Job        `json:"job"`
	Run        *store.Run        `json:"run"`
	Subdomains []recon.Subdomain `json:"subdomains"`
	Warning    string            `json:"warning,omitempty"`
}

// ExtendedPorts covers the well-known range plus ports typical for internal,
// developer and container deployments (web UIs, admin panels, databases,
// message brokers, proxies) that nmap's internet-tuned top-1000 misses
// (e.g. 5672/15672 RabbitMQ, 8474 Toxiproxy, 8787, 15432, 2223, 6379).
const ExtendedPorts = "1-1100,1433,1521,1723,1883,2049,2082-2083,2086-2087,2181,2222-2223,2375-2376,2379,3000-3010,3128,3306,3389,3690," +
	"4000,4200,4369,4443-4444,4848,5000-5010,5050,5060,5222,5432-5433,5555,5601,5671-5673,5800,5900-5901,5984-5985,6000,6379,6443,6666," +
	"7000-7001,7070,7443,7474,7687,8000-8100,8118,8123,8161,8181,8200,8291,8333,8443-8444,8474,8500,8530-8531,8545,8600,8666,8686,8761," +
	"8787,8800,8834,8880-8890,8983,9000-9100,9200,9300,9418,9443,9999-10000,10250,10443,11211,15432,15672-15673,16010,25672,27017-27018," +
	"28017,50000,50070"

// AutoFullMaxAddrs: the "auto" profile scans all ports up to this many addresses.
const AutoFullMaxAddrs = 16

var profiles = map[string]struct {
	ports string
	rate  int
}{
	"fast":     {"top:100", 300},
	"standard": {ExtendedPorts, 500},
	"full":     {"1-65535", 1000},
}

// QuickScan builds a one-off job from a single target and starts it at once:
// subdomains (passive) -> ports & services -> web fingerprint -> CVEs.
func (m *Manager) QuickScan(ctx context.Context, in QuickScanRequest, user string) (*QuickScanResult, error) {
	if !in.Authorized {
		return nil, errors.New("potwierdź, że masz zgodę właściciela na skanowanie tego celu")
	}
	in.Target = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(in.Target, "https://"), "http://"))
	in.Target = strings.TrimSuffix(strings.SplitN(in.Target, "/", 2)[0], ".")
	var list []string
	for _, t := range targets.ParseList(in.Target) {
		list = append(list, t)
	}
	if len(list) == 0 {
		return nil, errors.New("podaj cel: domenę, adres IP, zakres lub CIDR")
	}
	var kinds []string
	total := int64(0)
	for _, t := range list {
		tg, err := targets.Classify(t)
		if err != nil {
			return nil, err
		}
		kinds = append(kinds, tg.Kind)
		total += tg.Count
	}
	if in.Profile == "full" && total > 256 {
		return nil, fmt.Errorf("profil pełny (wszystkie 65535 portów) jest dostępny dla maks. 256 adresów")
	}
	if total > 4096 {
		return nil, fmt.Errorf("szybki skan obsługuje do 4096 adresów (podano %d) – dla większych zakresów utwórz zwykłe zadanie", total)
	}
	res := &QuickScanResult{Subdomains: []recon.Subdomain{}}
	tin := []store.TargetInput{}
	for _, t := range list {
		tin = append(tin, store.TargetInput{Value: t, Tags: []string{"szybki-skan"}})
	}
	if in.Subdomains && len(list) == 1 && kinds[0] == targets.KindDomain && PublicDomain(list[0]) {
		// "www.example.org" has no subdomains of its own: enumerate the
		// parent domain, otherwise only the typed name would be scanned.
		base := SubdomainBase(list[0])
		subs, err := recon.Subdomains(ctx, base, 0)
		if err != nil {
			res.Warning = "Nie udało się pobrać subdomen (" + err.Error() + ") – skanuję tylko podaną domenę."
		} else {
			if len(subs) > MaxQuickSubdomains {
				res.Warning = fmt.Sprintf("Znaleziono %d aktywnych subdomen %s – szybki skan obejmie pierwsze %d. Dla pełnego zakresu utwórz zwykłe zadanie.",
					len(subs), base, MaxQuickSubdomains)
				subs = subs[:MaxQuickSubdomains]
			}
			res.Subdomains = subs
			for _, s := range subs {
				if s.Name != list[0] {
					tin = append(tin, store.TargetInput{Value: s.Name, Tags: []string{"szybki-skan", "subdomena"}, Note: "z Certificate Transparency (crt.sh)"})
				}
			}
		}
	}
	// "auto": a handful of hosts (localhost, one server, a lab) gets every port,
	// so services on non-standard ports are not missed; larger scopes the
	// extended list. Decided after subdomain expansion.
	addrs := total + int64(len(tin)-len(list))
	if in.Profile == "" || in.Profile == "auto" {
		in.Profile = "standard"
		if addrs <= AutoFullMaxAddrs {
			in.Profile = "full"
		}
	}
	// the run's packet budget is split between parallel nmap processes and
	// chunks are cut by target, so never run more workers than targets
	// (one host scanned by 1 of 4 workers would get only 1/4 of the rate)
	conc := int(min(4, max(1, addrs)))
	p, ok := profiles[in.Profile]
	if !ok {
		in.Profile = "fast"
		p = profiles["fast"]
	}
	engine := "nmap"
	if _, err := m.engines.Get("nmap"); err != nil {
		engine = "native"
	}
	rate := p.rate
	if m.cfg.MaxRate > 0 && rate > m.cfg.MaxRate {
		rate = m.cfg.MaxRate
	}
	j := &store.Job{Name: "Szybki skan: " + in.Target, Description: fmt.Sprintf("Utworzony z formularza „Szybki skan” przez %s (profil %s).", user, in.Profile),
		Enabled: true, Engine: engine, Ports: p.ports, RatePPS: rate, HTTPRPS: 10, Concurrency: conc, ChunkTargetSec: 60, Timing: "T3",
		ServiceDetection: true, HTTPFingerprint: true, PathProbes: true, WindowAlways: true, Timezone: "Europe/Warsaw",
		IntervalMinutes: 0, InactiveAfter: 3, ReprobeAttempts: 1, ReprobeDelaySec: 10, Quick: true, VulnLookup: in.Vulns && m.vulns != nil}
	j.Defaults()
	if err := j.Validate(m.cfg.MaxRate); err != nil {
		return nil, err
	}
	// Re-scanning the same target reuses its quick job, so the new run is
	// compared with the previous one (new / gone / changed services) instead
	// of starting another baseline that reports nothing new.
	var id int64
	if prev := m.findQuickJob(ctx, j.Name); prev != nil {
		if ar, err := m.st.ActiveRun(ctx, prev.ID); err == nil {
			return nil, fmt.Errorf("skan tego celu już trwa (przebieg #%d)", ar.ID)
		}
		j.ID, j.NextRunAt = prev.ID, prev.NextRunAt
		if err := m.st.UpdateJob(ctx, j); err != nil {
			return nil, err
		}
		if err := m.st.DeleteAllTargets(ctx, prev.ID); err != nil {
			return nil, err
		}
		id = prev.ID
	} else {
		var err error
		if id, err = m.st.CreateJob(ctx, j); err != nil {
			return nil, err
		}
	}
	if _, err := m.st.AddTargets(ctx, id, tin, "quick", m.cfg.MaxTargets); err != nil {
		if j.ID == 0 {
			m.st.DeleteJob(ctx, id)
		}
		return nil, err
	}
	run, err := m.StartRun(ctx, id, "quick", true, user)
	if err != nil {
		return nil, err
	}
	res.Job, _ = m.st.GetJob(ctx, id)
	res.Run = run
	return res, nil
}
