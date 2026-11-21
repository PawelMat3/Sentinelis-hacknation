package scanner

import (
	"context"
	"time"

	"asi/internal/clock"
	"asi/internal/lab"
)

// Sim scans the deterministic lab.Model. It honours ports, generation and
// time-of-day behaviour and costs a configurable amount of (real or virtual)
// time per target so chunking, ETA and window logic are observable.
type Sim struct {
	Model       *lab.Model
	Clock       clock.Clock
	CostPerHost time.Duration
}

func (s *Sim) Name() string { return "sim" }

func (s *Sim) Scan(ctx context.Context, targets []string, o Options) ([]HostResult, error) {
	ports, err := ExpandPorts(o.Ports)
	if err != nil {
		return nil, err
	}
	allowed := map[int]bool{}
	for _, p := range ports {
		allowed[p] = true
	}
	now := o.Now
	if now.IsZero() {
		now = s.Clock.Now()
	}
	cost := time.Duration(len(targets)) * s.CostPerHost
	if err := s.Clock.Sleep(ctx, cost); err != nil {
		return nil, err
	}
	var out []HostResult
	for _, t := range targets {
		h, up := s.Model.Probe(t, now, o.Generation)
		hr := HostResult{Address: t, Up: up}
		if h.Address != "" {
			hr.Address = h.Address
			hr.Hostname = h.Hostname
			if h.Address != t {
				hr.Target = t
			}
		}
		if !up {
			out = append(out, hr)
			continue
		}
		hr.Reason = "syn-ack"
		for _, sv := range h.Services {
			if !allowed[sv.Port] {
				continue
			}
			pr := PortResult{Port: sv.Port, Proto: "tcp", State: "open", Name: sv.Name, Banner: sv.Banner, Tunnel: sv.Tunnel}
			if o.ServiceDetection {
				pr.Product, pr.Version = sv.Product, sv.Version
			}
			hr.Ports = append(hr.Ports, pr)
		}
		out = append(out, hr)
	}
	return out, nil
}
