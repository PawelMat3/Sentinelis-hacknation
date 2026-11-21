// Package analysis holds the pure decision logic (no I/O): host availability
// state machine with hour-of-day profiling, curiosity/priority scoring and
// service snapshot diffing.
package analysis

import (
	"fmt"
	"strings"
	"time"
)

// Host states.
const (
	StateActive   = "active"   // responded in the last scan
	StateUnstable = "unstable" // flapping / periodic availability
	StateSuspect  = "suspect"  // missed 1..N-1 consecutive scans (awaiting confirmation)
	StateInactive = "inactive" // missed >= N consecutive scans (confirmed gone)
)

// Host events emitted on transitions.
const (
	EvHostNew      = "host_new"
	EvHostReturned = "host_returned"
	EvHostSuspect  = "host_suspect"
	EvHostInactive = "host_inactive"
	EvHostUnstable = "host_unstable"
	EvHostStable   = "host_stable"
)

const historyLen = 32

// Policy tunes the state machine (per scan job).
type Policy struct {
	InactiveAfter  int // consecutive misses before a host is reported inactive
	UnstableWindow int // how many recent observations to look at for flapping
	UnstableFlips  int // transitions within window that mark a host unstable
}

func DefaultPolicy() Policy { return Policy{InactiveAfter: 3, UnstableWindow: 12, UnstableFlips: 3} }

// Track is the persisted availability state of a host.
type Track struct {
	State     string  `json:"state"`
	Misses    int     `json:"misses"`
	History   string  `json:"history"` // '1'/'0', oldest first, last historyLen observations
	HourUp    [24]int `json:"hour_up"`
	HourProbe [24]int `json:"hour_probe"`
	Probes    int     `json:"probes"`
	Ups       int     `json:"ups"`
}

// Flips counts up/down transitions in the last n observations.
func (t *Track) Flips(n int) int {
	h := t.History
	if len(h) > n {
		h = h[len(h)-n:]
	}
	f := 0
	for i := 1; i < len(h); i++ {
		if h[i] != h[i-1] {
			f++
		}
	}
	return f
}

// ExpectedDown reports whether, based on the hourly profile, the host is
// normally unreachable at this hour (enough samples, <=20% availability) while
// being reachable at other hours. Absence at such an hour is not news.
func (t *Track) ExpectedDown(hour int) bool {
	if t.HourProbe[hour] < 2 {
		return false
	}
	rate := float64(t.HourUp[hour]) / float64(t.HourProbe[hour])
	return rate <= 0.2 && t.Ups > 0
}

// Observe records one scan outcome at time at (local hour bucket) and applies
// the state machine. It returns the emitted event ("" if none).
func (t *Track) Observe(up bool, at time.Time, p Policy) string {
	if p.InactiveAfter <= 0 {
		p = DefaultPolicy()
	}
	hour := at.Hour()
	prev := t.State
	t.Probes++
	t.HourProbe[hour]++
	if up {
		t.Ups++
		t.HourUp[hour]++
		t.History += "1"
	} else {
		t.History += "0"
	}
	if len(t.History) > historyLen {
		t.History = t.History[len(t.History)-historyLen:]
	}
	flapping := t.Flips(p.UnstableWindow) >= p.UnstableFlips

	if up {
		t.Misses = 0
		switch {
		case prev == "":
			t.State = StateActive
			return EvHostNew
		case prev == StateInactive:
			t.State = StateActive
			if flapping {
				t.State = StateUnstable
			}
			return EvHostReturned
		case flapping:
			t.State = StateUnstable
			if prev != StateUnstable {
				return EvHostUnstable
			}
			return ""
		case prev == StateUnstable && strings.HasSuffix(t.History, "11111111"):
			t.State = StateActive
			return EvHostStable
		case prev == StateUnstable:
			return ""
		default:
			t.State = StateActive
			return ""
		}
	}

	// down
	if prev == StateInactive {
		return ""
	}
	if prev == StateUnstable || flapping {
		// Periodic hosts: absence in their usual "off" hours is expected and
		// does not count towards inactivity; otherwise require twice as much
		// evidence before declaring them gone.
		if !t.ExpectedDown(hour) {
			t.Misses++
		}
		if t.Misses >= 2*p.InactiveAfter {
			t.State = StateInactive
			return EvHostInactive
		}
		t.State = StateUnstable
		if prev != StateUnstable {
			return EvHostUnstable
		}
		return ""
	}
	t.Misses++
	if t.Misses >= p.InactiveAfter {
		t.State = StateInactive
		return EvHostInactive
	}
	t.State = StateSuspect
	if prev != StateSuspect {
		return EvHostSuspect
	}
	return ""
}

// Availability returns the overall availability ratio (0..1).
func (t *Track) Availability() float64 {
	if t.Probes == 0 {
		return 0
	}
	return float64(t.Ups) / float64(t.Probes)
}

// Pattern classifies the hour-of-day profile into a human label and the
// contiguous hours in which the host typically responds.
func (t *Track) Pattern() string {
	probed, upH, downH := 0, 0, 0
	for h := 0; h < 24; h++ {
		if t.HourProbe[h] == 0 {
			continue
		}
		probed++
		r := float64(t.HourUp[h]) / float64(t.HourProbe[h])
		if r >= 0.8 {
			upH++
		} else if r <= 0.2 {
			downH++
		}
	}
	switch {
	case t.Probes < 3 || probed < 2:
		return "za mało danych"
	case downH == 0 && upH == probed:
		return "stała dostępność"
	case upH == 0 && downH == probed:
		return "brak odpowiedzi"
	case upH+downH == probed && upH > 0 && downH > 0:
		return "okresowa: odpowiada w godz. " + t.UpHours()
	default:
		return fmt.Sprintf("niestabilna (%.0f%% odpowiedzi)", t.Availability()*100)
	}
}

// UpHours renders hours with >=80% availability as compact ranges ("8-18").
func (t *Track) UpHours() string {
	var parts []string
	start := -1
	for h := 0; h <= 24; h++ {
		ok := h < 24 && t.HourProbe[h] > 0 && float64(t.HourUp[h])/float64(t.HourProbe[h]) >= 0.8
		// treat unprobed hours between two up hours as up (sparse sampling)
		if h < 24 && t.HourProbe[h] == 0 && start >= 0 {
			ok = true
		}
		if ok && start < 0 {
			start = h
		}
		if !ok && start >= 0 {
			end := h - 1
			for end > start && t.HourProbe[end] == 0 {
				end--
			}
			parts = append(parts, fmt.Sprintf("%d-%d", start, end+1))
			start = -1
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
