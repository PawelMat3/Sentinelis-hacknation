package analysis

import (
	"strings"
	"testing"
	"time"

	"asi/internal/fingerprint"
)

func at(h int) time.Time { return time.Date(2026, 11, 20, h, 0, 0, 0, time.UTC) }

func TestStableHostGoesSuspectThenInactive(t *testing.T) {
	p := DefaultPolicy()
	var tr Track
	if ev := tr.Observe(true, at(2), p); ev != EvHostNew || tr.State != StateActive {
		t.Fatalf("first sighting: %s %s", ev, tr.State)
	}
	for i := 0; i < 5; i++ {
		tr.Observe(true, at(3+i), p)
	}
	if ev := tr.Observe(false, at(9), p); ev != EvHostSuspect || tr.State != StateSuspect {
		t.Fatalf("1 miss -> suspect, got %s %s", ev, tr.State)
	}
	tr.Observe(false, at(10), p)
	if tr.State != StateSuspect {
		t.Fatal("2 misses still suspect")
	}
	if ev := tr.Observe(false, at(11), p); ev != EvHostInactive || tr.State != StateInactive {
		t.Fatalf("3 misses -> inactive, got %s %s", ev, tr.State)
	}
	if ev := tr.Observe(true, at(12), p); ev != EvHostReturned {
		t.Fatalf("return event, got %s", ev)
	}
}

func TestSuspectRecoversWithoutNoise(t *testing.T) {
	p := DefaultPolicy()
	var tr Track
	tr.Observe(true, at(1), p)
	tr.Observe(false, at(2), p)
	if ev := tr.Observe(true, at(3), p); ev != "" || tr.State != StateActive {
		t.Fatalf("single blip should recover silently, got %q %s", ev, tr.State)
	}
}

func TestPeriodicHostBecomesUnstableNotInactive(t *testing.T) {
	p := DefaultPolicy()
	var tr Track
	// Business-hours host scanned at 03:00 and 14:00 for 6 days.
	var events []string
	for d := 0; d < 6; d++ {
		if ev := tr.Observe(false, at(3), p); ev != "" {
			events = append(events, ev)
		}
		if ev := tr.Observe(true, at(14), p); ev != "" {
			events = append(events, ev)
		}
	}
	if tr.State != StateUnstable {
		t.Fatalf("expected unstable, got %s (events %v)", tr.State, events)
	}
	for _, e := range events {
		if e == EvHostInactive {
			t.Fatalf("periodic host must never be reported inactive: %v", events)
		}
	}
	if !tr.ExpectedDown(3) || tr.ExpectedDown(14) {
		t.Fatal("hourly profile wrong")
	}
	if pat := tr.Pattern(); !strings.HasPrefix(pat, "okresowa") || !strings.Contains(pat, "14-15") {
		t.Fatalf("pattern: %q", pat)
	}
	// Truly gone: misses at its usual "up" hour count.
	for i := 0; i < 6; i++ {
		tr.Observe(false, at(14), p)
	}
	if tr.State != StateInactive {
		t.Fatalf("periodic host silent in its up-hours should become inactive, got %s misses=%d", tr.State, tr.Misses)
	}
}

func TestDiffAndDigest(t *testing.T) {
	a := Snapshot{Name: "http", Product: "nginx", Version: "1.18.0", Status: 200, Title: "A", Tech: []string{"nginx 1.18.0", "PHP"}}
	b := a
	b.Tech = []string{"PHP", "nginx 1.18.0"}
	if a.Digest() != b.Digest() {
		t.Fatal("digest must be order independent")
	}
	b.Version = "1.24.0"
	b.Title = "B"
	ch := DiffSnapshots(a, b)
	if len(ch) != 2 || ch[0].Field != "version" || ch[1].Field != "title" {
		t.Fatalf("diff: %+v", ch)
	}
}

func TestScore(t *testing.T) {
	s, pr, rs := Score(ScoreInput{Port: 8080, Detections: []fingerprint.Detection{
		{Name: "Środowisko testowe / staging", Confidence: 99, Curiosity: 30},
		{Name: "Repozytorium .git dostępne", Confidence: 95, Curiosity: 40},
	}, IsNew: true})
	if s < 60 || pr != "critical" || len(rs) < 3 {
		t.Fatalf("score=%d pr=%s rs=%+v", s, pr, rs)
	}
	s2, pr2, _ := Score(ScoreInput{Port: 22, Detections: []fingerprint.Detection{{Name: "OpenSSH", Confidence: 95}}})
	if s2 != 0 || pr2 != "info" {
		t.Fatalf("plain ssh should be info, got %d %s", s2, pr2)
	}
	s3, _, _ := Score(ScoreInput{Port: 6379})
	if s3 < 15 {
		t.Fatalf("exposed redis should score, got %d", s3)
	}
}

func TestLatencyShift(t *testing.T) {
	cases := []struct {
		old, new int64
		want     bool
	}{
		{3, 540, true},     // proxy latency added (Toxiproxy 500 ms)
		{540, 4, true},     // latency removed
		{120, 260, false},  // normal jitter
		{900, 1100, false}, // slow but stable
		{0, 800, false},    // no baseline
		{50, 320, true},
	}
	for _, c := range cases {
		if _, got := LatencyShift(c.old, c.new); got != c.want {
			t.Errorf("LatencyShift(%d,%d)=%v want %v", c.old, c.new, got, c.want)
		}
	}
	a := Snapshot{Name: "http", RespMS: 3}
	b := Snapshot{Name: "http", RespMS: 900}
	if a.Digest() != b.Digest() {
		t.Fatal("response time must not change the digest")
	}
}
