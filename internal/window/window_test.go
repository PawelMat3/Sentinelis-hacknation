package window

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T) *time.Location {
	l, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("tzdata missing")
	}
	return l
}

func TestOvernightWindow(t *testing.T) {
	loc := mustLoc(t)
	// Mon-Fri 22:00-06:00
	w, err := Parse("1111100", "22:00", "06:00", "Europe/Warsaw", false)
	if err != nil {
		t.Fatal(err)
	}
	mon2330 := time.Date(2026, 11, 23, 23, 30, 0, 0, loc) // Monday
	if !w.IsOpen(mon2330) {
		t.Fatal("Mon 23:30 should be open")
	}
	tue0300 := time.Date(2026, 11, 24, 3, 0, 0, 0, loc)
	if !w.IsOpen(tue0300) {
		t.Fatal("Tue 03:00 belongs to Monday's window")
	}
	if e := w.End(tue0300); !e.Equal(time.Date(2026, 11, 24, 6, 0, 0, 0, loc)) {
		t.Fatalf("end=%v", e)
	}
	if w.IsOpen(time.Date(2026, 11, 24, 12, 0, 0, 0, loc)) {
		t.Fatal("noon closed")
	}
	// Saturday 02:00 belongs to Friday's window -> open; Sunday 02:00 -> Saturday disabled -> closed.
	if !w.IsOpen(time.Date(2026, 11, 28, 2, 0, 0, 0, loc)) {
		t.Fatal("Sat 02:00 open (Friday window)")
	}
	if w.IsOpen(time.Date(2026, 11, 29, 2, 0, 0, 0, loc)) {
		t.Fatal("Sun 02:00 closed")
	}
	// Next open after Saturday noon is Monday 22:00.
	n := w.NextOpen(time.Date(2026, 11, 28, 12, 0, 0, 0, loc))
	if !n.Equal(time.Date(2026, 11, 30, 22, 0, 0, 0, loc)) {
		t.Fatalf("next open = %v", n)
	}
}

func TestDaytimeAndAlways(t *testing.T) {
	loc := mustLoc(t)
	w, _ := Parse("1111111", "08:00", "16:00", "Europe/Warsaw", false)
	if !w.IsOpen(time.Date(2026, 11, 22, 8, 0, 0, 0, loc)) || w.IsOpen(time.Date(2026, 11, 22, 16, 0, 0, 0, loc)) {
		t.Fatal("start inclusive, end exclusive")
	}
	if w.Length() != 8*time.Hour {
		t.Fatal("length")
	}
	a, _ := Parse("", "", "", "UTC", true)
	if !a.IsOpen(time.Now()) || !a.End(time.Now()).IsZero() {
		t.Fatal("always window")
	}
	full, _ := Parse("0000001", "00:00", "00:00", "Europe/Warsaw", false) // Sunday all day
	if !full.IsOpen(time.Date(2026, 11, 22, 23, 59, 0, 0, loc)) || full.IsOpen(time.Date(2026, 11, 23, 0, 1, 0, 0, loc)) {
		t.Fatal("full-day window")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse("111", "22:00", "06:00", "UTC", false); err == nil {
		t.Fatal("bad mask")
	}
	if _, err := Parse("1111111", "25:00", "06:00", "UTC", false); err == nil {
		t.Fatal("bad hour")
	}
}
