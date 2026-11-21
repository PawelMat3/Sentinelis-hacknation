// Package window implements recurring scan time windows, e.g. "Mon-Fri
// 22:00-06:00 Europe/Warsaw". Windows may cross midnight; the weekday flag
// refers to the day on which the window opens.
package window

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Window struct {
	Always   bool
	Days     [7]bool // indexed by time.Weekday (0 = Sunday)
	StartMin int
	EndMin   int
	Loc      *time.Location
}

// Parse builds a window. days is a 7-char mask Monday..Sunday, e.g. "1111100".
// start/end are "HH:MM". start == end means the whole day.
func Parse(days, start, end, tz string, always bool) (Window, error) {
	w := Window{Always: always}
	loc, err := time.LoadLocation(tz)
	if err != nil || tz == "" {
		loc = time.UTC
		if tz != "" && tz != "UTC" {
			return w, fmt.Errorf("unknown timezone %q", tz)
		}
	}
	w.Loc = loc
	if always {
		for i := range w.Days {
			w.Days[i] = true
		}
		return w, nil
	}
	if len(days) != 7 || strings.Trim(days, "01") != "" {
		return w, fmt.Errorf("days mask must be 7 chars of 0/1 (Mon..Sun), got %q", days)
	}
	for i, c := range days {
		wd := time.Weekday((i + 1) % 7) // Mon=1 ... Sun=0
		w.Days[wd] = c == '1'
	}
	if w.StartMin, err = parseHM(start); err != nil {
		return w, err
	}
	if w.EndMin, err = parseHM(end); err != nil {
		return w, err
	}
	return w, nil
}

func parseHM(s string) (int, error) {
	p := strings.Split(strings.TrimSpace(s), ":")
	if len(p) != 2 {
		return 0, fmt.Errorf("time must be HH:MM, got %q", s)
	}
	h, e1 := strconv.Atoi(p[0])
	m, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || h < 0 || h > 24 || m < 0 || m > 59 || (h == 24 && m != 0) {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}

func (w Window) at(day time.Time, min int) time.Time {
	return time.Date(day.Year(), day.Month(), day.Day(), min/60, min%60, 0, 0, w.Loc)
}

func (w Window) span(day time.Time) (time.Time, time.Time) {
	s := w.at(day, w.StartMin)
	var e time.Time
	if w.EndMin <= w.StartMin { // crosses midnight, or full day when equal
		e = w.at(day.AddDate(0, 0, 1), w.EndMin)
	} else {
		e = w.at(day, w.EndMin)
	}
	return s, e
}

// Span returns the window instance containing t.
func (w Window) Span(t time.Time) (start, end time.Time, ok bool) {
	if w.Always {
		return time.Time{}, time.Time{}, true
	}
	t = t.In(w.Loc)
	for _, d := range []int{0, -1} {
		day := time.Date(t.Year(), t.Month(), t.Day()+d, 0, 0, 0, 0, w.Loc)
		if !w.Days[day.Weekday()] {
			continue
		}
		s, e := w.span(day)
		if !t.Before(s) && t.Before(e) {
			return s, e, true
		}
	}
	return time.Time{}, time.Time{}, false
}

func (w Window) IsOpen(t time.Time) bool { _, _, ok := w.Span(t); return ok }

// End returns when the window containing t closes; zero for Always or closed.
func (w Window) End(t time.Time) time.Time { _, e, _ := w.Span(t); return e }

// NextOpen returns t if the window is open, else the next opening instant.
func (w Window) NextOpen(t time.Time) time.Time {
	if w.IsOpen(t) {
		return t
	}
	lt := t.In(w.Loc)
	for d := 0; d <= 8; d++ {
		day := time.Date(lt.Year(), lt.Month(), lt.Day()+d, 0, 0, 0, 0, w.Loc)
		if !w.Days[day.Weekday()] {
			continue
		}
		if s, _ := w.span(day); s.After(t) {
			return s
		}
	}
	return time.Time{}
}

// Length is the duration of one window instance.
func (w Window) Length() time.Duration {
	if w.Always {
		return 24 * time.Hour
	}
	d := w.EndMin - w.StartMin
	if d <= 0 {
		d += 24 * 60
	}
	return time.Duration(d) * time.Minute
}

func (w Window) String() string {
	if w.Always {
		return "zawsze (24/7)"
	}
	names := []string{"Nd", "Pn", "Wt", "Śr", "Cz", "Pt", "So"}
	var ds []string
	for i := 1; i <= 7; i++ {
		if w.Days[i%7] {
			ds = append(ds, names[i%7])
		}
	}
	return fmt.Sprintf("%s %02d:%02d-%02d:%02d %s", strings.Join(ds, ","), w.StartMin/60, w.StartMin%60, w.EndMin/60, w.EndMin%60, w.Loc)
}
