// Package targets parses scan scopes (IPs, CIDRs, ranges, domains) and builds
// an indexable, de-duplicated target Space. IPv4 scopes are stored as merged
// intervals, so a /16 (65 536 addresses) costs a few bytes and any address can
// be fetched by index in O(log n) - this is what lets the orchestrator carve
// adaptive chunks out of very large scopes without materialising them.
package targets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	KindIP     = "ip"
	KindCIDR   = "cidr"
	KindRange  = "range"
	KindDomain = "domain"
	KindIPv6   = "ipv6"
)

var hostnameRe = regexp.MustCompile(`^(?i:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?))*\.?$`)

// Target is a single normalised scope entry.
type Target struct {
	Value string `json:"value"`
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// Classify validates and normalises one scope entry.
func Classify(raw string) (Target, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return Target{}, errors.New("empty target")
	}
	if strings.ContainsAny(v, " \t;|&$`'\"<>") {
		return Target{}, fmt.Errorf("invalid characters in target %q", v)
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return Target{}, fmt.Errorf("invalid CIDR %q", v)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			return Target{Value: p.String(), Kind: KindCIDR, Count: int64(1) << (32 - p.Bits())}, nil
		}
		if p.Bits() < 120 {
			return Target{}, fmt.Errorf("IPv6 prefix %q too large (max /120)", v)
		}
		return Target{Value: p.String(), Kind: KindCIDR, Count: int64(1) << (128 - p.Bits())}, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if a.Is4() {
			return Target{Value: a.String(), Kind: KindIP, Count: 1}, nil
		}
		return Target{Value: a.String(), Kind: KindIPv6, Count: 1}, nil
	}
	if i := strings.Index(v, "-"); i > 0 && net.ParseIP(v[:i]) != nil {
		lo, hi, err := parseRange(v)
		if err != nil {
			return Target{}, err
		}
		return Target{Value: u2ip(lo) + "-" + u2ip(hi), Kind: KindRange, Count: int64(hi-lo) + 1}, nil
	}
	if len(v) <= 253 && hostnameRe.MatchString(v) && strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return Target{Value: strings.TrimSuffix(strings.ToLower(v), "."), Kind: KindDomain, Count: 1}, nil
	}
	return Target{}, fmt.Errorf("unrecognised target %q (expected IP, CIDR, range a.b.c.d-e or domain)", v)
}

func parseRange(v string) (uint32, uint32, error) {
	i := strings.Index(v, "-")
	a, err := netip.ParseAddr(v[:i])
	if err != nil || !a.Is4() {
		return 0, 0, fmt.Errorf("invalid range %q", v)
	}
	lo := ip2u(a)
	rest := v[i+1:]
	var hi uint32
	if b, err := netip.ParseAddr(rest); err == nil && b.Is4() {
		hi = ip2u(b)
	} else if n, err := strconv.Atoi(rest); err == nil && n >= 0 && n <= 255 {
		hi = lo&0xFFFFFF00 | uint32(n)
	} else {
		return 0, 0, fmt.Errorf("invalid range %q", v)
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("range %q is reversed", v)
	}
	return lo, hi, nil
}

func ip2u(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }
func u2ip(u uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b).String()
}

// ParseList splits free text (newline, comma, whitespace separated, # comments).
func ParseList(text string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' }) {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

type interval struct{ lo, hi uint32 } // inclusive

// Space is an ordered, de-duplicated, indexable set of scan targets.
type Space struct {
	ivs   []interval
	cum   []int64 // cum[i] = number of addresses before interval i
	ipv4N int64
	names []string // domains and IPv6 literals, appended after IPv4
}

// Build creates a Space from scope entries minus exclusions. max limits the
// total size (safety guard against accidental /8 scans); 0 = unlimited.
func Build(entries, exclusions []string, max int64) (*Space, error) {
	var ivs, ex []interval
	names := map[string]bool{}
	exNames := map[string]bool{}
	add := func(list []string, dst *[]interval, nm map[string]bool) error {
		for _, e := range list {
			t, err := Classify(e)
			if err != nil {
				return err
			}
			switch t.Kind {
			case KindIP:
				u := ip2u(netip.MustParseAddr(t.Value))
				*dst = append(*dst, interval{u, u})
			case KindCIDR:
				p := netip.MustParsePrefix(t.Value)
				if p.Addr().Is4() {
					lo := ip2u(p.Addr())
					*dst = append(*dst, interval{lo, lo + uint32(t.Count-1)})
				} else {
					for a := p.Addr(); p.Contains(a); a = a.Next() {
						nm[a.String()] = true
					}
				}
			case KindRange:
				lo, hi, _ := parseRange(t.Value)
				*dst = append(*dst, interval{lo, hi})
			default:
				nm[t.Value] = true
			}
		}
		return nil
	}
	if err := add(entries, &ivs, names); err != nil {
		return nil, err
	}
	if err := add(exclusions, &ex, exNames); err != nil {
		return nil, fmt.Errorf("exclusions: %w", err)
	}
	ivs = subtract(merge(ivs), merge(ex))
	s := &Space{ivs: ivs}
	s.cum = make([]int64, len(ivs))
	for i, iv := range ivs {
		s.cum[i] = s.ipv4N
		s.ipv4N += int64(iv.hi-iv.lo) + 1
	}
	for n := range names {
		if !exNames[n] {
			s.names = append(s.names, n)
		}
	}
	sort.Strings(s.names)
	if max > 0 && s.Len() > max {
		return nil, fmt.Errorf("scope has %d targets, exceeds safety limit %d (ASI_MAX_TARGETS)", s.Len(), max)
	}
	return s, nil
}

func merge(in []interval) []interval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo < in[j].lo })
	out := []interval{in[0]}
	for _, iv := range in[1:] {
		last := &out[len(out)-1]
		if uint64(iv.lo) <= uint64(last.hi)+1 {
			if iv.hi > last.hi {
				last.hi = iv.hi
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// subtract removes ex (merged) from in (merged).
func subtract(in, ex []interval) []interval {
	if len(ex) == 0 {
		return in
	}
	var out []interval
	for _, iv := range in {
		cur := []interval{iv}
		for _, e := range ex {
			var next []interval
			for _, c := range cur {
				if e.hi < c.lo || e.lo > c.hi {
					next = append(next, c)
					continue
				}
				if e.lo > c.lo {
					next = append(next, interval{c.lo, e.lo - 1})
				}
				if e.hi < c.hi {
					next = append(next, interval{e.hi + 1, c.hi})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return out
}

// Len is the total number of targets.
func (s *Space) Len() int64 { return s.ipv4N + int64(len(s.names)) }

// At returns the i-th target (0 <= i < Len).
func (s *Space) At(i int64) string {
	if i >= s.ipv4N {
		return s.names[i-s.ipv4N]
	}
	k := sort.Search(len(s.cum), func(j int) bool { return s.cum[j] > i }) - 1
	return u2ip(s.ivs[k].lo + uint32(i-s.cum[k]))
}

// Slice returns targets in [start, end).
func (s *Space) Slice(start, end int64) []string {
	if end > s.Len() {
		end = s.Len()
	}
	if start >= end {
		return nil
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, s.At(i))
	}
	return out
}

// Contains reports whether addr (IP literal or domain) is in the space.
func (s *Space) Contains(addr string) bool {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is4() {
		u := ip2u(a)
		k := sort.Search(len(s.ivs), func(j int) bool { return s.ivs[j].hi >= u })
		return k < len(s.ivs) && s.ivs[k].lo <= u
	}
	k := sort.SearchStrings(s.names, addr)
	return k < len(s.names) && s.names[k] == addr
}

// Summary describes the space for UI/logs.
func (s *Space) Summary() string {
	return fmt.Sprintf("%d IPv4 addresses in %d ranges, %d names", s.ipv4N, len(s.ivs), len(s.names))
}

// IsIP reports whether v is an IP literal.
func IsIP(v string) bool { _, err := netip.ParseAddr(v); return err == nil }
