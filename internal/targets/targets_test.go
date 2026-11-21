package targets

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":           KindIP,
		"10.0.0.7/24":        KindCIDR,
		"10.0.0.1-10.0.0.9":  KindRange,
		"10.0.0.1-20":        KindRange,
		"staging.agh.edu.pl": KindDomain,
		"::1":                KindIPv6,
	}
	for in, kind := range cases {
		tg, err := Classify(in)
		if err != nil || tg.Kind != kind {
			t.Errorf("%s: got %+v %v want %s", in, tg, err, kind)
		}
	}
	if tg, _ := Classify("10.0.0.7/24"); tg.Value != "10.0.0.0/24" || tg.Count != 256 {
		t.Errorf("cidr normalisation: %+v", tg)
	}
	for _, bad := range []string{"", "10.0.0.1;rm -rf", "10.0.0.300", "-oX /etc/passwd", "1.2.3.4-1.2.3.1"} {
		if _, err := Classify(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestSpaceLargeMergeExclude(t *testing.T) {
	s, err := Build([]string{"10.10.0.0/18", "10.10.0.0/24", "10.10.63.250-10.10.64.5", "example.org"},
		[]string{"10.10.1.0/24", "10.10.0.1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// /18 = 16384, overlapping /24 adds 0, range adds 6 beyond the /18, minus 256 minus 1, plus 1 domain.
	want := int64(16384 + 6 - 256 - 1 + 1)
	if s.Len() != want {
		t.Fatalf("len=%d want %d", s.Len(), want)
	}
	if s.At(0) != "10.10.0.0" || s.At(1) != "10.10.0.2" {
		t.Fatalf("exclusion not applied: %s %s", s.At(0), s.At(1))
	}
	if s.At(s.Len()-1) != "example.org" {
		t.Fatal("names must come last")
	}
	if s.Contains("10.10.1.5") || !s.Contains("10.10.64.5") || !s.Contains("example.org") {
		t.Fatal("contains mismatch")
	}
	seen := map[string]bool{}
	for i := int64(0); i < s.Len(); i++ {
		v := s.At(i)
		if seen[v] {
			t.Fatalf("duplicate %s", v)
		}
		seen[v] = true
	}
	if len(s.Slice(100, 200)) != 100 {
		t.Fatal("slice size")
	}
}

func TestSafetyLimit(t *testing.T) {
	if _, err := Build([]string{"10.0.0.0/8"}, nil, 1<<20); err == nil {
		t.Fatal("expected safety limit error")
	}
}

func TestParseList(t *testing.T) {
	got := ParseList("10.0.0.1, 10.0.0.2\n# comment\nexample.com ; 10.0.1.0/24 # tail")
	if len(got) != 4 {
		t.Fatalf("got %v", got)
	}
}
