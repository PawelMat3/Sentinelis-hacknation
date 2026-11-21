package analysis

import (
	"sort"
	"strings"

	"asi/internal/fingerprint"
)

// Reason explains one contribution to a curiosity score.
type Reason struct {
	Code   string `json:"code"`
	Points int    `json:"points"`
	Text   string `json:"text"`
}

// ScoreInput is everything that influences analytical priority of a service.
type ScoreInput struct {
	Port       int
	Name       string
	Detections []fingerprint.Detection
	Insights   []fingerprint.Insight
	HTTP       *fingerprint.HTTPInfo
	IsNew      bool
	Changed    []FieldChange
	HostState  string
}

var riskyPorts = map[int]string{23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC", 445: "SMB", 139: "NetBIOS", 3306: "MySQL",
	5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 502: "Modbus",
	1883: "MQTT", 2375: "Docker API", 8291: "Winbox"}

// Score computes the curiosity score (0..100), a priority bucket and the
// reasons. Signals: signature curiosity, interesting categories, risky
// exposed ports, TLS problems, header/cookie insights, novelty and change.
func Score(in ScoreInput) (int, string, []Reason) {
	var rs []Reason
	add := func(code string, pts int, text string) {
		for _, r := range rs {
			if r.Code == code {
				return
			}
		}
		rs = append(rs, Reason{code, pts, text})
	}
	for _, d := range in.Detections {
		if d.Curiosity > 0 {
			// scale by confidence: a 50%-sure admin panel is worth less
			pts := d.Curiosity * max(d.Confidence, 40) / 100
			add("sig:"+d.Name, pts, d.Name+" ("+itoa(d.Confidence)+"% pewności)")
		}
	}
	if name, ok := riskyPorts[in.Port]; ok {
		covered := false
		for _, r := range rs {
			if strings.Contains(strings.ToLower(r.Text), strings.ToLower(name)) {
				covered = true
			}
		}
		if !covered {
			add("risky-port", 15, "Wystawiona usługa wysokiego ryzyka: "+name)
		}
	}
	for _, i := range in.Insights {
		add("insight:"+i.Code, i.Points, i.Text)
	}
	if in.HTTP != nil && in.HTTP.StatusCode > 0 && in.Port != 80 && in.Port != 443 && in.HTTP.Error == "" {
		add("nonstandard-web-port", 3, "Aplikacja WWW na niestandardowym porcie "+itoa(in.Port))
	}
	if in.IsNew {
		add("new-service", 12, "Nowa usługa (pojawiła się w tym przebiegu)")
	}
	if len(in.Changed) > 0 {
		var f []string
		for _, c := range in.Changed {
			f = append(f, c.Field)
		}
		add("changed", 8, "Zmiana od poprzedniego skanu: "+strings.Join(f, ", "))
	}
	if in.HostState == StateUnstable {
		add("unstable-host", 3, "Host niestabilny / okresowy")
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Points > rs[j].Points })
	total := 0
	for i, r := range rs {
		// diminishing returns for many small signals
		if i >= 4 {
			total += r.Points / 2
		} else {
			total += r.Points
		}
	}
	if total > 100 {
		total = 100
	}
	return total, Priority(total), rs
}

func Priority(score int) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	case score >= 8:
		return "low"
	default:
		return "info"
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
