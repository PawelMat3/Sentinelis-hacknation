package iox

import (
	"bytes"
	"strings"
	"testing"

	"asi/internal/store"
)

func TestTargetsFormats(t *testing.T) {
	csvIn := "value,tags,note\n10.0.0.0/24,dmz;web,Sieć DMZ\nexample.org,,\n"
	tg, err := ParseTargets("csv", []byte(csvIn))
	if err != nil || len(tg) != 2 || tg[0].Note != "Sieć DMZ" || len(tg[0].Tags) != 2 {
		t.Fatalf("csv: %+v %v", tg, err)
	}
	js := `[ "10.1.0.0/16", {"value":"staging.example.org","tags":["staging"],"note":"x"} ]`
	tg, err = ParseTargets("json", []byte(js))
	if err != nil || len(tg) != 2 || tg[1].Tags[0] != "staging" {
		t.Fatalf("json: %+v %v", tg, err)
	}
	tg, _ = ParseTargets("text", []byte("10.0.0.1\n10.0.0.2 # db\n"))
	if len(tg) != 2 {
		t.Fatal("text")
	}
	if Detect("x.json", []byte("[1]")) != "json" || Detect("scan.xml", nil) != "nmap" || Detect("a.csv", []byte("a,b")) != "csv" {
		t.Fatal("detect")
	}
}

func TestResultsRoundTripCSV(t *testing.T) {
	sv := &store.Service{Address: "10.0.0.5", Hostname: "h", HostState: "active", Port: 443, Proto: "tcp", Status: "open", Name: "https",
		Product: "nginx", Version: "1.18.0", Title: "=HYPERLINK(\"evil\")", Server: "nginx", HTTPStatus: 200, Priority: "low", Tags: []string{"a", "b"},
		Tech: []store.Tech{{Name: "nginx", Version: "1.18.0"}}}
	var buf bytes.Buffer
	buf.WriteString(strings.Join(CSVHeader, ",") + "\n")
	row := ServiceCSVRow(sv)
	if !strings.HasPrefix(row[12], "'=") {
		t.Fatal("formula injection not neutralised")
	}
	for i := range row {
		if strings.ContainsAny(row[i], ",\"") {
			row[i] = "\"" + strings.ReplaceAll(row[i], "\"", "\"\"") + "\""
		}
	}
	buf.WriteString(strings.Join(row, ",") + "\n")
	hosts, err := ParseResults("csv", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || len(hosts[0].Services) != 1 {
		t.Fatalf("%+v", hosts)
	}
	s := hosts[0].Services[0]
	if s.Port != 443 || s.Product != "nginx" || s.HTTP == nil || s.HTTP.Header("Server") != "nginx" || len(s.ImportTags) != 2 {
		t.Fatalf("service: %+v http=%+v", s, s.HTTP)
	}
}

func TestResultsJSONAndValidation(t *testing.T) {
	doc := `{"format":"asi-results/v1","hosts":[{"address":"10.9.9.9","state":"active","tags":["x"],"services":[{"port":8080,"proto":"tcp","name":"http","title":"Dashboard [Jenkins]","http_status":200}]}]}`
	h, err := ParseResults("json", []byte(doc))
	if err != nil || len(h) != 1 || h[0].Services[0].HTTP.Title != "Dashboard [Jenkins]" {
		t.Fatalf("%+v %v", h, err)
	}
	flat := `[{"ip":"10.1.1.1","port":22,"service":"ssh","product":"OpenSSH"},{"ip":"10.1.1.1","port":80}]`
	h, err = ParseResults("json", []byte(flat))
	if err != nil || len(h) != 1 || len(h[0].Services) != 2 {
		t.Fatalf("flat: %+v %v", h, err)
	}
	if _, err := ParseResults("json", []byte(`[{"ip":"not-an-ip","port":1}]`)); err == nil {
		t.Fatal("invalid ip must fail")
	}
}
