package dojo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestImportFindingsMultipart(t *testing.T) {
	var got struct {
		auth, scanType, product, engagement, autoCreate string
		report                                          Report
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/user_profile/" {
			w.Write([]byte(`{"user":{"username":"asi-bot"}}`))
			return
		}
		if r.URL.Path != "/api/v2/import-scan/" || r.Method != http.MethodPost {
			http.Error(w, "bad path", 404)
			return
		}
		got.auth = r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		got.scanType = r.FormValue("scan_type")
		got.product = r.FormValue("product_name")
		got.engagement = r.FormValue("engagement_name")
		got.autoCreate = r.FormValue("auto_create_context")
		f, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "no file", 400)
			return
		}
		b, _ := io.ReadAll(f)
		json.Unmarshal(b, &got.report)
		w.WriteHeader(201)
		w.Write([]byte(`{"test":42,"engagement_id":7,"product_id":3}`))
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, APIKey: "secret-key-1234", ProductName: "AGH", EngagementName: "ASI"})
	if u, err := c.Ping(context.Background()); err != nil || u != "asi-bot" {
		t.Fatalf("ping: %v %q", err, u)
	}
	rep := Report{Findings: []Finding{{Title: "Jenkins exposed", Severity: "Info", Description: "x", UniqueIDFromTool: "asi-svc-1",
		Endpoints: []Endpoint{{Host: "10.0.0.1", Port: 8080, Protocol: "http"}}, Files: []File{Evidence("headers.txt", "X-Jenkins: 2.401")}}}}
	res, err := c.ImportFindings(context.Background(), rep, []string{"asi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.TestID != 42 || got.auth != "Token secret-key-1234" || got.scanType != "Generic Findings Import" || got.autoCreate != "true" || got.product != "AGH" {
		t.Fatalf("unexpected request: %+v res=%+v", got, res)
	}
	if len(got.report.Findings) != 1 || got.report.Findings[0].Endpoints[0].Port != 8080 {
		t.Fatalf("report: %+v", got.report)
	}
	ev, _ := base64.StdEncoding.DecodeString(got.report.Findings[0].Files[0].Data)
	if string(ev) != "X-Jenkins: 2.401" {
		t.Fatal("evidence file")
	}
	if m := c.cfg.Masked(); m.APIKey == "secret-key-1234" {
		t.Fatal("masking")
	}
}

func TestErrorsSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"Invalid token."}`, 401)
	}))
	defer srv.Close()
	if _, err := New(Config{URL: srv.URL, APIKey: "x", EngagementID: 1}).Ping(context.Background()); err == nil {
		t.Fatal("expected auth error")
	}
	if (Config{URL: "ftp://x", APIKey: "k", EngagementID: 1}).Valid() == nil {
		t.Fatal("bad scheme must be rejected")
	}
}
