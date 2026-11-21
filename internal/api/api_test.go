package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asi/internal/clock"
	"asi/internal/crypto"
	"asi/internal/lab"
	"asi/internal/orchestrator"
	"asi/internal/scanner"
	"asi/internal/store"
)

const pw = "Test-Password-123"

type client struct {
	t   *testing.T
	srv *httptest.Server
	tok string
}

func (c *client) do(method, path string, body any, csrf bool) (int, map[string]any) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.tok != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: c.tok})
	}
	if csrf {
		req.Header.Set("X-ASI-CSRF", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"), crypto.RandomKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	st.EnsureBuiltinRoles(ctx)
	st.SyncBuiltinSignatures(ctx)
	for _, u := range []struct{ name, role string }{{"admin", "Administracja"}, {"operator", "Dodawanie, usuwanie, modyfikacja"},
		{"analityk", "Modyfikacja i odczyt"}, {"audytor", "Odczyt"}} {
		r, _ := st.RoleByName(ctx, u.role)
		if _, err := st.CreateUser(ctx, u.name, u.name, pw, r.ID); err != nil {
			t.Fatal(err)
		}
	}
	model := lab.NewModel(time.Now())
	m := orchestrator.New(st, scanner.Registry{"sim": &scanner.Sim{Model: model, Clock: clock.Real{}}}, clock.Real{}, model, orchestrator.Config{Logf: t.Logf})
	m.ReloadSignatures(ctx)
	srv := httptest.NewServer(New(st, m, nil, Config{MaxRate: 2000, MaxTargets: 1 << 20}).Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func login(t *testing.T, srv *httptest.Server, user string) *client {
	c := &client{t: t, srv: srv}
	code, out := c.do("POST", "/api/auth/login", map[string]string{"username": user, "password": pw}, false)
	if code != 200 {
		t.Fatalf("login %s: %d %v", user, code, out)
	}
	c.tok = out["token"].(string)
	return c
}

func TestRBACMatrix(t *testing.T) {
	srv, st := setup(t)
	admin, op, an, ro := login(t, srv, "admin"), login(t, srv, "operator"), login(t, srv, "analityk"), login(t, srv, "audytor")
	anon := &client{t: t, srv: srv}

	if code, _ := anon.do("GET", "/api/dashboard", nil, false); code != 401 {
		t.Fatalf("anonymous must get 401, got %d", code)
	}
	host := map[string]any{"address": "10.9.9.9", "services": []map[string]any{{"port": 8080, "name": "http", "product": "Jenkins"}}}
	// create: operator yes, analyst/viewer no
	if code, _ := ro.do("POST", "/api/hosts", host, true); code != 403 {
		t.Fatalf("viewer create -> %d", code)
	}
	if code, _ := an.do("POST", "/api/hosts", host, true); code != 403 {
		t.Fatalf("analyst create -> %d", code)
	}
	code, out := op.do("POST", "/api/hosts", host, true)
	if code != 201 {
		t.Fatalf("operator create -> %d %v", code, out)
	}
	sid := int64(out["service_ids"].([]any)[0].(float64))
	path := "/api/services/" + itoa(sid)
	// update: analyst yes, viewer no
	note := map[string]any{"note": "tajne", "tags": []string{"x"}}
	if code, _ := ro.do("PATCH", path, note, true); code != 403 {
		t.Fatalf("viewer update -> %d", code)
	}
	if code, out := an.do("PATCH", path, note, true); code != 200 {
		t.Fatalf("analyst update -> %d %v", code, out)
	}
	// read: everyone
	for _, c := range []*client{admin, op, an, ro} {
		if code, _ := c.do("GET", path, nil, false); code != 200 {
			t.Fatalf("read -> %d", code)
		}
	}
	// delete: analyst no, operator yes
	if code, _ := an.do("DELETE", path, nil, true); code != 403 {
		t.Fatalf("analyst delete -> %d", code)
	}
	// admin-only
	for _, c := range []*client{op, an, ro} {
		if code, _ := c.do("GET", "/api/users", nil, false); code != 403 {
			t.Fatalf("non-admin users list -> %d", code)
		}
		if code, _ := c.do("GET", "/api/audit", nil, false); code != 403 {
			t.Fatalf("non-admin audit -> %d", code)
		}
	}
	if code, _ := admin.do("GET", "/api/users", nil, false); code != 200 {
		t.Fatal("admin users")
	}
	// CSRF: state change without header is refused even for admin
	if code, _ := admin.do("DELETE", path, nil, false); code != 403 {
		t.Fatalf("missing CSRF header must be refused, got %d", code)
	}
	if code, _ := op.do("DELETE", path, nil, true); code != 200 {
		t.Fatalf("operator delete -> %d", code)
	}
	// custom role: create & assign
	code, out = admin.do("POST", "/api/roles", map[string]any{"name": "Tylko eksport", "permissions": []string{"assets:read", "data:export"}}, true)
	if code != 201 {
		t.Fatalf("create role %d %v", code, out)
	}
	if code, _ := admin.do("PUT", "/api/roles/1", map[string]any{"name": "x", "permissions": []string{}}, true); code != 400 {
		t.Fatalf("built-in role must be immutable, got %d", code)
	}
	if code, _ := admin.do("POST", "/api/roles", map[string]any{"name": "bad", "permissions": []string{"root:everything"}}, true); code != 400 {
		t.Fatal("unknown permission must be rejected")
	}
	// denied attempts are audited
	a, _ := st.ListAudit(context.Background(), 500, 0)
	denied := 0
	for _, e := range a {
		if e.Action == "denied" {
			denied++
		}
	}
	if denied < 5 {
		t.Fatalf("denied actions should be audited, got %d", denied)
	}
}

func TestLoginThrottleAndSafeJobValidation(t *testing.T) {
	srv, _ := setup(t)
	anon := &client{t: t, srv: srv}
	for i := 0; i < 5; i++ {
		anon.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong"}, false)
	}
	if code, _ := anon.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": pw}, false); code != 429 {
		t.Fatalf("expected throttling, got %d", code)
	}
	srv2, _ := setup(t)
	admin := login(t, srv2, "admin")
	bad := []map[string]any{
		{"name": "x", "ports": "80;rm", "engine": "nmap"},
		{"name": "x", "ports": "top:100", "timing": "T5", "engine": "nmap"},
		{"name": "x", "ports": "top:100", "nmap_extra": "--script vuln", "engine": "nmap"},
		{"name": "x", "ports": "top:100", "rate_pps": 999999, "engine": "nmap"},
	}
	for _, j := range bad {
		if code, out := admin.do("POST", "/api/jobs", j, true); code != 400 {
			t.Fatalf("unsafe job accepted: %v -> %d %v", j, code, out)
		}
	}
	code, out := admin.do("POST", "/api/jobs", map[string]any{"name": "ok", "engine": "sim", "ports": "top:100", "window_always": true}, true)
	if code != 201 {
		t.Fatalf("job %d %v", code, out)
	}
	id := itoa(int64(out["id"].(float64)))
	code, out = admin.do("POST", "/api/jobs/"+id+"/targets?format=text", nil, true)
	_ = out
	req, _ := http.NewRequest("POST", srv2.URL+"/api/jobs/"+id+"/targets?format=text", strings.NewReader("10.0.0.0/8"))
	req.AddCookie(&http.Cookie{Name: cookieName, Value: admin.tok})
	req.Header.Set("X-ASI-CSRF", "1")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("a /8 must exceed the safety cap, got %d", resp.StatusCode)
	}
}

func itoa(i int64) string {
	b, _ := json.Marshal(i)
	return string(b)
}
