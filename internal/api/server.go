// Package api exposes the REST API and serves the embedded dashboard.
//
// Security model:
//   - session token in an HttpOnly, SameSite=Strict cookie (or Bearer header
//     for automation); only the SHA-256 of tokens is stored;
//   - every route declares the permission it needs (RBAC enforced server-side);
//   - state-changing requests require the X-ASI-CSRF header (cannot be set by
//     cross-site forms; CORS is not enabled);
//   - strict CSP, no inline scripts, login throttling, audit log.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/orchestrator"
	"asi/internal/store"
)

type Config struct {
	SecureCookie bool
	SessionTTL   time.Duration
	MaxRate      int
	MaxTargets   int64
	Version      string
	NmapVersion  string
	Demo         bool
	TrustProxy   bool
}

type Server struct {
	st     *store.Store
	m      *orchestrator.Manager
	cfg    Config
	static fs.FS

	loginMu   sync.Mutex
	loginFail map[string]*failWindow
}

type failWindow struct {
	n     int
	until time.Time
}

func New(st *store.Store, m *orchestrator.Manager, static fs.FS, cfg Config) *Server {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	return &Server{st: st, m: m, cfg: cfg, static: static, loginFail: map[string]*failWindow{}}
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func errf(code int, f string, a ...any) error { return &httpError{code, fmt.Sprintf(f, a...)} }

type handler func(w http.ResponseWriter, r *http.Request, u *store.User) error

const cookieName = "asi_session"

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) token(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// route registers an authenticated endpoint guarded by a permission.
func (s *Server) route(mux *http.ServeMux, pattern, perm string, h handler) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		tok := s.token(r)
		if tok == "" {
			writeErr(w, errf(401, "authentication required"))
			return
		}
		u, err := s.st.SessionUser(r.Context(), tok)
		if err != nil {
			writeErr(w, errf(401, "session expired"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			if r.Header.Get("X-ASI-CSRF") != "1" {
				writeErr(w, errf(403, "missing CSRF header"))
				return
			}
		}
		if perm != "" && !u.Can(perm) {
			s.st.Audit(r.Context(), u.Username, "denied", r.Method+" "+r.URL.Path, 0, "missing "+perm, s.clientIP(r))
			writeErr(w, errf(403, "permission %q required (role: %s)", perm, u.RoleName))
			return
		}
		// dataset filter chosen in the UI (real / demo / all); default: all
		sc := r.Header.Get("X-ASI-Scope")
		if sc == "" {
			sc = r.URL.Query().Get("scope")
		}
		r = r.WithContext(store.WithScope(r.Context(), store.ParseScope(sc)))
		if err := h(w, r, u); err != nil {
			writeErr(w, err)
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	code := 400
	msg := err.Error()
	switch {
	case errors.As(err, &he):
		code = he.code
	case errors.Is(err, store.ErrNotFound):
		code, msg = 404, "not found"
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		return errf(400, "invalid JSON body: %v", err)
	}
	return nil
}

func pathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errf(400, "invalid %s", name)
	}
	return id, nil
}

func qint(r *http.Request, k string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(k))
	if err != nil {
		return def
	}
	return v
}

func qint64(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

func (s *Server) audit(r *http.Request, u *store.User, action, entity string, id int64, detail string) {
	s.st.Audit(context.WithoutCancel(r.Context()), u.Username, action, entity, id, detail, s.clientIP(r))
}

func securityHeaders(next http.Handler, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic: %v", p)
				http.Error(w, "internal error", 500)
			}
		}()
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && (rec.code >= 400 || r.Method != http.MethodGet) {
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, time.Since(start).Round(time.Millisecond))
		}
	})
}

// Handler builds the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.st.DB.PingContext(r.Context()); err != nil {
			http.Error(w, "db error", 503)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	s.route(mux, "GET /api/auth/me", "", s.me)
	s.route(mux, "POST /api/auth/password", "", s.changePassword)
	s.route(mux, "GET /api/meta", "", s.meta)

	s.route(mux, "GET /api/dashboard", store.PermAssetsRead, s.dashboard)
	s.route(mux, "GET /api/hosts", store.PermAssetsRead, s.listHosts)
	s.route(mux, "POST /api/hosts", store.PermAssetsCreate, s.createHost)
	s.route(mux, "GET /api/hosts/{id}", store.PermAssetsRead, s.getHost)
	s.route(mux, "PATCH /api/hosts/{id}", store.PermAssetsUpdate, s.patchHost)
	s.route(mux, "DELETE /api/hosts/{id}", store.PermAssetsDelete, s.deleteHost)
	s.route(mux, "GET /api/services", store.PermAssetsRead, s.listServices)
	s.route(mux, "POST /api/services", store.PermAssetsCreate, s.createService)
	s.route(mux, "POST /api/services/bulk", store.PermAssetsUpdate, s.bulkServices)
	s.route(mux, "GET /api/services/{id}", store.PermAssetsRead, s.getService)
	s.route(mux, "PATCH /api/services/{id}", store.PermAssetsUpdate, s.patchService)
	s.route(mux, "DELETE /api/services/{id}", store.PermAssetsDelete, s.deleteService)
	s.route(mux, "GET /api/groups", store.PermAssetsRead, s.groups)
	s.route(mux, "GET /api/changes", store.PermAssetsRead, s.changes)
	s.route(mux, "GET /api/compare", store.PermAssetsRead, s.compare)

	s.route(mux, "GET /api/jobs", store.PermJobsRead, s.listJobs)
	s.route(mux, "POST /api/jobs", store.PermJobsCreate, s.createJob)
	s.route(mux, "GET /api/jobs/{id}", store.PermJobsRead, s.getJob)
	s.route(mux, "PUT /api/jobs/{id}", store.PermJobsUpdate, s.updateJob)
	s.route(mux, "DELETE /api/jobs/{id}", store.PermJobsDelete, s.deleteJob)
	s.route(mux, "GET /api/jobs/{id}/targets", store.PermJobsRead, s.listTargets)
	s.route(mux, "POST /api/jobs/{id}/targets", store.PermJobsCreate, s.addTargets)
	s.route(mux, "DELETE /api/jobs/{id}/targets", store.PermJobsDelete, s.deleteAllTargets)
	s.route(mux, "PATCH /api/jobs/{id}/targets/{tid}", store.PermJobsUpdate, s.patchTarget)
	s.route(mux, "DELETE /api/jobs/{id}/targets/{tid}", store.PermJobsDelete, s.deleteTarget)
	s.route(mux, "GET /api/jobs/{id}/targets/export", store.PermDataExport, s.exportTargets)
	s.route(mux, "GET /api/jobs/{id}/preview", store.PermJobsRead, s.previewJob)
	s.route(mux, "POST /api/jobs/{id}/run", store.PermScansRun, s.runJob)
	s.route(mux, "GET /api/runs", store.PermJobsRead, s.listRuns)
	s.route(mux, "GET /api/runs/{id}", store.PermJobsRead, s.getRun)
	s.route(mux, "POST /api/runs/{id}/{action}", store.PermScansRun, s.runAction)
	s.route(mux, "POST /api/scans/stop-all", store.PermScansRun, s.stopAll)
	s.route(mux, "POST /api/quickscan", store.PermScansRun, s.quickScan)
	s.route(mux, "GET /api/quickscan", store.PermJobsRead, s.listQuick)
	s.route(mux, "GET /api/vulns", store.PermAssetsRead, s.listVulns)

	s.route(mux, "GET /api/export/results", store.PermDataExport, s.exportResults)
	s.route(mux, "GET /api/export/changes", store.PermDataExport, s.exportChanges)
	s.route(mux, "POST /api/import/results", store.PermDataImport, s.importResults)

	s.route(mux, "GET /api/signatures", store.PermSigsRead, s.listSignatures)
	s.route(mux, "POST /api/signatures", store.PermSigsCreate, s.createSignature)
	s.route(mux, "POST /api/signatures/test", store.PermSigsRead, s.testSignature)
	s.route(mux, "POST /api/signatures/import", store.PermSigsCreate, s.importSignatures)
	s.route(mux, "GET /api/signatures/export", store.PermDataExport, s.exportSignatures)
	s.route(mux, "PUT /api/signatures/{id}", store.PermSigsUpdate, s.updateSignature)
	s.route(mux, "DELETE /api/signatures/{id}", store.PermSigsDelete, s.deleteSignature)

	s.route(mux, "GET /api/permissions", "", s.permissions)
	s.route(mux, "GET /api/roles", "", s.listRoles)
	s.route(mux, "POST /api/roles", store.PermAdminRoles, s.createRole)
	s.route(mux, "PUT /api/roles/{id}", store.PermAdminRoles, s.updateRole)
	s.route(mux, "DELETE /api/roles/{id}", store.PermAdminRoles, s.deleteRole)
	s.route(mux, "GET /api/users", store.PermAdminUsers, s.listUsers)
	s.route(mux, "POST /api/users", store.PermAdminUsers, s.createUser)
	s.route(mux, "PATCH /api/users/{id}", store.PermAdminUsers, s.updateUser)
	s.route(mux, "DELETE /api/users/{id}", store.PermAdminUsers, s.deleteUser)
	s.route(mux, "GET /api/audit", store.PermAdminAudit, s.listAudit)

	s.route(mux, "GET /api/settings/dojo", store.PermAdminSettings, s.getDojo)
	s.route(mux, "PUT /api/settings/dojo", store.PermAdminSettings, s.putDojo)
	s.route(mux, "POST /api/settings/dojo/test", store.PermAdminSettings, s.testDojo)
	s.route(mux, "POST /api/dojo/export", store.PermDojoExport, s.dojoExport)
	s.route(mux, "GET /api/dojo/history", store.PermDojoExport, s.dojoHistory)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, errf(404, "unknown endpoint")) })
	if s.static != nil {
		files := http.FileServerFS(s.static)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			p := strings.TrimPrefix(r.URL.Path, "/")
			if p == "" {
				p = "index.html"
			}
			if _, err := fs.Stat(s.static, p); err != nil {
				r.URL.Path = "/"
			}
			// revalidate every UI file: after an upgrade browsers must not keep an
			// old core.js next to a new main.js (the files are small)
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
		})
	}
	return logRequests(securityHeaders(mux, s.cfg.SecureCookie))
}

// --- auth --------------------------------------------------------------------------

func (s *Server) throttled(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	f := s.loginFail[ip]
	return f != nil && f.n >= 5 && time.Now().Before(f.until)
}

func (s *Server) recordFail(ip string, ok bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if ok {
		delete(s.loginFail, ip)
		return
	}
	f := s.loginFail[ip]
	if f == nil || time.Now().After(f.until) {
		f = &failWindow{}
		s.loginFail[ip] = f
	}
	f.n++
	f.until = time.Now().Add(5 * time.Minute)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.throttled(ip) {
		writeErr(w, errf(429, "too many failed attempts, try again in a few minutes"))
		return
	}
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	u, err := s.st.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil {
		s.recordFail(ip, false)
		s.st.Audit(r.Context(), in.Username, "login_failed", "auth", 0, "", ip)
		writeErr(w, errf(401, "invalid username or password"))
		return
	}
	s.recordFail(ip, true)
	tok, err := s.st.CreateSession(r.Context(), u.ID, ip, s.cfg.SessionTTL)
	if err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.SessionTTL.Seconds())})
	s.st.Audit(r.Context(), u.Username, "login", "auth", u.ID, "", ip)
	writeJSON(w, 200, map[string]any{"user": u, "permissions": u.EffectivePermissions(), "token": tok})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if t := s.token(r); t != "" {
		s.st.DeleteSession(r.Context(), t)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u *store.User) error {
	writeJSON(w, 200, map[string]any{"user": u, "permissions": u.EffectivePermissions()})
	return nil
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, u *store.User) error {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if _, err := s.st.Authenticate(r.Context(), u.Username, in.Old); err != nil {
		return errf(403, "current password is incorrect")
	}
	if err := s.st.UpdateUser(r.Context(), u.ID, store.UserPatch{Password: &in.New}); err != nil {
		return err
	}
	s.audit(r, u, "password_change", "user", u.ID, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request, u *store.User) error {
	writeJSON(w, 200, map[string]any{
		"version": s.cfg.Version, "engines": s.m.Engines(), "nmap": s.cfg.NmapVersion, "max_rate": s.cfg.MaxRate,
		"max_targets": s.cfg.MaxTargets, "demo": s.cfg.Demo, "has_demo_data": s.st.HasDemoData(r.Context()), "server_time": s.m.Clock().Now().Unix(),
		"key_fingerprint": s.st.K.Fingerprint(), "permissions": store.AllPermissions,
	})
	return nil
}
