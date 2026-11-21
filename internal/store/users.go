package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Permissions (resource:action). Roles are sets of permissions; "*" = all.
const (
	PermAssetsRead    = "assets:read"
	PermAssetsCreate  = "assets:create"
	PermAssetsUpdate  = "assets:update"
	PermAssetsDelete  = "assets:delete"
	PermJobsRead      = "jobs:read"
	PermJobsCreate    = "jobs:create"
	PermJobsUpdate    = "jobs:update"
	PermJobsDelete    = "jobs:delete"
	PermScansRun      = "scans:run"
	PermSigsRead      = "signatures:read"
	PermSigsCreate    = "signatures:create"
	PermSigsUpdate    = "signatures:update"
	PermSigsDelete    = "signatures:delete"
	PermDataImport    = "data:import"
	PermDataExport    = "data:export"
	PermDojoExport    = "dojo:export"
	PermAdminUsers    = "admin:users"
	PermAdminRoles    = "admin:roles"
	PermAdminSettings = "admin:settings"
	PermAdminAudit    = "admin:audit"
)

type PermissionInfo struct {
	Key   string `json:"key"`
	Group string `json:"group"`
	Label string `json:"label"`
}

var AllPermissions = []PermissionInfo{
	{PermAssetsRead, "Zasoby i znaleziska", "Odczyt hostów, usług, zmian, dashboardu"},
	{PermAssetsCreate, "Zasoby i znaleziska", "Ręczne dodawanie hostów/usług"},
	{PermAssetsUpdate, "Zasoby i znaleziska", "Edycja znalezisk (tagi, notatki, korekty, triage)"},
	{PermAssetsDelete, "Zasoby i znaleziska", "Usuwanie hostów/usług"},
	{PermJobsRead, "Skany", "Odczyt zadań, celów i przebiegów"},
	{PermJobsCreate, "Skany", "Tworzenie zadań i dodawanie celów"},
	{PermJobsUpdate, "Skany", "Modyfikacja konfiguracji zadań i celów"},
	{PermJobsDelete, "Skany", "Usuwanie zadań i celów"},
	{PermScansRun, "Skany", "Uruchamianie / pauzowanie / anulowanie skanów"},
	{PermSigsRead, "Sygnatury", "Odczyt sygnatur"},
	{PermSigsCreate, "Sygnatury", "Tworzenie sygnatur"},
	{PermSigsUpdate, "Sygnatury", "Modyfikacja / włączanie sygnatur"},
	{PermSigsDelete, "Sygnatury", "Usuwanie sygnatur"},
	{PermDataImport, "Dane", "Import celów i wyników (CSV/JSON/nmap XML)"},
	{PermDataExport, "Dane", "Eksport wyników (CSV/JSON)"},
	{PermDojoExport, "Integracje", "Wysyłanie obserwacji do DefectDojo"},
	{PermAdminUsers, "Administracja", "Zarządzanie użytkownikami"},
	{PermAdminRoles, "Administracja", "Zarządzanie rolami"},
	{PermAdminSettings, "Administracja", "Ustawienia systemu i integracji"},
	{PermAdminAudit, "Administracja", "Dziennik audytu"},
}

func ValidPermission(p string) bool {
	if p == "*" {
		return true
	}
	for _, x := range AllPermissions {
		if x.Key == p {
			return true
		}
	}
	return false
}

var readPerms = []string{PermAssetsRead, PermJobsRead, PermSigsRead, PermDataExport}

// BuiltinRoles are the four roles required by the specification.
var BuiltinRoles = []Role{
	{Name: "Administracja", Description: "Pełny dostęp, w tym użytkownicy, role, ustawienia i audyt", Permissions: []string{"*"}},
	{Name: "Dodawanie, usuwanie, modyfikacja", Description: "Pełna praca operacyjna: dodawanie, usuwanie i modyfikacja danych, uruchamianie skanów, import/eksport, DefectDojo",
		Permissions: append(append([]string{}, readPerms...), PermAssetsCreate, PermAssetsUpdate, PermAssetsDelete, PermJobsCreate, PermJobsUpdate,
			PermJobsDelete, PermScansRun, PermSigsCreate, PermSigsUpdate, PermSigsDelete, PermDataImport, PermDojoExport)},
	{Name: "Modyfikacja i odczyt", Description: "Odczyt oraz modyfikacja istniejących danych (bez dodawania i usuwania)",
		Permissions: append(append([]string{}, readPerms...), PermAssetsUpdate, PermJobsUpdate, PermSigsUpdate)},
	{Name: "Odczyt", Description: "Tylko odczyt dashboardu, wyników i konfiguracji", Permissions: append([]string{}, readPerms...)},
}

type Role struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Builtin     bool     `json:"builtin"`
	Users       int      `json:"users"`
}

func (r *Role) Has(p string) bool {
	for _, x := range r.Permissions {
		if x == "*" || x == p {
			return true
		}
	}
	return false
}

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	RoleID      int64  `json:"role_id"`
	RoleName    string `json:"role_name"`
	Disabled    bool   `json:"disabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login"`
	Role        *Role  `json:"-"`
}

func (u *User) Can(p string) bool { return u != nil && u.Role != nil && u.Role.Has(p) }

// EffectivePermissions expands "*".
func (u *User) EffectivePermissions() []string {
	if u.Role == nil {
		return nil
	}
	if u.Role.Has("*") {
		var all []string
		for _, p := range AllPermissions {
			all = append(all, p.Key)
		}
		return all
	}
	return u.Role.Permissions
}

// EnsureBuiltinRoles creates/updates the four mandated roles.
func (s *Store) EnsureBuiltinRoles(ctx context.Context) error {
	for _, r := range BuiltinRoles {
		_, err := s.DB.ExecContext(ctx, `INSERT INTO roles(name, description, permissions, builtin, created_at) VALUES(?,?,?,1,?)
			ON CONFLICT(name) DO UPDATE SET description=excluded.description, permissions=excluded.permissions, builtin=1`,
			r.Name, r.Description, jsonStr(r.Permissions), s.now())
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) scanRole(row interface{ Scan(...any) error }) (*Role, error) {
	var r Role
	var perms string
	var b int
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &perms, &b, &r.Users); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(perms), &r.Permissions)
	r.Builtin = b == 1
	return &r, nil
}

const roleCols = `r.id, r.name, r.description, r.permissions, r.builtin, (SELECT COUNT(*) FROM users u WHERE u.role_id=r.id)`

func (s *Store) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+roleCols+` FROM roles r ORDER BY r.builtin DESC, r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Role
	for rows.Next() {
		r, err := s.scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRole(ctx context.Context, id int64) (*Role, error) {
	r, err := s.scanRole(s.DB.QueryRowContext(ctx, `SELECT `+roleCols+` FROM roles r WHERE r.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *Store) RoleByName(ctx context.Context, name string) (*Role, error) {
	r, err := s.scanRole(s.DB.QueryRowContext(ctx, `SELECT `+roleCols+` FROM roles r WHERE r.name=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func cleanPerms(perms []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range perms {
		if !ValidPermission(p) {
			return nil, fmt.Errorf("unknown permission %q", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) CreateRole(ctx context.Context, r Role) (int64, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return 0, errors.New("role name required")
	}
	perms, err := cleanPerms(r.Permissions)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO roles(name, description, permissions, builtin, created_at) VALUES(?,?,?,0,?)`,
		r.Name, r.Description, jsonStr(perms), s.now())
	if err != nil {
		return 0, fmt.Errorf("create role: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateRole(ctx context.Context, r Role) error {
	cur, err := s.GetRole(ctx, r.ID)
	if err != nil {
		return err
	}
	if cur.Builtin {
		return errors.New("built-in roles cannot be modified (create a custom role instead)")
	}
	perms, err := cleanPerms(r.Permissions)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE roles SET name=?, description=?, permissions=? WHERE id=?`, strings.TrimSpace(r.Name), r.Description, jsonStr(perms), r.ID)
	return err
}

func (s *Store) DeleteRole(ctx context.Context, id int64) error {
	r, err := s.GetRole(ctx, id)
	if err != nil {
		return err
	}
	if r.Builtin {
		return errors.New("built-in roles cannot be deleted")
	}
	if r.Users > 0 {
		return fmt.Errorf("role is assigned to %d user(s)", r.Users)
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM roles WHERE id=?`, id)
	return err
}

// --- users ---------------------------------------------------------------

const userCols = `u.id, u.username, u.display_name, u.role_id, r.name, u.disabled, u.created_at, u.last_login`

func (s *Store) scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var d int
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.RoleID, &u.RoleName, &d, &u.CreatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	u.Disabled = d == 1
	return &u, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	u, err := s.scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Role, err = s.GetRole(ctx, u.RoleID)
	return u, err
}

func ValidatePassword(p string) error {
	if len(p) < 10 {
		return errors.New("password must have at least 10 characters")
	}
	if len(p) > 72 {
		return errors.New("password too long (max 72 bytes)")
	}
	return nil
}

func (s *Store) CreateUser(ctx context.Context, username, display, password string, roleID int64) (int64, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || strings.ContainsAny(username, " \t<>\"'") {
		return 0, errors.New("username must have >=3 chars and no spaces/quotes")
	}
	if err := ValidatePassword(password); err != nil {
		return 0, err
	}
	if _, err := s.GetRole(ctx, roleID); err != nil {
		return 0, fmt.Errorf("role: %w", err)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users(username, display_name, password_hash, role_id, created_at) VALUES(?,?,?,?,?)`,
		username, display, string(h), roleID, s.now())
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}
	return res.LastInsertId()
}

type UserPatch struct {
	DisplayName *string `json:"display_name"`
	RoleID      *int64  `json:"role_id"`
	Disabled    *bool   `json:"disabled"`
	Password    *string `json:"password"`
}

func (s *Store) UpdateUser(ctx context.Context, id int64, p UserPatch) error {
	if _, err := s.GetUser(ctx, id); err != nil {
		return err
	}
	if p.DisplayName != nil {
		s.DB.ExecContext(ctx, `UPDATE users SET display_name=? WHERE id=?`, *p.DisplayName, id)
	}
	if p.RoleID != nil {
		if _, err := s.GetRole(ctx, *p.RoleID); err != nil {
			return fmt.Errorf("role: %w", err)
		}
		s.DB.ExecContext(ctx, `UPDATE users SET role_id=? WHERE id=?`, *p.RoleID, id)
	}
	if p.Disabled != nil {
		s.DB.ExecContext(ctx, `UPDATE users SET disabled=? WHERE id=?`, b2i(*p.Disabled), id)
		if *p.Disabled {
			s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id)
		}
	}
	if p.Password != nil && *p.Password != "" {
		if err := ValidatePassword(*p.Password); err != nil {
			return err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(*p.Password), 12)
		if err != nil {
			return err
		}
		s.DB.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, string(h), id)
		s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id)
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) CountUsers(ctx context.Context) int {
	var n int
	s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

// dummyHash makes failed logins for unknown users take as long as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equaliser"), 12)

var ErrBadCredentials = errors.New("invalid username or password")

func (s *Store) Authenticate(ctx context.Context, username, password string) (*User, error) {
	var id int64
	var hash string
	var disabled int
	err := s.DB.QueryRowContext(ctx, `SELECT id, password_hash, disabled FROM users WHERE username=?`, strings.TrimSpace(username)).Scan(&id, &hash, &disabled)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrBadCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || disabled == 1 {
		return nil, ErrBadCredentials
	}
	s.DB.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, s.now(), id)
	return s.GetUser(ctx, id)
}

// --- sessions ------------------------------------------------------------

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CreateSession returns a random bearer token; only its SHA-256 is stored.
func (s *Store) CreateSession(ctx context.Context, userID int64, ip string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, created_at, expires_at, ip) VALUES(?,?,?,?,?)`,
		hashToken(tok), userID, s.now(), s.Now().Add(ttl).Unix(), ip)
	return tok, err
}

func (s *Store) SessionUser(ctx context.Context, token string) (*User, error) {
	var uid, exp int64
	err := s.DB.QueryRowContext(ctx, `SELECT user_id, expires_at FROM sessions WHERE token_hash=?`, hashToken(token)).Scan(&uid, &exp)
	if err != nil || exp < s.now() {
		return nil, ErrNotFound
	}
	u, err := s.GetUser(ctx, uid)
	if err != nil || u.Disabled {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) {
	s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hashToken(token))
}

func (s *Store) PurgeSessions(ctx context.Context) {
	s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, s.now())
}

// --- audit ---------------------------------------------------------------

type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Entity   string `json:"entity"`
	EntityID int64  `json:"entity_id"`
	Detail   string `json:"detail"`
	IP       string `json:"ip"`
}

func (s *Store) Audit(ctx context.Context, user, action, entity string, id int64, detail, ip string) {
	s.DB.ExecContext(ctx, `INSERT INTO audit_log(ts, username, action, entity, entity_id, detail, ip) VALUES(?,?,?,?,?,?,?)`,
		s.now(), user, action, entity, id, detail, ip)
}

func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, username, action, entity, entity_id, detail, ip FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		rows.Scan(&a.ID, &a.TS, &a.Username, &a.Action, &a.Entity, &a.EntityID, &a.Detail, &a.IP)
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- settings (encrypted) ------------------------------------------------

func (s *Store) GetSetting(ctx context.Context, key string, v any) error {
	var enc string
	err := s.DB.QueryRowContext(ctx, `SELECT value_enc FROM settings WHERE key=?`, key).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return s.K.OpenJSON("settings."+key, enc, v)
}

func (s *Store) SetSetting(ctx context.Context, key string, v any) error {
	enc, err := s.K.SealJSON("settings."+key, v)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO settings(key, value_enc, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc, updated_at=excluded.updated_at`,
		key, enc, s.now())
	return err
}
